// Package source — джерела правил («пилок»): bare-клон у кеші, закріплений коміт, дерево на цьому коміті, індекс
// правил. MVP-a: kind git, role rules-tree — готове дерево правил DocScan (як yara-docscan-rules).
package source

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rifatismailov/Anthophila_Hive/internal/dupes"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

// Cache — теки bare-клонів (<root>/<id>-<хеш url>.git).
type Cache struct{ Root string }

func (c Cache) dir(s workspace.Source) string {
	h := sha256.Sum256([]byte(s.URL))
	return filepath.Join(c.Root, s.ID+"-"+hex.EncodeToString(h[:6])+".git")
}

// Fetch — оновити клон джерела (мережа).
func (c Cache) Fetch(s workspace.Source, auth *gitx.Auth) (*gitx.Repo, error) {
	if s.Kind != "git" {
		return nil, fmt.Errorf("source %s: kind %q is not supported yet (git)", s.ID, s.Kind)
	}
	return gitx.Mirror(s.URL, c.dir(s), auth)
}

// Repo — клон без мережі (має бути вже завантажений).
func (c Cache) Repo(s workspace.Source) (*gitx.Repo, error) {
	d := c.dir(s)
	if _, err := os.Stat(filepath.Join(d, "HEAD")); err != nil {
		return nil, fmt.Errorf("source %s is not fetched yet", s.ID)
	}
	return &gitx.Repo{Dir: d, Bare: true}, nil
}

// Extract — дерево джерела на закріпленому коміті в dst.
func (c Cache) Extract(s workspace.Source, dst string) error {
	if s.Commit == "" {
		return fmt.Errorf("source %s has no pinned commit", s.ID)
	}
	r, err := c.Repo(s)
	if err != nil {
		return err
	}
	if _, err := r.Resolve(s.Commit); err != nil {
		return fmt.Errorf("source %s: commit %s is not in the cache (fetch the source)", s.ID, short(s.Commit))
	}
	return r.Extract(s.Commit, dst)
}

// Change — різниця двох комітів джерела по файлах правил.
type Change struct{ Status, Path string } // A | M | D

// Diff — які файли правил змінилися між комітами (для показу перед закріпленням).
func (c Cache) Diff(s workspace.Source, from, to string) ([]Change, error) {
	r, err := c.Repo(s)
	if err != nil {
		return nil, err
	}
	out, err := r.Run("diff", "--name-status", "--no-renames", from, to)
	if err != nil {
		return nil, err
	}
	var ch []Change
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && IsRulesFile(f[1]) {
			ch = append(ch, Change{f[0], f[1]})
		}
	}
	return ch, nil
}

// IsRulesFile — файл правил YARA.
func IsRulesFile(p string) bool { return yaraparse.IsRulesFile(p) }

// Skip — що з дерева правил не йде на ПК (cirun/deploy/rules.go: skipRules).
func Skip(rel string) bool {
	first := strings.SplitN(rel, "/", 2)[0]
	return first == ".git" || first == "tools" || rel == "README.md" || strings.HasPrefix(filepath.Base(rel), ".")
}

// Index — записи бібліотеки для дерева tree (origin — id джерела, "org" або "critical"; prefix — шлях у пакеті).
func Index(tree, origin, prefix string) ([]store.Rule, error) {
	var out []store.Rule
	err := filepath.Walk(tree, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(tree, p)
		rel = filepath.ToSlash(rel)
		if fi.IsDir() {
			if rel != "." && Skip(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if Skip(rel) || !IsRulesFile(rel) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src := string(b)
		for _, r := range yaraparse.Parse(src).Rules {
			meta := map[string]string{}
			for _, kv := range r.Meta {
				if _, ok := meta[kv.Key]; !ok {
					meta[kv.Key] = kv.Value
				}
			}
			sig, cond := dupes.Signature(r)
			out = append(out, store.Rule{Origin: origin, File: prefix + rel, Name: r.Name, Kind: Kind(prefix+rel, origin),
				Private: r.Private || r.Global, Tags: r.Tags, Meta: meta, Line: r.Line, TextHash: dupes.TextHash(src, r), BodyHash: dupes.BodyHash(r),
				Strings: sig, Cond: cond})
		}
		return nil
	})
	return out, err
}

// Kind — вид правила за шляхом у пакеті.
func Kind(pkgPath, origin string) string {
	switch {
	case origin == "critical" || strings.HasPrefix(pkgPath, "critical/"):
		return "critical"
	case pkgPath == "docscan-policy.yar" || pkgPath == "docscan.yar":
		return "policy"
	}
	return "detection"
}

func short(c string) string {
	if len(c) > 8 {
		return c[:8]
	}
	return c
}
