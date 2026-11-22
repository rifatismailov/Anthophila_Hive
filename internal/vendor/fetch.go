package vendor

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

// Cache — кеш джерел: git — bare-клони (<root>/git/<name>-<хеш url>.git), релізи — розпаковані
// (<root>/release/<name>-<тег>/).
type Cache struct{ Root string }

func (c Cache) gitDir(s Source) string {
	h := sha256.Sum256([]byte(s.URL))
	return filepath.Join(c.Root, "git", s.Name+"-"+hex.EncodeToString(h[:6])+".git")
}

func (c Cache) releaseDir(s Source) string {
	return filepath.Join(c.Root, "release", s.Name+"-"+strings.TrimPrefix(s.Pin, "release:"))
}

// Fetch — джерело в кеш. from — тека з уже завантаженими джерелами (vendor-sources генератора): git-репозиторій
// <from>/<name> або розпакований реліз з <from>/<name>/.release; без неї — з мережі (URL джерела).
// Повертає sha256 архіву релізу (для git — "").
func (c Cache) Fetch(s Source, from string) (string, error) {
	if s.IsRelease() {
		dst := c.releaseDir(s)
		if _, err := os.Stat(filepath.Join(dst, ".release")); err == nil {
			return s.SHA256, nil
		}
		tag := strings.TrimPrefix(s.Pin, "release:")
		if from != "" {
			src := filepath.Join(from, s.Name)
			b, err := os.ReadFile(filepath.Join(src, ".release"))
			if err != nil || strings.TrimSpace(string(b)) != s.Pin {
				return "", fmt.Errorf("%s: %s/.release is not %s", s.Name, src, s.Pin)
			}
			if err := copyTree(src, dst); err != nil {
				os.RemoveAll(dst)
				return "", err
			}
			return s.SHA256, nil
		}
		zipPath := filepath.Join(c.Root, "release", s.Name+"-"+tag+".zip")
		sum, err := download(s.URL, zipPath)
		if err != nil {
			return "", err
		}
		if s.SHA256 != "" && sum != s.SHA256 {
			return "", fmt.Errorf("%s: sha256 %s, pinned %s - the release changed upstream", s.Name, sum, s.SHA256)
		}
		if err := unzip(zipPath, dst); err != nil {
			os.RemoveAll(dst)
			return "", err
		}
		os.WriteFile(filepath.Join(dst, ".release"), []byte(s.Pin), 0o644)
		return sum, nil
	}
	url := s.URL
	if from != "" {
		if _, err := os.Stat(filepath.Join(from, s.Name, ".git")); err == nil {
			url = filepath.Join(from, s.Name)
		}
	}
	r, err := gitx.Mirror(url, c.gitDir(s), nil)
	if err != nil {
		return "", err
	}
	if url != s.URL { // надалі оновлення — з самого джерела
		r.Run("remote", "set-url", "origin", s.URL)
	}
	if _, err := r.Resolve(s.Pin); err != nil {
		if _, ferr := r.Run("fetch", "-q", "origin", s.Pin); ferr != nil {
			return "", fmt.Errorf("%s: commit %s is not in %s", s.Name, first(s.Pin, 12), url)
		}
	}
	return "", nil
}

// Repo — bare-клон git-джерела.
func (c Cache) Repo(s Source) (*gitx.Repo, error) {
	d := c.gitDir(s)
	if _, err := os.Stat(filepath.Join(d, "HEAD")); err != nil {
		return nil, fmt.Errorf("vendor source %s is not fetched (hive vendor fetch)", s.Name)
	}
	return &gitx.Repo{Dir: d, Bare: true}, nil
}

// Trees — теки всіх джерел на закріплених комітах: git розпаковується в tmp, реліз — з кешу (лише читання).
func (c Cache) Trees(cfg *Config, tmp string) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range cfg.Sources {
		if s.IsRelease() {
			d := c.releaseDir(s)
			if _, err := os.Stat(filepath.Join(d, ".release")); err != nil {
				return nil, fmt.Errorf("vendor source %s (%s) is not fetched (hive vendor fetch)", s.Name, s.Pin)
			}
			out[s.Name] = d
			continue
		}
		r, err := c.Repo(s)
		if err != nil {
			return nil, err
		}
		d := filepath.Join(tmp, s.Name)
		if err := r.Extract(s.Pin, d); err != nil {
			return nil, fmt.Errorf("%s @ %s: %w", s.Name, first(s.Pin, 12), err)
		}
		out[s.Name] = d
	}
	return out, nil
}

func download(url, dst string) (string, error) {
	os.MkdirAll(filepath.Dir(dst), 0o755)
	c := &http.Client{Timeout: 30 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	f, err := os.Create(dst + ".part")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 2<<30))
	f.Close()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), os.Rename(dst+".part", dst)
}

func unzip(src, dst string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, e := range zr.File {
		name := filepath.Clean(filepath.FromSlash(e.Name))
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return fmt.Errorf("%s: unsafe path %q", src, e.Name)
		}
		p := filepath.Join(dst, name)
		if e.FileInfo().IsDir() {
			os.MkdirAll(p, 0o755)
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0o755)
		rc, err := e.Open()
		if err != nil {
			return err
		}
		f, err := os.Create(p)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(f, io.LimitReader(rc, 1<<30))
		rc.Close()
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(t, 0o755)
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		return copyFile(p, t)
	})
}

// RuleChange — зміна правила між двома станами.
type RuleChange struct {
	Status string // added | removed | changed
	File   string
	Rule   string
}

// DiffTrees — різниця по правилах між двома теками (лише файли .yar / .yara; files — лише ці шляхи, nil — усі).
func DiffTrees(a, b string, files []string) ([]RuleChange, error) {
	idx := func(root string) (map[string]string, error) {
		m := map[string]string{}
		add := func(rel string) error {
			text, err := readText(filepath.Join(root, filepath.FromSlash(rel)))
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			_, rules, _ := splitRules(text)
			for _, r := range rules {
				body := wsRe.ReplaceAllString(r.head(), " ")
				m[rel+"\x00"+r.name] = body
			}
			return nil
		}
		if files != nil {
			for _, f := range files {
				if err := add(f); err != nil {
					return nil, err
				}
			}
			return m, nil
		}
		err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return err
			}
			if yaraparse.IsRulesFile(p) {
				rel, _ := filepath.Rel(root, p)
				return add(filepath.ToSlash(rel))
			}
			return nil
		})
		return m, err
	}
	ma, err := idx(a)
	if err != nil {
		return nil, err
	}
	mb, err := idx(b)
	if err != nil {
		return nil, err
	}
	var out []RuleChange
	for k, v := range mb {
		f, r, _ := strings.Cut(k, "\x00")
		if old, ok := ma[k]; !ok {
			out = append(out, RuleChange{"added", f, r})
		} else if old != v {
			out = append(out, RuleChange{"changed", f, r})
		}
	}
	for k := range ma {
		if _, ok := mb[k]; !ok {
			f, r, _ := strings.Cut(k, "\x00")
			out = append(out, RuleChange{"removed", f, r})
		}
	}
	sortChanges(out)
	return out, nil
}

func sortChanges(c []RuleChange) {
	sort.Slice(c, func(i, j int) bool {
		if c[i].File != c[j].File {
			return c[i].File < c[j].File
		}
		return c[i].Rule < c[j].Rule
	})
}
