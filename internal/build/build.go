// Package build — збирання пакета правил DocScan точно у форматі cirun rules-release (cirun/deploy/rules.go):
//
//	DocScan-rules.zip         дерево джерела (без tools/, README.md, прихованих) з рішеннями простору (відкинуті
//	                          правила вирізано) + org/*.yar (власні, підключені в file-index.yar) + critical/*.yar +
//	                          VERSION.txt
//	rules-manifest.json/.sig  маніфест (продукт docscan-rules), підпис ключем простору
//	DocScan-rules-bundle.zip  ці три файли — для ручного встановлення
//
// Відмінності від cirun, свідомі: ключ — простору (не лише OfficialKeys); zip детермінований (сортування, час
// файлів = час релізу), тож відтворення дає ті самі sha256 файлів; після збирання — контракт (internal/contract) і
// прогін tests/match / tests/no-match критичних правил.
package build

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/checks"
	"github.com/rifatismailov/Anthophila_Hive/internal/contract"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/source"
	"github.com/rifatismailov/Anthophila_Hive/internal/vendor"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

// Input — з чого збирати.
type Input struct {
	SourceTree   string // дерево джерела (rules-tree) на закріпленому коміті
	SourceID     string
	SourceCommit string
	WSTree       string // дерево простору на коміті WSCommit (git archive)
	WSCommit     string
	Decisions    []workspace.Decision
	Critical     []CriticalTest // тести набору критичних правил (scope critical), уже на диску
	// VendorTree — вихід генератора вендорних правил (internal/vendor); "" — дерево джерела як є. Якщо задано,
	// general/, maldoc/<джерело>/, file-index.yar і LICENSE-* беруться з генератора.
	VendorTree string
	// редакція пакета (workspace.Edition): без власних правил виявлення / без правил критичної інформації
	NoOwn, NoCritical bool
}

// CriticalTest — документ тесту набору критичних правил.
type CriticalTest struct{ Path, Expect string }

// Options — як збирати.
type Options struct {
	Version   string
	Created   time.Time
	Seed      string // seed ed25519 (base64); після збирання викликач затирає
	PublicKey string // ключ простору (ПК: extra_public_keys)
	Tools     yaraexec.Tools
	NewerThan string // версія на цілі / остання опублікована
	OutDir    string
}

// Result — що зібрано і як перевірено.
type Result struct {
	Version  string
	Dir      string
	Assets   map[string]string // ім'я -> шлях
	PkgSHA   string
	KeyID    string
	Files    int
	FileSHA  map[string]string // шлях у пакеті -> sha256 (те саме, що в маніфесті)
	Contract *contract.Report
	Critical *checks.SetResult
	Notes    []string
}

// OK — контракт зелений і критичні тести пройдено.
func (r *Result) OK() bool {
	if r.Contract == nil || r.Contract.Result() != "PASS" {
		return false
	}
	return r.Critical == nil || (len(r.Critical.Missed) == 0 && len(r.Critical.Unwanted) == 0)
}

// Files — вміст пакета (шлях з "/" -> байти) без VERSION.txt.
func Files(in Input) (map[string][]byte, []string, error) {
	files := map[string][]byte{}
	var notes []string
	err := filepath.Walk(in.SourceTree, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(in.SourceTree, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if source.Skip(rel) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() || rel == "VERSION.txt" || !fi.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		files[rel] = b
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	if _, ok := files["docscan-index.yar"]; !ok {
		return nil, nil, fmt.Errorf("source %s has no docscan-index.yar - not a DocScan rules tree", in.SourceID)
	}
	if in.VendorTree != "" {
		for p := range files {
			gen := p == "file-index.yar" || strings.HasPrefix(p, "LICENSE-")
			for _, d := range vendor.GeneratedDirs {
				if strings.HasPrefix(p, d+"/") {
					gen = true
				}
			}
			if gen {
				delete(files, p)
			}
		}
		n := 0
		err := filepath.Walk(in.VendorTree, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(in.VendorTree, p)
			rel = filepath.ToSlash(rel)
			if source.Skip(rel) {
				return nil
			}
			b, err := os.ReadFile(p)
			files[rel] = b
			n++
			return err
		})
		if err != nil {
			return nil, nil, err
		}
		notes = append(notes, fmt.Sprintf("vendor rules: %d files from the generator", n))
	}

	// рішення: вирізати відкинуті правила
	byFile := map[string]map[string]bool{}
	dropped := map[string]string{}
	for _, d := range in.Decisions {
		if d.Source != in.SourceID || d.Status != "drop" {
			continue
		}
		if byFile[d.File] == nil {
			byFile[d.File] = map[string]bool{}
		}
		byFile[d.File][d.Rule] = true
		dropped[d.Rule] = d.File
	}
	for f, names := range byFile {
		b, ok := files[f]
		if !ok {
			return nil, nil, fmt.Errorf("decision for %s: the file is not in source %s at %s (stale decision)", f, in.SourceID, short(in.SourceCommit))
		}
		out, missing := yaraparse.Remove(string(b), names)
		if len(missing) > 0 {
			sort.Strings(missing)
			return nil, nil, fmt.Errorf("decision for %s: no rule %s there (stale decision)", f, strings.Join(missing, ", "))
		}
		files[f] = []byte(out)
		notes = append(notes, fmt.Sprintf("%s: %d rule(s) dropped", f, len(names)))
	}

	// власні правила виявлення: org/<ім'я>.yar, підключені в кінці file-index.yar
	names := map[string]string{} // назва правила -> файл (усі правила виявлення компілюються разом)
	for p, b := range files {
		if source.IsRulesFile(p) && !strings.HasPrefix(p, "critical/") {
			for _, r := range yaraparse.Parse(string(b)).Rules {
				names[r.Name] = p
			}
		}
	}
	if len(dropped) > 0 {
		used := map[string]string{}
		for p, b := range files {
			if source.IsRulesFile(p) && !strings.HasPrefix(p, "critical/") {
				for _, r := range yaraparse.Parse(string(b)).Rules {
					for _, w := range yaraparse.ConditionWords(r) {
						used[w] = p + ": " + r.Name
					}
				}
			}
		}
		for n, f := range dropped {
			if by, ok := used[n]; ok {
				return nil, nil, fmt.Errorf("rule %s (%s) is dropped, but %s uses it - keep it or drop that rule too", n, f, by)
			}
		}
	}
	own, _ := filepath.Glob(filepath.Join(in.WSTree, "rules", "org", "*.yar"))
	if in.NoOwn {
		own = nil
	}
	sort.Strings(own)
	if len(own) > 0 {
		var inc strings.Builder
		inc.WriteString("\n// Organisation rules (Anthophila_Hive workspace)\n")
		for _, p := range own {
			pkg := "org/" + filepath.Base(p)
			if _, ok := files[pkg]; ok {
				return nil, nil, fmt.Errorf("%s is already in source %s", pkg, in.SourceID)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, nil, err
			}
			for _, r := range yaraparse.Parse(string(b)).Rules {
				if f, ok := names[r.Name]; ok {
					return nil, nil, fmt.Errorf("rule name %s of %s is already used in %s - every detection rule is compiled together, names must be unique", r.Name, pkg, f)
				}
				names[r.Name] = pkg
			}
			files[pkg] = b
			fmt.Fprintf(&inc, "include \"%s\"\n", pkg)
		}
		fi, ok := files["file-index.yar"]
		if !ok {
			return nil, nil, fmt.Errorf("source %s has no file-index.yar to include the organisation rules from", in.SourceID)
		}
		if !bytes.HasSuffix(fi, []byte("\n")) {
			fi = append(fi, '\n')
		}
		files["file-index.yar"] = append(append([]byte(nil), fi...), inc.String()...)
		notes = append(notes, fmt.Sprintf("%d organisation rule file(s) included from file-index.yar", len(own)))
	}

	// критичні правила простору
	crit, _ := filepath.Glob(filepath.Join(in.WSTree, "critical", "*.yar"))
	if in.NoCritical {
		crit = nil
		for p := range files {
			if strings.HasPrefix(p, "critical/") {
				delete(files, p)
			}
		}
	}
	if len(crit) > 0 {
		for p := range files {
			if strings.HasPrefix(p, "critical/") {
				return nil, nil, fmt.Errorf("source %s has its own critical/ - the critical rules come only from the workspace", in.SourceID)
			}
		}
	}
	sort.Strings(crit)
	for _, p := range crit {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, nil, err
		}
		files["critical/"+filepath.Base(p)] = b
	}
	return files, notes, nil
}

// VersionLine — перший рядок VERSION.txt (формат cirun; версію з нього читає ПК).
func VersionLine(version, srcCommit, wsCommit string, nCritical int, created time.Time) string {
	crit := ""
	if nCritical > 0 {
		crit = fmt.Sprintf(", critical %s: %d files", short(wsCommit), nCritical)
	}
	return fmt.Sprintf("DocScan rules %s (commit %s%s, %s)\r\n", version, short(srcCommit), crit, created.UTC().Format("2006-01-02"))
}

// Zip — детермінований zip: імена відсортовані, VERSION.txt останнім, час кожного файлу = created.
func Zip(files map[string][]byte, created time.Time) ([]byte, error) {
	var names []string
	for n := range files {
		if n != "VERSION.txt" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if _, ok := files["VERSION.txt"]; ok {
		names = append(names, "VERSION.txt")
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, n := range names {
		if !manifest.SafePath(n) {
			return nil, fmt.Errorf("unsafe path in the package: %q", n)
		}
		o, err := w.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: created.UTC()})
		if err != nil {
			return nil, err
		}
		if _, err := o.Write(files[n]); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Build — пакет, маніфест, підпис, bundle у o.OutDir, потім контракт і критичні тести.
func Build(in Input, o Options) (*Result, error) {
	if !manifest.ValidVersion(o.Version) {
		return nil, fmt.Errorf("version %q is not vX.Y.Z", o.Version)
	}
	pub, err := manifest.PublicKeyOf(o.Seed)
	if err != nil {
		return nil, err
	}
	if pub != o.PublicKey {
		return nil, fmt.Errorf("the signing key is %s, the workspace key is %s - PCs trust only the workspace key", pub, o.PublicKey)
	}
	files, notes, err := Files(in)
	if err != nil {
		return nil, err
	}
	nCrit := 0
	for p := range files {
		if strings.HasPrefix(p, "critical/") {
			nCrit++
		}
	}
	files["VERSION.txt"] = []byte(VersionLine(o.Version, in.SourceCommit, in.WSCommit, nCrit, o.Created))
	pkg, err := Zip(files, o.Created)
	if err != nil {
		return nil, err
	}
	r := &Result{Version: o.Version, Dir: o.OutDir, PkgSHA: sum(pkg), Files: len(files), FileSHA: map[string]string{}, Notes: notes,
		Assets: map[string]string{}}
	for n, b := range files {
		r.FileSHA[n] = sum(b)
	}
	m := manifest.Manifest{Schema: manifest.Schema, Product: manifest.ProductRules, Version: o.Version,
		Build: short(in.WSCommit), Commit: in.WSCommit, Created: o.Created.UTC().Format(time.RFC3339),
		Package: manifest.File{Name: install.PackageName, Size: int64(len(pkg)), SHA256: r.PkgSHA}, Files: r.FileSHA}
	if err := m.Check(); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	sig, err := manifest.Sign(data, o.Seed)
	if err != nil {
		return nil, err
	}
	if _, r.KeyID, err = manifest.VerifyProduct(data, sig, []string{o.PublicKey}, manifest.ProductRules); err != nil {
		return nil, fmt.Errorf("manifest self-check: %w", err)
	}
	var bundle bytes.Buffer
	bw := zip.NewWriter(&bundle)
	for _, f := range []struct {
		n string
		b []byte
	}{{install.ManifestName, data}, {install.SigName, []byte(sig)}, {install.PackageName, pkg}} {
		w, err := bw.CreateHeader(&zip.FileHeader{Name: f.n, Method: zip.Deflate, Modified: o.Created.UTC()})
		if err != nil {
			return nil, err
		}
		w.Write(f.b)
	}
	if err := bw.Close(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(o.OutDir, 0o755); err != nil {
		return nil, err
	}
	for n, b := range map[string][]byte{install.PackageName: pkg, install.ManifestName: data, install.SigName: []byte(sig), install.BundleName: bundle.Bytes()} {
		p := filepath.Join(o.OutDir, n)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return nil, err
		}
		r.Assets[n] = p
	}

	// контракт — тим самим кодом, що на ПК
	co := contract.Options{Keys: []string{o.PublicKey}, NewerThan: o.NewerThan}
	if o.Tools.Configured() {
		co.Compiler = o.Tools
	}
	if r.Contract, err = contract.VerifyRules(r.Assets[install.BundleName], co); err != nil {
		return nil, err
	}

	// критичні тести (як cirun: усі tests/match у черзі, жоден tests/no-match) з основними правилами пакета
	if len(in.Critical) > 0 && nCrit > 0 && o.Tools.Configured() {
		tmp, err := os.MkdirTemp("", "hive-build-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		tree := filepath.Join(tmp, "rules")
		for n, b := range files {
			p := filepath.Join(tree, filepath.FromSlash(n))
			os.MkdirAll(filepath.Dir(p), 0o755)
			if err := os.WriteFile(p, b, 0o644); err != nil {
				return nil, err
			}
		}
		md, nd := filepath.Join(tmp, "match"), filepath.Join(tmp, "no-match")
		for i, t := range in.Critical {
			d := md
			if t.Expect == "no-match" {
				d = nd
			}
			os.MkdirAll(d, 0o755)
			b, err := os.ReadFile(t.Path)
			if err != nil {
				return nil, err
			}
			// ім'я — як у наборі (розширення важливе для розбору документа); номер — щоб не було збігів імен
			if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("%04d_%s", i, filepath.Base(t.Path))), b, 0o600); err != nil {
				return nil, err
			}
		}
		r.Critical, err = checks.CheckCriticalSet(o.Tools, filepath.Join(tree, "critical"), filepath.Join(tree, "docscan-index.yar"), dirIf(md), dirIf(nd))
		if err != nil {
			return nil, err
		}
	} else if len(in.Critical) > 0 && nCrit > 0 {
		r.Notes = append(r.Notes, "critical tests not run: no DocScan yara")
	}
	return r, nil
}

func dirIf(d string) string {
	if _, err := os.Stat(d); err != nil {
		return ""
	}
	return d
}

func short(c string) string {
	if len(c) > 8 {
		return c[:8]
	}
	return c
}

var testNameRe = regexp.MustCompile(`^\d{4}_`)

// TestName — ім'я документа тесту без службового номера (для звіту).
func TestName(p string) string { return testNameRe.ReplaceAllString(filepath.Base(p), "") }
