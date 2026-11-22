package contract

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

// fakeCompiler — компіляція без yara (для перевірок, що не стосуються самої компіляції).
type fakeCompiler struct{ index, critical error }

func (f fakeCompiler) CompileIndex(string) error    { return f.index }
func (f fakeCompiler) CompileCritical(string) error { return f.critical }

// spec — що покласти в тестовий bundle і як його зіпсувати.
type spec struct {
	files      map[string]string // вміст пакета (за ним рахується маніфест)
	version    string            // у маніфесті
	versionTxt string            // перший рядок VERSION.txt; "" — правильний
	seed       string            // ключ підпису
	zipOnly    map[string]string // підмінити / додати у zip ПІСЛЯ розрахунку маніфесту
	dropFromZ  []string          // прибрати із zip після розрахунку маніфесту
	pkgTail    string            // дописати байти в кінець пакета після розрахунку sha256
	sig        string            // замість справжнього підпису
	extra      bool              // зайвий файл у bundle
}

var testSeed, testPub = func() (string, string) {
	s, p, err := manifest.NewSeed()
	if err != nil {
		panic(err)
	}
	return s, p
}()

func baseSpec() spec {
	return spec{
		version: "v2.0.0",
		seed:    testSeed,
		files: map[string]string{
			"docscan-index.yar":  "include \"docscan-policy.yar\"\ninclude \"file-index.yar\"\n",
			"docscan-policy.yar": "rule DS_X { condition: false }\n",
			"file-index.yar":     "include \"general/a.yar\"\n",
			"general/a.yar":      "rule A { condition: false }\n",
			"critical/zsu.yar":   "rule crit_markings { strings: $a = \"x\" condition: $a }\n",
			"critical/bank.yar":  "rule ORG_BANK_CARD { strings: $a = \"y\" condition: $a }\n",
		},
	}
}

func writeZip(t *testing.T, p string, files map[string]string) {
	t.Helper()
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		o, err := w.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: time.Unix(0, 0)})
		if err != nil {
			t.Fatal(err)
		}
		o.Write([]byte(files[n]))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// build — тестовий DocScan-rules-bundle.zip за spec.
func build(t *testing.T, s spec) string {
	t.Helper()
	d := t.TempDir()
	files := map[string]string{}
	for k, v := range s.files {
		files[k] = v
	}
	if s.versionTxt == "" {
		s.versionTxt = "DocScan rules " + s.version + " (commit abcdef12, critical 12345678: 2 files, 2026-11-22)"
	}
	files["VERSION.txt"] = s.versionTxt + "\r\n"
	hashes := map[string]string{}
	for k, v := range files {
		hashes[k] = sum([]byte(v))
	}
	for k, v := range s.zipOnly {
		files[k] = v
	}
	for _, k := range s.dropFromZ {
		delete(files, k)
	}
	pkgPath := filepath.Join(d, install.PackageName)
	writeZip(t, pkgPath, files)
	pkg, _ := os.ReadFile(pkgPath)
	m := manifest.Manifest{Schema: manifest.Schema, Product: manifest.ProductRules, Version: s.version, Build: "abcdef12",
		Commit: "abcdef12", Created: "2026-11-22T00:00:00Z",
		Package: manifest.File{Name: install.PackageName, Size: int64(len(pkg)), SHA256: sum(pkg)}, Files: hashes}
	data, _ := json.MarshalIndent(m, "", "  ")
	data = append(data, '\n')
	sig, err := manifest.Sign(data, s.seed)
	if err != nil {
		t.Fatal(err)
	}
	if s.sig != "" {
		sig = s.sig
	}
	b := map[string]string{install.ManifestName: string(data), install.SigName: sig, install.PackageName: string(pkg) + s.pkgTail}
	if s.extra {
		b["README.txt"] = "x"
	}
	bundle := filepath.Join(d, install.BundleName)
	writeZip(t, bundle, b)
	return bundle
}

func status(r *Report, id string) Check {
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	return Check{ID: id, Status: "MISSING"}
}

func verify(t *testing.T, s spec, o Options) *Report {
	t.Helper()
	if o.Keys == nil {
		o.Keys = []string{testPub}
	}
	if o.Compiler == nil {
		o.Compiler = fakeCompiler{}
	}
	r, err := VerifyRules(build(t, s), o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGoodPackagePasses(t *testing.T) {
	r := verify(t, baseSpec(), Options{NewerThan: "v1.9.9"})
	if r.Result() != "PASS" {
		for _, c := range r.Checks {
			t.Logf("%s %s %s", c.Status, c.ID, c.Detail)
		}
		t.Fatalf("result %s", r.Result())
	}
}

// Кожне псування має дати FAIL саме в своїй перевірці.
func TestBrokenPackagesFail(t *testing.T) {
	_, otherPub, _ := manifest.NewSeed()
	otherSeed, _, _ := manifest.NewSeed()
	cases := []struct {
		name string
		mod  func(*spec)
		o    Options
		id   string
		want string // частина пояснення
	}{
		{"file changed after signing", func(s *spec) { s.zipOnly = map[string]string{"general/a.yar": "rule A { condition: true }\n"} }, Options{}, "R05", "sha256 differs"},
		{"extra file in the package", func(s *spec) { s.zipOnly = map[string]string{"general/evil.yar": "x"} }, Options{}, "R05", "unexpected file"},
		{"file of the manifest missing", func(s *spec) { s.dropFromZ = []string{"general/a.yar"} }, Options{}, "R05", "files of the manifest"},
		{"package bytes changed", func(s *spec) { s.pkgTail = "junk" }, Options{}, "R04", "size / sha256"},
		{"signed by another key", func(s *spec) { s.seed = otherSeed }, Options{}, "R03", "not valid for any trusted key"},
		{"trusted keys do not include ours", func(s *spec) {}, Options{Keys: []string{otherPub}}, "R03", "not valid"},
		{"broken signature line", func(s *spec) { s.sig = "ed25519 deadbeef AAAA\n" }, Options{}, "R03", "bad signature"},
		{"unsafe path", func(s *spec) { s.files["../evil.yar"] = "x" }, Options{}, "R03", "invalid"},
		{"VERSION.txt differs from the manifest", func(s *spec) { s.versionTxt = "DocScan rules v1.0.0 (commit abcdef12, 2026-11-22)" }, Options{}, "R07", "reinstall"},
		{"no docscan-index.yar", func(s *spec) { delete(s.files, "docscan-index.yar") }, Options{}, "R06", "no docscan-index.yar"},
		{"critical subfolder", func(s *spec) { s.files["critical/sub/x.yar"] = "rule Q { condition: false }" }, Options{}, "R08", "no subfolders"},
		{"critical bad file name", func(s *spec) { s.files["critical/звіт.yar"] = "rule Q { condition: false }" }, Options{}, "R08", "not a rules file"},
		{"critical not .yar", func(s *spec) { s.files["critical/notes.txt"] = "x" }, Options{}, "R08", "not a rules file"},
		{"critical too big", func(s *spec) { s.files["critical/big.yar"] = strings.Repeat("/", MaxCriticalBytes) }, Options{}, "R08", "bytes together"},
		{"critical duplicate rule names", func(s *spec) { s.files["critical/bank2.yar"] = "rule ORG_BANK_CARD { condition: false }\n" }, Options{}, "R09", "ORG_BANK_CARD"},
		{"rules do not compile", func(s *spec) {}, Options{Compiler: fakeCompiler{index: errors.New("yarac: syntax error")}}, "R10", "syntax error"},
		{"critical do not compile", func(s *spec) {}, Options{Compiler: fakeCompiler{critical: errors.New("critical rules: error")}}, "R11", "error"},
		{"not newer than the target", func(s *spec) {}, Options{NewerThan: "v2.0.0"}, "R12", "not newer"},
		{"older than the target", func(s *spec) {}, Options{NewerThan: "v2.0.1"}, "R12", "not newer"},
		{"extra file in the bundle", func(s *spec) { s.extra = true }, Options{}, "R01", "exactly"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := baseSpec()
			c.mod(&s)
			r := verify(t, s, c.o)
			ch := status(r, c.id)
			if ch.Status != Fail || !strings.Contains(ch.Detail, c.want) {
				for _, x := range r.Checks {
					t.Logf("%s %s %s", x.Status, x.ID, x.Detail)
				}
				t.Fatalf("%s: %s %q, want FAIL with %q", c.id, ch.Status, ch.Detail, c.want)
			}
			if r.Result() != "FAIL" {
				t.Fatalf("result %s", r.Result())
			}
		})
	}
}

func TestNoCompilerIsIncomplete(t *testing.T) {
	r, err := VerifyRules(build(t, baseSpec()), Options{Keys: []string{testPub}, NewerThan: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Result() != "INCOMPLETE" || status(r, "R10").Status != Skip {
		t.Fatalf("result %s, R10 %s", r.Result(), status(r, "R10").Status)
	}
}

func TestTokenInURLRefused(t *testing.T) {
	if _, err := VerifyRules("https://reader:secret@example.invalid/rules", Options{Keys: []string{testPub}}); err == nil || !strings.Contains(err.Error(), "leaks") {
		t.Fatalf("expected a refusal, got %v", err)
	}
}

// Справжній реліз (HIVE_RELEASE_DIR: тека з rules-manifest.json, .sig, DocScan-rules.zip, bundle) і його зіпсовані
// копії; компіляція — справжнім DocScan, якщо задано HIVE_YARA / HIVE_YARAC.
func TestRealRelease(t *testing.T) {
	dir := os.Getenv("HIVE_RELEASE_DIR")
	if dir == "" {
		t.Skip("HIVE_RELEASE_DIR is not set")
	}
	o := Options{Keys: manifest.OfficialKeys}
	if tl := yaraexec.FromEnv(); tl.Configured() {
		o.Compiler = tl
	}
	r, err := VerifyRules(filepath.Join(dir, install.BundleName), o)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Checks {
		if c.Status == Fail {
			t.Errorf("real release: %s %s", c.ID, c.Detail)
		}
	}
	orig, _ := install.ReadBundle(filepath.Join(dir, install.BundleName))
	corrupt := func(name string, edit func(map[string][]byte)) string {
		m := map[string][]byte{}
		for k, v := range orig.Files {
			m[k] = append([]byte(nil), v...)
		}
		edit(m)
		out := map[string]string{}
		for k, v := range m {
			out[k] = string(v)
		}
		p := filepath.Join(t.TempDir(), name+".zip")
		writeZip(t, p, out)
		return p
	}
	// переписаний пакет: одне правило змінено, маніфест — старий
	repack := func(m map[string][]byte, edit func(map[string]string)) {
		p := filepath.Join(t.TempDir(), "in.zip")
		os.WriteFile(p, m[install.PackageName], 0o644)
		zr, _ := zip.OpenReader(p)
		files := map[string]string{}
		for _, e := range zr.File {
			rc, _ := e.Open()
			b := make([]byte, e.UncompressedSize64)
			n, _ := io.ReadFull(rc, b)
			rc.Close()
			files[e.Name] = string(b[:n])
		}
		zr.Close()
		edit(files)
		q := filepath.Join(t.TempDir(), "out.zip")
		writeZip(t, q, files)
		m[install.PackageName], _ = os.ReadFile(q)
	}
	for _, c := range []struct {
		name, id string
		edit     func(map[string][]byte)
	}{
		{"package-bytes", "R04", func(m map[string][]byte) { m[install.PackageName] = append(m[install.PackageName], 0) }},
		{"manifest-edited", "R03", func(m map[string][]byte) {
			m[install.ManifestName] = []byte(strings.Replace(string(m[install.ManifestName]), r.Version, "v9.9.9", 1))
		}},
		{"rule-changed", "R04", func(m map[string][]byte) {
			repack(m, func(f map[string]string) { f["docscan-policy.yar"] += "\n// changed\n" })
		}},
	} {
		rep, err := VerifyRules(corrupt(c.name, c.edit), o)
		if err != nil {
			t.Fatal(err)
		}
		if status(rep, c.id).Status != Fail || rep.Result() != "FAIL" {
			t.Errorf("%s: %s %s, want FAIL", c.name, c.id, status(rep, c.id).Status)
		}
	}
}
