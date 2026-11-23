package build

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for n, s := range files {
		p := filepath.Join(root, filepath.FromSlash(n))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func tree(t *testing.T) (src, ws string) {
	src, ws = t.TempDir(), t.TempDir()
	write(t, src, map[string]string{
		"docscan-index.yar":  "include \"docscan-policy.yar\"\ninclude \"file-index.yar\"\n",
		"docscan-policy.yar": "rule DS_P { condition: false }\n",
		"file-index.yar":     "include \"general/a.yar\"\n",
		"general/a.yar":      "// about A\nrule A { condition: false }\n\n// about B\nrule B { condition: A }\n\nrule C { condition: false }\n",
		"LICENSE-x":          "license",
		"README.md":          "not shipped",
		"tools/gen.py":       "not shipped",
		".hidden":            "not shipped",
	})
	write(t, ws, map[string]string{
		"rules/org/own.yar": "rule ORG_Mal_X { strings: $a = \"evil\" condition: $a }\n",
		"critical/zsu.yar":  "rule crit_markings { strings: $a = \"службов\" condition: $a }\n",
	})
	return
}

func TestFiles(t *testing.T) {
	src, ws := tree(t)
	in := Input{SourceTree: src, SourceID: "s", SourceCommit: "1234567890", WSTree: ws, WSCommit: "abcdef0123",
		Decisions: []workspace.Decision{{Source: "s", File: "general/a.yar", Rule: "C", Status: "drop", Reason: "FP"}}}
	files, _, err := Files(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"README.md", "tools/gen.py", ".hidden"} {
		if _, ok := files[n]; ok {
			t.Errorf("%s shipped", n)
		}
	}
	if _, ok := files["LICENSE-x"]; !ok {
		t.Error("licence not shipped")
	}
	if a := string(files["general/a.yar"]); strings.Contains(a, "rule C") || !strings.Contains(a, "rule B") {
		t.Errorf("drop C:\n%s", a)
	}
	if fi := string(files["file-index.yar"]); !strings.HasSuffix(fi, "include \"org/own.yar\"\n") {
		t.Errorf("file-index.yar:\n%s", fi)
	}
	if _, ok := files["critical/zsu.yar"]; !ok {
		t.Error("no critical/zsu.yar")
	}
	// редакції: без власних — org/ немає і file-index.yar не підключає; без критичних — critical/ немає
	ed := in
	ed.NoOwn, ed.NoCritical = true, true
	ef, _, err := Files(ed)
	if err != nil {
		t.Fatal(err)
	}
	for p := range ef {
		if strings.HasPrefix(p, "org/") || strings.HasPrefix(p, "critical/") {
			t.Errorf("%s in an edition without own / critical rules", p)
		}
	}
	if strings.Contains(string(ef["file-index.yar"]), "org/") || ef["general/a.yar"] == nil {
		t.Errorf("edition file-index.yar:\n%s", ef["file-index.yar"])
	}
	// відкинути правило, на яке посилається інше, не можна
	in.Decisions = []workspace.Decision{{Source: "s", File: "general/a.yar", Rule: "A", Status: "drop", Reason: "x"}}
	if _, _, err := Files(in); err == nil || !strings.Contains(err.Error(), "uses it") {
		t.Fatalf("dependency: %v", err)
	}
	// застаріле рішення
	in.Decisions = []workspace.Decision{{Source: "s", File: "general/a.yar", Rule: "Gone", Status: "drop", Reason: "x"}}
	if _, _, err := Files(in); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale: %v", err)
	}
	// конфлікт назв з правилами джерела
	in.Decisions = nil
	write(t, ws, map[string]string{"rules/org/own.yar": "rule A { condition: true }\n"})
	if _, _, err := Files(in); err == nil || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("name clash: %v", err)
	}
}

func TestBuildDeterministicAndVerified(t *testing.T) {
	src, ws := tree(t)
	seed, pub, _ := manifest.NewSeed()
	in := Input{SourceTree: src, SourceID: "s", SourceCommit: "1234567890", WSTree: ws, WSCommit: "abcdef0123"}
	created := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	o := Options{Version: "v1.0.1", Created: created, Seed: seed, PublicKey: pub, NewerThan: "v1.0.0", Tools: yaraexec.FromEnv()}
	o.OutDir = t.TempDir()
	r1, err := Build(in, o)
	if err != nil {
		t.Fatal(err)
	}
	o.OutDir = t.TempDir()
	r2, err := Build(in, o)
	if err != nil {
		t.Fatal(err)
	}
	if r1.PkgSHA != r2.PkgSHA {
		t.Fatalf("not deterministic: %s vs %s", r1.PkgSHA, r2.PkgSHA)
	}
	want := "PASS"
	if !o.Tools.Configured() {
		want = "INCOMPLETE"
	}
	if got := r1.Contract.Result(); got != want {
		for _, c := range r1.Contract.Checks {
			t.Logf("%s %s %s", c.Status, c.ID, c.Detail)
		}
		t.Fatalf("contract %s, want %s", got, want)
	}
	_, other, _ := manifest.NewSeed()
	o.PublicKey = other
	if _, err := Build(in, o); err == nil {
		t.Fatal("foreign signing key accepted")
	}
}

// Приймальний тест MVP: з тих самих комітів — ті самі файли з тими самими sha256, що в офіційному релізі (крім
// VERSION.txt). HIVE_RULES_REPO — чекаут yara-docscan-rules; HIVE_RELEASE_DIR — файли релізу v1.0.0.
func TestSameFilesAsOfficialRelease(t *testing.T) {
	repo, rel := os.Getenv("HIVE_RULES_REPO"), os.Getenv("HIVE_RELEASE_DIR")
	if repo == "" || rel == "" {
		t.Skip("HIVE_RULES_REPO / HIVE_RELEASE_DIR are not set")
	}
	var off manifest.Manifest
	b, err := os.ReadFile(filepath.Join(rel, install.ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &off)
	src := t.TempDir()
	if err := (&gitx.Repo{Dir: repo}).Extract(off.Commit, src); err != nil {
		t.Fatal(err)
	}
	files, _, err := Files(Input{SourceTree: src, SourceID: "docscan-rules", SourceCommit: off.Commit, WSTree: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for p, h := range off.Files {
		if p == "VERSION.txt" {
			continue
		}
		n++
		if b, ok := files[p]; !ok {
			t.Errorf("missing %s", p)
		} else if sum(b) != h {
			t.Errorf("%s: sha256 differs", p)
		}
	}
	for p := range files {
		if _, ok := off.Files[p]; !ok {
			t.Errorf("extra %s", p)
		}
	}
	t.Logf("%s @ %s: %d files compared, release %s", repo, off.Commit[:8], n, off.Version)
}
