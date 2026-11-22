package hive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/build"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

const miniGenerator = `
import re
SOURCES = {"upstream": ("%s", "%s")}
FORGE_SOURCES = {}
SOURCE_INFO = {}
RENAME = {}
DROP = {"Old_FP": "FP: clean documents"}
OLD_YEAR = 2016
INFO = {"Indicator_X"}
INFO_TAG = "docscan_info"
DOC_TAG = "docscan_doc"
`

func TestVendorGeneratorFlow(t *testing.T) {
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		if _, err := os.Stat("/opt/homebrew/bin/python3"); err != nil {
			t.Skip("no python3 (needed only to import the generator settings)")
		}
	}
	d := t.TempDir()
	up, _ := gitx.Init(filepath.Join(d, "upstream"))
	put(t, up.Dir, map[string]string{
		"yara/apt.yar":   "rule APT_A { strings: $a = \"apt-a\" condition: uint16(0) == 0x5A4D and $a }\nrule Old_FP { condition: false }\nrule Lnx_Thing { condition: uint32(0) == 0x464c457f }\n",
		"yara/ind.yar":   "rule Indicator_X { strings: $a = \"x\" condition: $a }\n",
		"yara/other.yar": "rule Not_Selected { condition: false }\n",
		"LICENSE":        "MIT\r\n",
	})
	c1, _ := up.CommitAll("v1", "")
	src, _ := gitx.Init(filepath.Join(d, "rules"))
	put(t, src.Dir, map[string]string{
		"docscan-index.yar":        "include \"docscan-policy.yar\"\ninclude \"file-index.yar\"\n",
		"docscan-policy.yar":       "import \"docscan\"\nrule DS_P { meta: severity = \"HIGH\" condition: false }\n",
		"file-index.yar":           "// stale, regenerated\n",
		"general/stale.yar":        "rule Stale { condition: false }\n",
		"maldoc/vba_plaintext.yar": "rule VBA_Plain { strings: $a = \"Sub AutoOpen\" condition: $a }\n",
	})
	src.CommitAll("tree", "")
	script := filepath.Join(d, "build_vendor_rules.py")
	os.WriteFile(script, []byte(strings.Replace(strings.Replace(miniGenerator, "%s", up.Dir, 1), "%s", c1, 1)), 0o644)
	selFile := filepath.Join(d, "vendor-selection.txt")
	os.WriteFile(selFile, []byte("# out src path\ngeneral upstream yara/apt.yar\ngeneral upstream yara/ind.yar\n"), 0o644)

	a, err := Open(filepath.Join(d, "data"), yaraexec.FromEnv())
	if err != nil {
		t.Fatal(err)
	}
	w, _ := a.CreateWS(workspace.Config{Name: "pub", Visibility: "public"}, "t")
	_, seed, _ := a.NewKey(w, "rules", "env:HIVE_VENDOR_TEST_KEY", "t")
	t.Setenv("HIVE_VENDOR_TEST_KEY", seed)
	if err := a.AddSource(w, workspace.Source{ID: "rules", URL: src.Dir, Ref: "main"}, "t"); err != nil {
		t.Fatal(err)
	}
	rep, err := a.ImportVendor(w, script, selFile, "", "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Rules != 2 || len(rep.Dropped) != 2 || len(rep.Info) != 1 {
		t.Fatalf("report %+v", rep)
	}
	r, _ := os.ReadFile(filepath.Join(w.Dir, "vendor", "report.md"))
	if !strings.Contains(string(r), "Old_FP — FP: clean documents") || !strings.Contains(string(r), "Lnx_Thing — ELF only") {
		t.Fatalf("report.md:\n%s", r)
	}
	// бібліотека: згенерований набір + відкинуті генератором з причиною
	got, _, _ := a.DB.FindRules(store.RuleQuery{WS: "pub", Origin: "rules", Text: "APT_A"})
	if len(got) != 1 || got[0].File != "general/apt.yar" {
		t.Fatalf("library %+v", got)
	}
	if st, _, _ := a.DB.FindRules(store.RuleQuery{WS: "pub", Text: "Stale"}); len(st) != 0 {
		t.Fatal("stale source file still in the library")
	}
	dr, _, _ := a.DB.FindRules(store.RuleQuery{WS: "pub", Origin: "vendor"})
	if len(dr) != 2 || dr[0].Meta["hive_dropped"] == "" {
		t.Fatalf("dropped %+v", dr)
	}

	if a.Tools.Configured() {
		b, err := a.Build(w, "patch", false, "t")
		if err != nil || !b.OK() {
			t.Fatalf("build: %v", err)
		}
		zipFiles := b.FileSHA
		if _, ok := zipFiles["general/stale.yar"]; ok {
			t.Fatal("stale generated file shipped")
		}
		for _, p := range []string{"general/apt.yar", "general/ind.yar", "file-index.yar", "LICENSE-upstream", "maldoc/vba_plaintext.yar"} {
			if _, ok := zipFiles[p]; !ok && p != "LICENSE-upstream" {
				t.Errorf("no %s in the package", p)
			}
		}
	}

	// оновлення джерела: перегляд різниці, потім закріплення
	put(t, up.Dir, map[string]string{
		"yara/apt.yar": "rule APT_A { strings: $a = \"apt-a2\" condition: uint16(0) == 0x5A4D and $a }\nrule APT_B { strings: $b = \"b\" condition: uint16(0) == 0x5A4D and $b }\nrule Old_FP { condition: false }\n",
		"yara/new.yar": "rule Brand_New { condition: false }\n",
	})
	c2, _ := up.CommitAll("v2", "")
	u, err := a.VendorUpdatePreview(w, "upstream", "main")
	if err != nil {
		t.Fatal(err)
	}
	st := map[string]string{}
	for _, c := range u.Changes {
		st[c.Rule] = c.Status
	}
	if u.To != c2 || st["APT_A"] != "changed" || st["APT_B"] != "added" || st["Lnx_Thing"] != "removed" || len(u.NewFiles) != 2 {
		t.Fatalf("preview %+v", u)
	}
	if len(u.Added) != 1 || !strings.HasSuffix(u.Added[0], "APT_B") || u.KeptBefore >= u.KeptAfter {
		t.Fatalf("generated diff %+v", u)
	}
	if cfg, _, _ := w.Vendor(); cfg.Sources[0].Pin != c1 {
		t.Fatal("preview changed the pin")
	}
	if _, err := a.VendorPin(w, "upstream", c2, "t"); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := a.DB.FindRules(store.RuleQuery{WS: "pub", Text: "APT_B"}); len(got) != 1 {
		t.Fatal("APT_B not in the library after pinning")
	}
}

// Справжні джерела: пакет Hive з генератором = офіційний реліз v1.0.0 (ті самі файли, ті самі sha256, крім
// VERSION.txt). HIVE_VENDOR_DIR, HIVE_RULES_REPO, HIVE_RELEASE_DIR, HIVE_YARA / HIVE_YARAC.
func TestVendorRealParityPackage(t *testing.T) {
	vdir, repo, rel := os.Getenv("HIVE_VENDOR_DIR"), os.Getenv("HIVE_RULES_REPO"), os.Getenv("HIVE_RELEASE_DIR")
	if vdir == "" || repo == "" || rel == "" {
		t.Skip("HIVE_VENDOR_DIR / HIVE_RULES_REPO / HIVE_RELEASE_DIR are not set")
	}
	var off manifest.Manifest
	b, _ := os.ReadFile(filepath.Join(rel, install.ManifestName))
	json.Unmarshal(b, &off)
	d := t.TempDir()
	a, err := Open(filepath.Join(d, "data"), yaraexec.FromEnv())
	if err != nil {
		t.Fatal(err)
	}
	w, _ := a.CreateWS(workspace.Config{Name: "anthophila", Visibility: "public"}, "t")
	if err := a.AddSource(w, workspace.Source{ID: "docscan-rules", URL: repo, Commit: off.Commit}, "t"); err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(d, "tools")
	if err := (&gitx.Repo{Dir: repo}).Extract(off.Commit, filepath.Join(d, "snap")); err != nil {
		t.Fatal(err)
	}
	os.Rename(filepath.Join(d, "snap", "tools"), tools)
	rep, err := a.ImportVendor(w, filepath.Join(tools, "build_vendor_rules.py"), filepath.Join(tools, "vendor-selection.txt"), vdir, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("generator: %d files, %d rules", rep.Files, rep.Rules)
	tmp := t.TempDir()
	head, _ := w.Head()
	in, err := a.input(w, head, tmp)
	if err != nil {
		t.Fatal(err)
	}
	if in.VendorTree, _, err = a.vendorTree(in.WSTree, in.SourceTree); err != nil {
		t.Fatal(err)
	}
	files, notes, err := build.Files(in)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(notes)
	n := 0
	for p, h := range off.Files {
		if p == "VERSION.txt" {
			continue
		}
		n++
		if b, ok := files[p]; !ok {
			t.Errorf("missing %s", p)
		} else if sha(b) != h {
			t.Errorf("%s differs", p)
		}
	}
	for p := range files {
		if _, ok := off.Files[p]; !ok {
			t.Errorf("extra %s", p)
		}
	}
	t.Logf("%d package files = official %s", n, off.Version)
}
