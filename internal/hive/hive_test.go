package hive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/orglists"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func put(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for n, s := range files {
		p := filepath.Join(root, filepath.FromSlash(n))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEndToEnd(t *testing.T) {
	tools := yaraexec.FromEnv()
	if !tools.Configured() {
		t.Skip("HIVE_YARA / HIVE_YARAC are not set: the end-to-end test needs DocScan")
	}
	d := t.TempDir()
	// джерело: маленьке дерево правил DocScan у git
	srcRepo, _ := gitx.Init(filepath.Join(d, "rules-src"))
	put(t, srcRepo.Dir, map[string]string{
		"docscan-index.yar": "include \"file-index.yar\"\n",
		"file-index.yar":    "include \"general/a.yar\"\n",
		"general/a.yar":     "rule Vendor_A { strings: $a = \"vendor-a\" condition: $a }\n\nrule Vendor_FP { strings: $a = \"common\" condition: $a }\n",
		"README.md":         "x",
	})
	srcCommit, _ := srcRepo.CommitAll("rules", "")
	// критичні правила з тестами, як docscan-critical
	crit := filepath.Join(d, "docscan-critical")
	put(t, crit, map[string]string{
		"critical/zsu.yar":        "rule crit_markings {\n meta:\n  description = \"грифи\"\n  category = \"classified\"\n  owner = \"sb\"\n strings:\n  $m = /службов[^ ]{0,12} користуванн/\n condition:\n  $m\n}\n",
		"tests/match/doc1.txt":    "Для службового користування",
		"tests/no-match/doc2.txt": "звичайний лист",
	})
	white := filepath.Join(d, "whitelist.json")
	put(t, d, map[string]string{"whitelist.json": `{"schema":1,"entries":[{"sha256":"` + strings.Repeat("1", 64) + `","comment":"own app"}]}`})

	a, err := Open(filepath.Join(d, "data"), tools)
	if err != nil {
		t.Fatal(err)
	}
	w, err := a.CreateWS(workspace.Config{Name: "org-example", Visibility: "private", VersionFloor: "v1.0.0"}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	_, seed, err := a.NewKey(w, "rules", "env:HIVE_TEST_RULES_KEY", "tester")
	if err != nil || seed == "" {
		t.Fatalf("%v", err)
	}
	t.Setenv("HIVE_TEST_RULES_KEY", seed)
	_, lseed, _ := a.NewKey(w, "lists", "env:HIVE_TEST_LISTS_KEY", "tester")
	t.Setenv("HIVE_TEST_LISTS_KEY", lseed)

	if err := a.AddSource(w, workspace.Source{ID: "docscan-rules", URL: srcRepo.Dir, Ref: "main"}, "tester"); err != nil {
		t.Fatal(err)
	}
	if nr, nt, err := a.ImportCritical(w, crit, "tester"); err != nil || nr != 1 || nt != 2 {
		t.Fatalf("import critical: %d %d %v", nr, nt, err)
	}
	if n, err := a.ImportList(w, "white", white, "tester"); err != nil || n != 1 {
		t.Fatalf("import list: %d %v", n, err)
	}
	// бібліотека
	rules, total, _ := a.DB.FindRules(storeQuery(w, "Vendor"))
	if total != 2 || len(rules) != 2 {
		t.Fatalf("library: %d", total)
	}
	if txt, err := a.RuleText(w, "docscan-rules", "general/a.yar", "Vendor_FP"); err != nil || !strings.HasPrefix(txt, "rule Vendor_FP") {
		t.Fatalf("rule text %q %v", txt, err)
	}
	if err := a.Decide(w, workspace.Decision{Source: "docscan-rules", File: "general/a.yar", Rule: "Vendor_FP", Status: "drop", Reason: "FP on clean documents"}, "tester"); err != nil {
		t.Fatal(err)
	}
	// власне правило: помилка не зберігається, правильне — зберігається
	if fs, saved, _ := a.SaveOwnRule(w, "org", "incident.yar", "rule Vendor_A { condition: true }\n", "tester"); saved || len(fs) == 0 {
		t.Fatalf("name clash saved: %+v", fs)
	}
	if fs, saved, err := a.SaveOwnRule(w, "org", "incident.yar", "rule ORG_Mal_Incident { strings: $a = \"incident-marker\" condition: $a }\n", "tester"); !saved || err != nil {
		t.Fatalf("%+v %v", fs, err)
	}
	a.AddTest(w, workspace.TestCase{Scope: "rule", Rule: "ORG_Mal_Incident", Expect: "match", Name: "sample.bin"}, strings.NewReader("xx incident-marker xx"), "tester")
	a.AddTest(w, workspace.TestCase{Scope: "rule", Rule: "ORG_Mal_Incident", Expect: "no-match", Name: "clean.docx"}, strings.NewReader("nothing"), "tester")
	res, err := a.RunTests(w, "org", "incident.yar")
	if err != nil || len(res) != 2 || !res[0].OK || !res[1].OK {
		t.Fatalf("tests %+v %v", res, err)
	}
	// списки
	wl, _, warns, _ := a.Lists(w)
	if len(wl.Entries) != 1 {
		t.Fatalf("white %d", len(wl.Entries))
	}
	_ = warns
	wl.Entries = append(wl.Entries, orglists.Entry{Path: `C:\Users\*\Desktop\App*.lnk`, LnkTarget: `\\fileserver\BIN\App\`, Comment: "app shortcut"})
	if err := a.SaveList(w, "white", wl, "add App shortcut", "tester"); err != nil {
		t.Fatal(err)
	}

	// збирання
	br, err := a.Build(w, "patch", false, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if br.Version != "v1.0.1" || !br.OK() || br.Critical == nil || br.Critical.Match != 1 {
		for _, c := range br.Contract.Checks {
			t.Logf("%s %s %s", c.Status, c.ID, c.Detail)
		}
		t.Fatalf("build %s ok=%v critical=%+v", br.Version, br.OK(), br.Critical)
	}
	pkgA, _ := os.ReadFile(filepath.Join(br.Dir, "DocScan-rules.zip"))
	if len(pkgA) == 0 {
		t.Fatal("no package")
	}
	// публікація в теку (як UNC) і списки
	share := filepath.Join(d, "share")
	w.Cfg.Targets = []workspace.Target{{ID: "share", Kind: "folder", Path: filepath.Join(share, "rules")}, {ID: "lists", Kind: "lists-folder", Path: filepath.Join(share, "lists")}}
	w.SaveConfig()
	w.Commit("targets", "tester")
	if _, err := a.Publish(w, "v1.0.1", "share", "tester", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(w.Dir, "releases", "v1.0.1.lock")); err != nil {
		t.Fatal("no lock")
	}
	if tag, _ := w.Repo.Line("tag", "--list", "v1.0.1"); tag != "v1.0.1" {
		t.Fatal("no tag")
	}
	if _, err := a.PublishLists(w, "lists", "tester", nil); err != nil {
		t.Fatal(err)
	}
	// наступна версія враховує ціль; відтворення дає ті самі sha256
	if next, _, _ := a.NextVersion(w, "patch", true); next != "v1.0.2" {
		t.Fatalf("next %s", next)
	}
	n, diff, err := a.Reproduce(w, "v1.0.1")
	if err != nil || len(diff) > 0 {
		t.Fatalf("reproduce: %d %v %v", n, diff, err)
	}
	_ = srcCommit
}

func storeQuery(w *workspace.WS, text string) (q store.RuleQuery) {
	q.WS, q.Text = w.Cfg.Name, text
	return
}
