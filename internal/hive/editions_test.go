package hive

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

// Редакції: збирання (кожен склад — один раз), публікація в публічну гілку лише з явним підтвердженням, склад
// кожної редакції в гілці відповідає налаштуванню, наступна версія враховує версію на цілі.
func TestEditionsBuildAndPublish(t *testing.T) {
	tools := yaraexec.FromEnv()
	if !tools.Configured() {
		t.Skip("HIVE_YARA / HIVE_YARAC are not set")
	}
	d := t.TempDir()
	srcRepo, _ := gitx.Init(filepath.Join(d, "rules-src"))
	put(t, srcRepo.Dir, map[string]string{
		"docscan-index.yar": "include \"file-index.yar\"\n",
		"file-index.yar":    "include \"general/a.yar\"\n",
		"general/a.yar":     "rule Vendor_A { strings: $a = \"vendor-a\" condition: $a }\n",
	})
	srcRepo.CommitAll("rules", "")
	crit := filepath.Join(d, "docscan-critical")
	put(t, crit, map[string]string{
		"critical/zsu.yar":        "rule crit_markings {\n meta:\n  category = \"classified\"\n strings:\n  $m = /службов[^ ]{0,12} користуванн/\n condition:\n  $m\n}\n",
		"tests/match/doc1.txt":    "Для службового користування",
		"tests/no-match/doc2.txt": "звичайний лист",
	})
	put(t, d, map[string]string{"whitelist.json": `{"schema":1,"entries":[{"sha256":"` + strings.Repeat("1", 64) + `","comment":"own app"}]}`})
	a, err := Open(filepath.Join(d, "data"), tools)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := a.CreateWS(workspace.Config{Name: "org", Visibility: "private", VersionFloor: "v1.0.0"}, "tester")
	_, seed, _ := a.NewKey(w, "rules", "env:HIVE_TEST_ED_RULES", "tester")
	t.Setenv("HIVE_TEST_ED_RULES", seed)
	_, lseed, _ := a.NewKey(w, "lists", "env:HIVE_TEST_ED_LISTS", "tester")
	t.Setenv("HIVE_TEST_ED_LISTS", lseed)
	if err := a.AddSource(w, workspace.Source{ID: "docscan-rules", URL: srcRepo.Dir, Ref: "main"}, "tester"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.ImportCritical(w, crit, "tester"); err != nil {
		t.Fatal(err)
	}
	a.ImportList(w, "white", filepath.Join(d, "whitelist.json"), "tester")
	if _, saved, err := a.SaveOwnRule(w, "org", "inc.yar", "rule ORG_Inc { strings: $a = \"inc-marker\" condition: $a }\n", "tester"); !saved || err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(d, "Anthophila_Pollen.git")
	if out, err := exec.Command("git", "init", "-q", "--bare", bare).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := a.SaveTarget(w, workspace.Target{ID: "pollen", Kind: "editions-branch", Repo: bare, Branch: "main", Public: true,
		Editions: []string{"nope"}}, "tester"); err == nil {
		t.Fatal("unknown edition accepted")
	}
	if err := a.SaveTarget(w, workspace.Target{ID: "pollen", Kind: "editions-branch", Repo: bare, Branch: "main", Public: true}, "tester"); err != nil {
		t.Fatal(err)
	}

	br, err := a.Build(w, "patch", true, "tester")
	if err != nil {
		t.Fatal(err)
	}
	rel, _ := a.DB.Release("org", br.Version)
	if rel.Result != "PASS" {
		t.Fatalf("build %s: %s %s", br.Version, rel.Result, rel.Report)
	}
	eds := a.ReleaseEditions(rel)
	if len(eds) != 6 {
		t.Fatalf("editions: %d", len(eds))
	}
	dirs := map[string]bool{}
	for _, e := range eds {
		if e.Rules {
			dirs[e.Dir] = true
		}
		switch e.ID {
		case "full":
			if e.Dir != rel.Dir || e.CritFiles != 1 || e.OwnFiles != 1 {
				t.Fatalf("full: %+v", e)
			}
		case "vendor":
			if e.CritFiles != 0 || e.OwnFiles != 0 || e.Result != "PASS" {
				t.Fatalf("vendor: %+v", e)
			}
		case "lists":
			if e.Dir != "" {
				t.Fatalf("lists: %+v", e)
			}
		}
	}
	if len(dirs) != 3 { // rules+own+critical (основний), rules+own, rules
		t.Fatalf("packages built: %d", len(dirs))
	}
	// публічна ціль, приватний простір: без підтвердження — ні (і через звичайний Publish теж)
	if _, err := a.Publish(w, br.Version, "pollen", "tester", nil); err == nil || !strings.Contains(err.Error(), "explicit confirmation") {
		t.Fatalf("public without ack: %v", err)
	}
	plan, err := a.PlanEditions(w, rel, "pollen")
	if err != nil || !plan.NeedsAck || len(plan.Sensitive["full"]) != 4 || plan.Sensitive["vendor"] != nil {
		t.Fatalf("plan %+v %v", plan, err)
	}
	if _, err := a.PublishEditions(w, br.Version, "pollen", "tester", true, nil); err != nil {
		t.Fatal(err)
	}
	show := func(p string) string {
		b, _ := exec.Command("git", "--git-dir", bare, "show", "main:"+p).Output()
		return string(b)
	}
	for id, want := range map[string][2]bool{"full": {true, true}, "nocrit": {true, false}, "vendor": {false, false}} {
		var m manifest.Manifest
		if err := json.Unmarshal([]byte(show(id+"/rules-manifest.json")), &m); err != nil || m.Version != br.Version {
			t.Fatalf("%s manifest: %v %s", id, err, m.Version)
		}
		_, hasOwn := m.Files["org/inc.yar"]
		_, hasCrit := m.Files["critical/zsu.yar"]
		if hasOwn != want[0] || hasCrit != want[1] {
			t.Fatalf("%s: own %v critical %v", id, hasOwn, hasCrit)
		}
	}
	if show("full-black/whitelist.json") != "" || show("full-black/blacklist.json") == "" || show("lists/rules-manifest.json") != "" {
		t.Fatal("lists in editions")
	}
	if !strings.Contains(show("README.md"), "| [Повна](full/)") {
		t.Fatalf("README:\n%s", show("README.md"))
	}
	// наступна версія — більша за ту, що в гілці
	if next, _, err := a.NextVersion(w, "patch", true); err != nil || manifest.Compare(next, br.Version) <= 0 {
		t.Fatalf("next %s %v", next, err)
	}
	// редакцію, яку ціль публікує, з набору не прибрати, поки ціль її називає
	a.SaveTarget(w, workspace.Target{ID: "pollen", Kind: "editions-branch", Repo: bare, Branch: "main", Public: true, Editions: []string{"vendor"}}, "tester")
	if err := a.SaveEditions(w, []workspace.Edition{{ID: "full", Title: "Повна", Rules: true, Own: true, Critical: true}}, "tester"); err == nil {
		t.Fatal("edition used by a target removed")
	}
}
