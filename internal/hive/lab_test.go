package hive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/lab"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func TestLabAndDupesFlow(t *testing.T) {
	tools := yaraexec.FromEnv()
	if !tools.Configured() {
		t.Skip("HIVE_YARA / HIVE_YARAC are not set")
	}
	d := t.TempDir()
	src, _ := gitx.Init(filepath.Join(d, "src"))
	put(t, src.Dir, map[string]string{
		"docscan-index.yar":  "include \"docscan-policy.yar\"\ninclude \"file-index.yar\"\n",
		"docscan-policy.yar": "import \"docscan\"\nrule DS_P { meta: severity = \"HIGH\" condition: false }\n",
		"file-index.yar":     "include \"general/a.yar\"\ninclude \"general/forge.yar\"\n",
		"general/a.yar":      "rule Mal_A { strings: $a = \"evil-a\" condition: $a }\nrule Uses_A { condition: Mal_A }\n",
		"general/forge.yar":  "rule FORGE_Mal_A {\n strings:\n  $x = \"evil-a\"\n condition:\n  $x\n}\n",
	})
	src.CommitAll("rules", "")
	clean, mal := filepath.Join(d, "sets", "clean"), filepath.Join(d, "sets", "mal")
	put(t, clean, map[string]string{"invoice.txt": "invoice for March", "letter.txt": "hello"})
	put(t, mal, map[string]string{"s1.bin": "x evil-a x"})

	a, err := Open(filepath.Join(d, "data"), tools)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := a.CreateWS(workspace.Config{Name: "org", Visibility: "private", VersionFloor: "v1.0.0"}, "t")
	_, seed, _ := a.NewKey(w, "rules", "env:HIVE_LAB_TEST_KEY", "t")
	t.Setenv("HIVE_LAB_TEST_KEY", seed)
	if err := a.AddSource(w, workspace.Source{ID: "docscan-rules", URL: src.Dir, Ref: "main"}, "t"); err != nil {
		t.Fatal(err)
	}
	// дублікати: FORGE_Mal_A = Mal_A (L1)
	groups, err := a.Dupes(w)
	if err != nil || len(groups) != 1 || groups[0].Level != "L1" {
		t.Fatalf("dupes %+v %v", groups, err)
	}
	// лишити копію замість Mal_A не можна: на Mal_A посилається Uses_A
	if n, skipped, _ := a.KeepOne(w, "L1", groups[0].Key, "docscan-rules|general/forge.yar|FORGE_Mal_A", "t"); n != 0 || len(skipped) != 1 {
		t.Fatalf("keep forge: %d %v", n, skipped)
	}
	// відкинути копію з forge.yar; Mal_A лишається
	if n, skipped, err := a.DropDupesIn(w, "forge.yar", "t"); err != nil || n != 1 {
		t.Fatalf("drop dupes: %d %v %v", n, skipped, err)
	}

	if _, err := a.AddLabSet("clean", "clean", clean, false, false, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddLabSet("mal", "malware", mal, true, false, "t"); err != nil {
		t.Fatal(err)
	}
	// ШПЗ з git-репозиторію — ні
	put(t, filepath.Join(src.Dir, "samples"), map[string]string{"x.bin": "x"})
	if _, err := a.AddLabSet("bad", "malware", filepath.Join(src.Dir, "samples"), false, false, "t"); err == nil || !strings.Contains(err.Error(), "git") {
		t.Fatalf("malware set inside git accepted: %v", err)
	}
	if err := a.SetLabConfig(w, workspace.Lab{Sets: []string{"clean", "mal"}}, "t"); err != nil {
		t.Fatal(err)
	}
	w.Cfg.Targets = []workspace.Target{{ID: "share", Kind: "folder", Path: filepath.Join(d, "share")}}
	w.SaveConfig()
	w.Commit("target", "t")

	b1, err := a.Build(w, "patch", false, "t")
	if err != nil || !b1.OK() {
		t.Fatalf("build 1: %v", err)
	}
	if _, err := a.Publish(w, "v1.0.1", "share", "t", nil); err == nil || !strings.Contains(err.Error(), "no lab run") {
		t.Fatalf("published without the lab: %v", err)
	}
	lr, err := a.RunLab(w, "v1.0.1", "", "", "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if lr.Report.Result == lab.Red || lr.Run.Baseline != "none" {
		t.Fatalf("first run %s vs %s", lr.Report.Result, lr.Run.Baseline)
	}
	if _, err := a.Publish(w, "v1.0.1", "share", "t", nil); err != nil {
		t.Fatal(err)
	}

	// нове правило з хибним спрацюванням на чистому документі
	if fs, ok, err := a.SaveOwnRule(w, "org", "fp.yar", "rule ORG_Too_Broad { strings: $a = \"invoice\" condition: $a }\n", "t"); !ok || err != nil {
		t.Fatalf("%+v %v", fs, err)
	}
	b2, err := a.Build(w, "patch", true, "t")
	if err != nil || b2.Version != "v1.0.2" {
		t.Fatalf("build 2: %v", err)
	}
	lr, err = a.RunLab(w, "v1.0.2", "", "", "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if lr.Run.Baseline != "v1.0.1" || lr.Report.Result != lab.Red {
		t.Fatalf("second run %s vs %s", lr.Report.Result, lr.Run.Baseline)
	}
	if _, err := a.Publish(w, "v1.0.2", "share", "t", nil); err == nil || !strings.Contains(err.Error(), "red") {
		t.Fatalf("red lab published: %v", err)
	}
	var key string
	for _, g := range lr.Report.Gates {
		if g.ID == "G2" {
			key = g.Items[0].Key
		}
	}
	if _, err := a.Accept(w, lr.Run.ID, key, "", "t"); err == nil {
		t.Fatal("accepted without a reason")
	}
	lr2, err := a.Accept(w, lr.Run.ID, key, "invoices are not malware, but we want this rule", "t")
	if err != nil || lr2.Report.Result == lab.Red {
		t.Fatalf("accept: %v %s", err, lr2.Report.Result)
	}
	if _, err := a.Publish(w, "v1.0.2", "share", "t", nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(w.Dir, "lab", "accepted.yaml")); !strings.Contains(string(b), "ORG_Too_Broad") {
		t.Fatal("accepted.yaml")
	}
	again, _ := a.LabReport(w, lr.Run.ID)
	if again.Report.Result != lr2.Report.Result {
		t.Fatal("report not saved")
	}
}
