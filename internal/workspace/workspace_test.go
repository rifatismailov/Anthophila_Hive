package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateOpenDecisions(t *testing.T) {
	d := filepath.Join(t.TempDir(), "org-example")
	w, err := Create(d, Config{Name: "org-example", Visibility: "private", VersionFloor: "v1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(d, Config{Name: "org-example", Visibility: "private"}); err == nil {
		t.Fatal("second create accepted")
	}
	if err := w.SetDecision(Decision{Source: "s", File: "general/a.yar", Rule: "A", Status: "drop"}); err == nil {
		t.Fatal("drop without a reason accepted")
	}
	if err := w.SetDecision(Decision{Source: "s", File: "general/a.yar", Rule: "A", Status: "drop", Reason: "FP", By: "me"}); err != nil {
		t.Fatal(err)
	}
	w.SetDecision(Decision{Source: "s", File: "general/a.yar", Rule: "B", Status: "drop", Reason: "slow"})
	w.SetDecision(Decision{Source: "s", File: "general/a.yar", Rule: "A"}) // прибрати
	ds, _ := w.Decisions()
	if len(ds) != 1 || ds[0].Rule != "B" {
		t.Fatalf("decisions %+v", ds)
	}
	if _, err := w.Commit("decisions", "tester"); err != nil {
		t.Fatal(err)
	}
	w2, err := Open(d)
	if err != nil || w2.Cfg.VersionFloor != "v1.0.0" {
		t.Fatalf("%+v %v", w2, err)
	}
	log, _ := w.Repo.Line("log", "-1", "--format=%an %s")
	if log != "tester decisions" {
		t.Fatalf("log %q", log)
	}
}

func TestRefusesBinaries(t *testing.T) {
	d := filepath.Join(t.TempDir(), "ws")
	w, err := Create(d, Config{Name: "ws", Visibility: "public"})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "critical", "sample.yar"), []byte("MZ\x90\x00 not a rule"), 0o644)
	if _, err := w.Commit("oops", ""); err == nil || !strings.Contains(err.Error(), "sample.yar") {
		t.Fatalf("binary committed: %v", err)
	}
	os.Remove(filepath.Join(d, "critical", "sample.yar"))
	os.WriteFile(filepath.Join(d, "critical", "zsu.yar"), []byte("rule crit { strings: $a = \"службов\" condition: $a }\r\n"), 0o644)
	if _, err := w.Commit("rule", ""); err != nil {
		t.Fatal(err)
	}
	if got := w.OwnFiles("critical"); len(got) != 1 || got[0] != "zsu.yar" {
		t.Fatalf("own files %v", got)
	}
}
