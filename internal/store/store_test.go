package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "hive.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	rules := []Rule{
		{File: "general/a.yar", Name: "APT_A", Kind: "detection", Tags: []string{"apt"}, Meta: map[string]string{"author": "x"}, Line: 3},
		{File: "general/b.yar", Name: "Crime_B", Kind: "detection", Line: 1},
	}
	if err := d.ReplaceRules("ws", "src", rules); err != nil {
		t.Fatal(err)
	}
	if err := d.ReplaceRules("ws", "src", rules[:1]); err != nil {
		t.Fatal(err)
	}
	got, total, err := d.FindRules(RuleQuery{WS: "ws", Text: "apt"})
	if err != nil || total != 1 || got[0].Name != "APT_A" || got[0].Meta["author"] != "x" {
		t.Fatalf("%+v %d %v", got, total, err)
	}
	r := Release{WS: "ws", Version: "v1.0.1", Status: "built", Created: time.Now(), Result: "PASS"}
	if err := d.PutRelease(r); err != nil {
		t.Fatal(err)
	}
	r.Status = "published"
	d.PutRelease(r)
	r.Status = "built"
	if err := d.PutRelease(r); err == nil {
		t.Fatal("published release overwritten by a candidate")
	}
	d.Audit("ws", "me", "publish", "v1.0.1 -> mirror")
	if a, _ := d.AuditLog("ws", 5); len(a) != 1 || a[0].Action != "publish" {
		t.Fatalf("audit %+v", a)
	}
}
