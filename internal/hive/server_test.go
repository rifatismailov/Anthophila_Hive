package hive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func TestKeystoreAndFourEyes(t *testing.T) {
	tools := yaraexec.FromEnv()
	if !tools.Configured() {
		t.Skip("HIVE_YARA / HIVE_YARAC are not set")
	}
	d := t.TempDir()
	src, _ := gitx.Init(filepath.Join(d, "src"))
	put(t, src.Dir, map[string]string{"docscan-index.yar": "include \"general/a.yar\"\n", "general/a.yar": "rule A { condition: false }\n"})
	src.CommitAll("rules", "")
	a, err := Open(filepath.Join(d, "data"), tools)
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("the keystore passphrase")
	if err := a.Keys.Init(pass); err != nil {
		t.Fatal(err)
	}
	a.Unlock = func(string) ([]byte, error) { return append([]byte(nil), pass...), nil }
	w, _ := a.CreateWS(workspace.Config{Name: "pub", Visibility: "public", FourEyes: true}, "admin")
	pub, seedOnce, err := a.NewKey(w, "rules", "hive:pub-rules", "admin")
	if err != nil || seedOnce != "" || pub == "" {
		t.Fatalf("key: %v (seed shown: %v)", err, seedOnce != "")
	}
	if l := a.Keys.List(); len(l) != 1 || l[0].Public != pub {
		t.Fatalf("keystore %+v", l)
	}
	a.AddSource(w, workspace.Source{ID: "rules", URL: src.Dir, Ref: "main"}, "admin")
	w.Cfg.Targets = []workspace.Target{{ID: "share", Kind: "folder", Path: filepath.Join(d, "share")},
		{ID: "public", Kind: "folder", Path: filepath.Join(d, "public"), Public: true}}
	w.SaveConfig()
	w.Commit("targets", "admin")

	// без пароля сховища — не підписати
	a.Unlock = nil
	if _, err := a.Build(w, "patch", false, "alice"); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("built without the passphrase: %v", err)
	}
	a.Unlock = func(string) ([]byte, error) { return []byte("wrong passphrase!!!"), nil }
	if _, err := a.Build(w, "patch", false, "alice"); err == nil {
		t.Fatal("built with a wrong passphrase")
	}
	a.Unlock = func(string) ([]byte, error) { return append([]byte(nil), pass...), nil }
	b, err := a.Build(w, "patch", false, "alice")
	if err != nil || !b.OK() {
		t.Fatalf("build: %v", err)
	}
	if _, err := a.Publish(w, b.Version, "share", "alice", nil); err == nil || !strings.Contains(err.Error(), "four eyes") {
		t.Fatalf("builder published: %v", err)
	}
	if _, err := a.Publish(w, b.Version, "public", "carol", nil); err == nil || !strings.Contains(err.Error(), "approve") {
		t.Fatalf("public without approval: %v", err)
	}
	if err := a.Approve(w, b.Version, "alice", "mine"); err == nil {
		t.Fatal("builder approved")
	}
	if err := a.Approve(w, b.Version, "bob", "checked the lab report"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Publish(w, b.Version, "public", "carol", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Publish(w, b.Version, "share", "carol", nil); err != nil {
		t.Fatal(err)
	}
}

func TestBackupRestore(t *testing.T) {
	d := t.TempDir()
	a, err := Open(filepath.Join(d, "data"), yaraexec.Tools{})
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("the keystore passphrase")
	a.Keys.Init(pass)
	a.Unlock = func(string) ([]byte, error) { return append([]byte(nil), pass...), nil }
	w, _ := a.CreateWS(workspace.Config{Name: "org", Visibility: "private"}, "admin")
	pub, _, err := a.NewKey(w, "rules", "hive:org-rules", "admin")
	if err != nil {
		t.Fatal(err)
	}
	a.Auth.Add("admin", 5, "the admin password")
	out := filepath.Join(d, "backup.tar.gz")
	n, err := a.Backup(out, true, false)
	if err != nil || n == 0 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := a.Backup(out, true, false); err == nil {
		t.Fatal("backup overwrote an existing file")
	}
	b, _ := os.ReadFile(out)
	seed, _ := a.Keys.Open("org-rules", pass)
	if strings.Contains(string(b), string(seed)) {
		t.Fatal("plain key in the backup")
	}
	nd := filepath.Join(d, "restored")
	if _, err := Restore(out, nd); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(out, nd); err == nil {
		t.Fatal("restore into a non-empty folder")
	}
	b2, err := Open(nd, yaraexec.Tools{})
	if err != nil {
		t.Fatal(err)
	}
	w2, err := b2.WS("org")
	if err != nil || w2.Cfg.RulesKey.Public != pub {
		t.Fatalf("workspace: %v", err)
	}
	if v, err := b2.Keys.Open("org-rules", pass); err != nil || string(v) != string(seed) {
		t.Fatalf("key after restore: %v", err)
	}
	if b2.Auth.Count() != 1 {
		t.Fatal("users lost")
	}
}
