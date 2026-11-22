package gitx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCommitMirrorExtract(t *testing.T) {
	d := t.TempDir()
	src, err := Init(filepath.Join(d, "src"))
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(src.Dir, "general"), 0o755)
	crlf := "rule A {\r\n condition: true\r\n}\r\n"
	os.WriteFile(filepath.Join(src.Dir, "general", "a.yar"), []byte(crlf), 0o644)
	c1, err := src.CommitAll("first", "")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := src.CommitAll("nothing", ""); again != c1 {
		t.Fatalf("empty commit created")
	}
	m, err := Mirror(src.Dir, filepath.Join(d, "cache", "src.git"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Resolve("main")
	if err != nil || got != c1 {
		t.Fatalf("resolve main: %q %v", got, err)
	}
	out := filepath.Join(d, "out")
	if err := m.Extract(c1, out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(out, "general", "a.yar"))
	if string(b) != crlf {
		t.Fatalf("not byte for byte: %q", b)
	}
	if s, _ := m.Show(c1, "general/a.yar"); string(s) != crlf {
		t.Fatalf("show: %q", s)
	}
	if s, err := m.Show(c1, "nope"); s != nil || err != nil {
		t.Fatalf("missing file: %q %v", s, err)
	}
}

func TestOrphanForcePush(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target.git")
	if _, err := (&Repo{}).Run("init", "-q", "--bare", target); err != nil {
		t.Fatal(err)
	}
	work := &Repo{Dir: filepath.Join(d, "work.git"), Bare: true}
	(&Repo{}).Run("init", "-q", "--bare", work.Dir)
	push := func(v, expected string) (string, error) {
		c, err := work.OrphanCommit(map[string][]byte{"rules-manifest.json": []byte(v), "DocScan-rules.zip": []byte("zip " + v)}, "rules "+v)
		if err != nil {
			t.Fatal(err)
		}
		return c, work.ForcePushBranch(target, c, "docscan-rules", expected)
	}
	c1, err := push("v1", "")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := push("v2", c1)
	if err != nil {
		t.Fatal(err)
	}
	head, _ := work.RemoteHead(target, "docscan-rules")
	if head != c2 {
		t.Fatalf("head %s, want %s", head, c2)
	}
	// у гілці лише один коміт — без історії архівів
	tr := &Repo{Dir: target, Bare: true}
	if n, _ := tr.Line("rev-list", "--count", "docscan-rules"); n != "1" {
		t.Fatalf("branch has %s commits", n)
	}
	// хтось опублікував між читанням і записом — lease не дасть затерти
	if _, err := push("v3", c1); err == nil {
		t.Fatal("stale lease accepted")
	}
	got, _ := work.FetchBranch(target, "docscan-rules")
	if b, _ := work.Show(got, "rules-manifest.json"); string(b) != "v2" {
		t.Fatalf("fetched %q", b)
	}
}

func TestTokenNotInErrors(t *testing.T) {
	r := &Repo{Auth: &Auth{Token: "s3cr3t-token"}}
	_, err := r.Run("ls-remote", "https://s3cr3t-token@127.0.0.1:1/x.git")
	if err == nil {
		t.Skip("unexpected success")
	}
	if strings.Contains(err.Error(), "s3cr3t-token") {
		t.Fatalf("token in the error: %v", err)
	}
}
