package publish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/build"
	"github.com/rifatismailov/Anthophila_Hive/internal/contract"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/orglists"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/lists"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func release(t *testing.T, seed, pub, version string) string {
	t.Helper()
	src := t.TempDir()
	for n, s := range map[string]string{
		"docscan-index.yar": "include \"general/a.yar\"\n", "general/a.yar": "rule A { condition: false }\n",
	} {
		p := filepath.Join(src, n)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(s), 0o644)
	}
	out := t.TempDir()
	_, err := build.Build(build.Input{SourceTree: src, SourceID: "s", SourceCommit: "1111111111", WSTree: t.TempDir(), WSCommit: "2222222222"},
		build.Options{Version: version, Created: time.Now(), Seed: seed, PublicKey: pub, OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func env(t *testing.T, pub string) Env {
	v := contract.Options{Keys: []string{pub}}
	if tl := yaraexec.FromEnv(); tl.Configured() {
		v.Compiler = tl
	}
	return Env{WorkDir: t.TempDir(), Verify: v}
}

func failed(r *contract.Report) bool { return r == nil || r.Result() == "FAIL" }

func TestRulesFolder(t *testing.T) {
	seed, pub, _ := manifest.NewSeed()
	ws := workspace.Config{Name: "org", Visibility: "private"}
	tg := workspace.Target{ID: "share", Kind: "folder", Path: filepath.Join(t.TempDir(), "share")}
	e := env(t, pub)
	res, err := Rules(ws, tg, release(t, seed, pub, "v1.0.1"), "v1.0.1", e)
	if err != nil || failed(res.Report) {
		t.Fatalf("%v %+v", err, res)
	}
	if v, _ := CurrentRulesVersion(tg, e); v != "v1.0.1" {
		t.Fatalf("current %q", v)
	}
	if _, err := Rules(ws, tg, release(t, seed, pub, "v1.0.1"), "v1.0.1", e); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("same version accepted: %v", err)
	}
	if _, err := Rules(ws, tg, release(t, seed, pub, "v1.0.2"), "v1.0.2", e); err != nil {
		t.Fatal(err)
	}
}

func TestRulesMirrorBranch(t *testing.T) {
	seed, pub, _ := manifest.NewSeed()
	bare := filepath.Join(t.TempDir(), "mirror.git")
	(&gitx.Repo{}).Run("init", "-q", "--bare", bare)
	ws := workspace.Config{Name: "org", Visibility: "private"}
	tg := workspace.Target{ID: "mirror", Kind: "mirror-branch", Repo: bare, Branch: "docscan-rules"}
	e := env(t, pub)
	if _, err := Rules(ws, tg, release(t, seed, pub, "v1.0.1"), "v1.0.1", e); err == nil || !strings.Contains(err.Error(), "rules.mirror.token") {
		t.Fatalf("closed branch without token support on PCs accepted: %v", err)
	}
	tg.PCsTokenSupported = true
	for _, v := range []string{"v1.0.1", "v1.0.2"} {
		res, err := Rules(ws, tg, release(t, seed, pub, v), v, e)
		if err != nil || failed(res.Report) {
			t.Fatalf("%s: %v", v, err)
		}
	}
	r := &gitx.Repo{Dir: bare, Bare: true}
	if n, _ := r.Line("rev-list", "--count", "docscan-rules"); n != "1" {
		t.Fatalf("branch keeps %s commits", n)
	}
	if ls, _ := r.Line("ls-tree", "--name-only", "docscan-rules"); ls != "DocScan-rules.zip\nrules-manifest.json\nrules-manifest.sig" {
		t.Fatalf("branch files:\n%s", ls)
	}
	// публічна ціль з приватного простору — ні
	if err := CheckRulesTarget(ws, workspace.Target{ID: "pub", Kind: "folder", Public: true}); err == nil {
		t.Fatal("private workspace to a public target accepted")
	}
	if err := CheckRulesTarget(ws, workspace.Target{ID: "x", Kind: "folder", PCsURL: "https://reader:tok@h/x"}); err == nil {
		t.Fatal("token in pcs_url accepted")
	}
}

func TestLists(t *testing.T) {
	seed, pub, _ := manifest.NewSeed()
	ws := workspace.Config{Name: "org", Visibility: "private"}
	sign := func(prev map[string]int64) []*lists.Signed {
		var out []*lists.Signed
		for _, k := range lists.Kinds {
			l := &orglists.List{Schema: 1, Entries: []orglists.Entry{{SHA256: strings.Repeat("a", 64), Comment: "x"}}}
			s, err := lists.Sign(l, k.Kind, seed, pub, prev[k.Kind], time.Now())
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return out
	}
	bare := filepath.Join(t.TempDir(), "lists.git")
	(&gitx.Repo{}).Run("init", "-q", "--bare", bare)
	for _, tg := range []workspace.Target{
		{ID: "lf", Kind: "lists-folder", Path: filepath.Join(t.TempDir(), "lists")},
		{ID: "lb", Kind: "lists-branch", Repo: bare, Branch: "docscan-lists"},
	} {
		e := env(t, pub)
		s1 := sign(nil)
		if _, err := Lists(ws, tg, s1, []string{pub}, e); err != nil {
			t.Fatalf("%s: %v", tg.ID, err)
		}
		cur, _ := CurrentSerials(tg, e)
		if cur["white"] != s1[0].Serial {
			t.Fatalf("%s: serials %v", tg.ID, cur)
		}
		if _, err := Lists(ws, tg, s1, []string{pub}, e); err == nil {
			t.Fatalf("%s: same serial republished", tg.ID)
		}
		if _, err := Lists(ws, tg, sign(cur), []string{pub}, e); err != nil {
			t.Fatalf("%s: %v", tg.ID, err)
		}
	}
}
