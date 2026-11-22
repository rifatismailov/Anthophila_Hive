package publish

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
)

// fakeForgejo — /api/v1/repos/o/r/releases (+ assets) і /o/r/releases/download/<tag>/<file>.
func fakeForgejo(t *testing.T, token string) *httptest.Server {
	var mu sync.Mutex
	type rel struct {
		ID     int64  `json:"id"`
		Tag    string `json:"tag_name"`
		Target string `json:"target_commitish"`
	}
	var rels []rel
	files := map[string][]byte{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("Authorization") != "token "+token {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/repos/o/r/releases":
			json.NewEncoder(w).Encode(rels)
		case r.Method == "POST" && r.URL.Path == "/api/v1/repos/o/r/releases":
			var x rel
			json.NewDecoder(r.Body).Decode(&x)
			x.ID = int64(len(rels) + 1)
			rels = append(rels, x)
			json.NewEncoder(w).Encode(x)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/assets"):
			var id int64
			fmt.Sscanf(r.URL.Path, "/api/v1/repos/o/r/releases/%d/assets", &id)
			f, _, err := r.FormFile("attachment")
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			b, _ := io.ReadAll(f)
			files[rels[id-1].Tag+"/"+r.URL.Query().Get("name")] = b
			w.Write([]byte("{}"))
		case strings.HasPrefix(r.URL.Path, "/o/r/releases/download/"):
			b, ok := files[strings.TrimPrefix(r.URL.Path, "/o/r/releases/download/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
}

func treeOf(t *testing.T) map[string][]byte {
	return map[string][]byte{"docscan-index.yar": []byte("include \"general/a.yar\"\n"), "general/a.yar": []byte("rule A { condition: false }\n"),
		"critical/secret.yar": []byte("rule ORG_Internal_Project { condition: false }\n"), "VERSION.txt": []byte("x")}
}

func TestReleaseForgejo(t *testing.T) {
	seed, pub, _ := manifest.NewSeed()
	ts := fakeForgejo(t, "push-token")
	defer ts.Close()
	// репозиторій правил, куди комітиться дерево
	d := t.TempDir()
	bare := filepath.Join(d, "rules.git")
	(&gitx.Repo{}).Run("init", "-q", "--bare", "-b", "main", bare)
	seedRepo, _ := gitx.Init(filepath.Join(d, "seed"))
	os.WriteFile(filepath.Join(seedRepo.Dir, "README.md"), []byte("rules\n"), 0o644)
	os.MkdirAll(filepath.Join(seedRepo.Dir, "tools"), 0o755)
	os.WriteFile(filepath.Join(seedRepo.Dir, "tools", "build.py"), []byte("# generator\n"), 0o644)
	os.WriteFile(filepath.Join(seedRepo.Dir, "old.yar"), []byte("rule Old { condition: false }\n"), 0o644)
	seedRepo.CommitAll("init", "")
	seedRepo.Run("push", "-q", bare, "main")

	ws := workspace.Config{Name: "anthophila", Visibility: "public"}
	tg := workspace.Target{ID: "fj", Kind: "release", Forge: "forgejo", API: ts.URL, Project: "o/r", Repo: bare, Branch: "main", CommitTree: true, Public: true}
	e := env(t, pub)
	e.Auth = &gitx.Auth{Token: "push-token"}
	in := ReleaseInput{Dir: release(t, seed, pub, "v1.0.1"), Version: "v1.0.1", Tree: treeOf(t), Report: []byte("# report\n"), Source: "test"}
	res, err := Release(ws, tg, in, e)
	if err != nil || failed(res.Report) {
		if res != nil && res.Report != nil {
			for _, c := range res.Report.Checks {
				t.Logf("%s %s %s", c.Status, c.ID, c.Detail)
			}
		}
		t.Fatalf("release: %v", err)
	}
	r := &gitx.Repo{Dir: bare, Bare: true}
	ls, _ := r.Line("ls-tree", "-r", "--name-only", "main")
	for _, want := range []string{"README.md", "docscan-index.yar", "general/a.yar", "tools/build.py", "tools/vendor-report.md"} {
		if !strings.Contains(ls, want) {
			t.Errorf("rules repo has no %s:\n%s", want, ls)
		}
	}
	for _, bad := range []string{"critical/", "VERSION.txt", "old.yar"} {
		if strings.Contains(ls, bad) {
			t.Errorf("rules repo has %s:\n%s", bad, ls)
		}
	}
	if n, _ := r.Line("rev-list", "--count", "main"); n != "2" {
		t.Errorf("history: %s commits (fast-forward expected)", n)
	}
	// той самий і старіший — ні
	if _, err := Release(ws, tg, in, e); err == nil || !strings.Contains(err.Error(), "never overwritten") {
		t.Fatalf("same release: %v", err)
	}
	in.Version = "v1.0.0"
	if _, err := Release(ws, tg, in, e); err == nil || !strings.Contains(err.Error(), "never be installed") {
		t.Fatalf("older release: %v", err)
	}
	// приватний простір — не в публічну ціль
	if _, err := Release(workspace.Config{Name: "org", Visibility: "private"}, tg, in, e); err == nil {
		t.Fatal("private workspace to a public release")
	}
	// без токена API відмовляє
	e.Auth = nil
	tg.CommitTree = false
	in.Version = "v1.0.2"
	if _, err := Release(ws, tg, in, e); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("no token: %v", err)
	}
}

func TestReleaseGitHubFakeGh(t *testing.T) {
	seed, pub, _ := manifest.NewSeed()
	d := t.TempDir()
	state := filepath.Join(d, "state")
	os.MkdirAll(filepath.Join(state, "download"), 0o755)
	bin := filepath.Join(d, "bin")
	os.MkdirAll(bin, 0o755)
	// фейковий gh: api → список релізів; release create → файли в state/download/<tag>/
	gh := `#!/bin/sh
S="` + state + `"
case "$1" in
  api)
    printf '['; first=1
    for f in "$S"/tags/*; do [ -e "$f" ] || continue; [ $first = 1 ] || printf ','; first=0
      printf '{"tag_name":"%s","target_commitish":"%s"}' "$(basename "$f")" "$(cat "$f")"; done
    printf ']\n' ;;
  release)
    tag="$3"; shift 3; mkdir -p "$S/tags" "$S/download/$tag"
    while [ $# -gt 0 ]; do case "$1" in --repo|--target|--title|--notes) [ "$1" = --target ] && echo "$2" > "$S/tags/$tag"; shift 2 ;; *) cp "$1" "$S/download/$tag/"; shift ;; esac; done
    [ -n "$GH_TOKEN" ] && echo "$GH_TOKEN" > "$S/token" ;;
esac
`
	os.WriteFile(filepath.Join(bin, "gh"), []byte(gh), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	files := httptest.NewServer(http.FileServer(http.Dir(filepath.Join(state, "download"))))
	defer files.Close()
	ws := workspace.Config{Name: "anthophila", Visibility: "public"}
	tg := workspace.Target{ID: "gh", Kind: "release", Forge: "github", Project: "rifatismailov/yara-docscan-rules", Branch: "main", Public: true, DownloadURL: files.URL}
	e := env(t, pub)
	e.Auth = &gitx.Auth{Token: "gh-token"}
	res, err := Release(ws, tg, ReleaseInput{Dir: release(t, seed, pub, "v1.0.1"), Version: "v1.0.1", Source: "test"}, e)
	if err != nil || failed(res.Report) {
		t.Fatalf("%v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "token")); strings.TrimSpace(string(b)) != "gh-token" {
		t.Fatal("GH_TOKEN not passed")
	}
	if _, err := Release(ws, tg, ReleaseInput{Dir: release(t, seed, pub, "v1.0.1"), Version: "v1.0.1"}, e); err == nil {
		t.Fatal("same tag accepted")
	}
}
