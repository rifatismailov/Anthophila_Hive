package publish

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/contract"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
)

// Реліз на GitHub / Forgejo (ціль kind "release", як нині yara-docscan-rules):
//   - commit_tree: дерево правил (пакет без critical/ і VERSION.txt + tools/vendor-report.md) — звичайним комітом
//     у гілку репозиторію правил (fast-forward, історія зберігається; критичні правила ніколи не йдуть у дерево);
//   - тег vX.Y.Z на цей коміт (або на голову гілки), реліз з чотирма файлами;
//   - перевірка: пакет завантажується за адресою релізу і проходить контракт DocScan.

// Forge — сервіс релізів.
type Forge interface {
	Tags() (map[string]string, error) // тег -> коміт
	Create(tag, commit, title, notes string, assets []string) error
	DownloadBase(tag string) string
}

// ghForge — GitHub через gh (токен — GH_TOKEN лише для дочірнього процесу).
type ghForge struct {
	project, token, base string
}

func (g ghForge) gh(args ...string) ([]byte, error) {
	cmd := exec.Command("gh", args...)
	cmd.Env = os.Environ()
	if g.token != "" {
		cmd.Env = append(cmd.Env, "GH_TOKEN="+g.token)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := errb.String()
		if g.token != "" {
			msg = strings.ReplaceAll(msg, g.token, "***")
		}
		return nil, fmt.Errorf("gh %s: %s", args[0], strings.TrimSpace(msg))
	}
	return out.Bytes(), nil
}

func (g ghForge) Tags() (map[string]string, error) {
	out, err := g.gh("api", "--paginate", "repos/"+g.project+"/releases?per_page=100")
	if err != nil {
		return nil, err
	}
	s := strings.ReplaceAll(strings.TrimSpace(string(out)), "]\n[", ",")
	s = strings.ReplaceAll(s, "][", ",")
	var rs []struct {
		Tag    string `json:"tag_name"`
		Target string `json:"target_commitish"`
	}
	if err := json.Unmarshal([]byte(s), &rs); err != nil {
		return nil, fmt.Errorf("gh api releases: %w", err)
	}
	m := map[string]string{}
	for _, r := range rs {
		m[r.Tag] = r.Target
	}
	return m, nil
}

func (g ghForge) Create(tag, commit, title, notes string, assets []string) error {
	args := append([]string{"release", "create", tag}, assets...)
	args = append(args, "--repo", g.project, "--target", commit, "--title", title, "--notes", notes)
	_, err := g.gh(args...)
	return err
}

func (g ghForge) DownloadBase(tag string) string {
	if g.base != "" {
		return strings.TrimRight(g.base, "/") + "/" + tag
	}
	return "https://github.com/" + g.project + "/releases/download/" + tag
}

// fjForge — Forgejo / Gitea через API (/api/v1), токен — заголовком.
type fjForge struct {
	api, project, token, base string
	http                      *http.Client
}

func (f fjForge) do(method, path string, body io.Reader, ctype string) ([]byte, error) {
	req, err := http.NewRequest(method, strings.TrimRight(f.api, "/")+"/api/v1/repos/"+f.project+path, body)
	if err != nil {
		return nil, err
	}
	if f.token != "" {
		req.Header.Set("Authorization", "token "+f.token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("forgejo %s %s: %s %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func (f fjForge) Tags() (map[string]string, error) {
	m := map[string]string{}
	for page := 1; page < 100; page++ {
		b, err := f.do("GET", fmt.Sprintf("/releases?limit=50&page=%d", page), nil, "")
		if err != nil {
			return nil, err
		}
		var rs []struct {
			Tag    string `json:"tag_name"`
			Target string `json:"target_commitish"`
		}
		if err := json.Unmarshal(b, &rs); err != nil {
			return nil, err
		}
		for _, r := range rs {
			m[r.Tag] = r.Target
		}
		if len(rs) < 50 {
			break
		}
	}
	return m, nil
}

func (f fjForge) Create(tag, commit, title, notes string, assets []string) error {
	body, _ := json.Marshal(map[string]any{"tag_name": tag, "target_commitish": commit, "name": title, "body": notes})
	b, err := f.do("POST", "/releases", bytes.NewReader(body), "application/json")
	if err != nil {
		return err
	}
	var rel struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(b, &rel); err != nil || rel.ID == 0 {
		return fmt.Errorf("forgejo: no release id in %s", b)
	}
	for _, a := range assets {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("attachment", filepath.Base(a))
		data, err := os.ReadFile(a)
		if err != nil {
			return err
		}
		fw.Write(data)
		mw.Close()
		if _, err := f.do("POST", fmt.Sprintf("/releases/%d/assets?name=%s", rel.ID, filepath.Base(a)), &buf, mw.FormDataContentType()); err != nil {
			return err
		}
	}
	return nil
}

func (f fjForge) DownloadBase(tag string) string {
	if f.base != "" {
		return strings.TrimRight(f.base, "/") + "/" + tag
	}
	return strings.TrimRight(f.api, "/") + "/" + f.project + "/releases/download/" + tag
}

var projectRe = regexp.MustCompile(`^[\w.-]+/[\w.-]+$`)

// NewForge — сервіс релізів цілі.
func NewForge(t workspace.Target, token string) (Forge, error) {
	if !projectRe.MatchString(t.Project) {
		return nil, fmt.Errorf("target %s: project %q is not owner/repo", t.ID, t.Project)
	}
	switch t.Forge {
	case "github":
		return ghForge{project: t.Project, token: token, base: t.DownloadURL}, nil
	case "forgejo", "gitea":
		if !strings.HasPrefix(t.API, "https://") && !strings.HasPrefix(t.API, "http://") {
			return nil, fmt.Errorf("target %s: api %q is not http(s)", t.ID, t.API)
		}
		return fjForge{api: t.API, project: t.Project, token: token, base: t.DownloadURL, http: &http.Client{Timeout: 10 * time.Minute}}, nil
	}
	return nil, fmt.Errorf("target %s: forge %q (github | forgejo)", t.ID, t.Forge)
}

// ReleaseInput — що публікувати.
type ReleaseInput struct {
	Dir      string // тека збирання: rules-manifest.json, .sig, DocScan-rules.zip, bundle
	Version  string
	Tree     map[string][]byte // файли пакета (для commit_tree)
	Report   []byte            // tools/vendor-report.md (якщо є генератор)
	Source   string            // для тексту релізу
	ForgeAPI Forge             // підміна в тестах
}

// Release — реліз у ціль kind "release".
func Release(ws workspace.Config, t workspace.Target, in ReleaseInput, e Env) (*Result, error) {
	if t.Public && ws.Visibility != "public" {
		return nil, fmt.Errorf("target %s is public, workspace %s is private: its critical rules and organisation rules must not leave it", t.ID, ws.Name)
	}
	f := in.ForgeAPI
	if f == nil {
		token := ""
		if e.Auth != nil {
			token = e.Auth.Token
		}
		var err error
		if f, err = NewForge(t, token); err != nil {
			return nil, err
		}
	}
	tags, err := f.Tags()
	if err != nil {
		return nil, err
	}
	if _, ok := tags[in.Version]; ok {
		return nil, fmt.Errorf("%s already has release %s - releases are never overwritten", t.Project, in.Version)
	}
	var vs []string
	for tg := range tags {
		if manifest.ValidVersion(tg) {
			vs = append(vs, tg)
		}
	}
	sort.Slice(vs, func(i, j int) bool { return manifest.Compare(vs[i], vs[j]) < 0 })
	if len(vs) > 0 && manifest.Compare(in.Version, vs[len(vs)-1]) <= 0 {
		return nil, fmt.Errorf("%s already has %s - %s would never be installed", t.Project, vs[len(vs)-1], in.Version)
	}
	res := &Result{}
	commit := t.Branch
	if t.CommitTree {
		c, err := commitTree(t, in, e)
		if err != nil {
			return nil, err
		}
		commit, res.Commit = c, c
		e.say("rules tree committed: %s", c[:8])
	}
	var assets []string
	for _, n := range []string{install.PackageName, install.ManifestName, install.SigName, install.BundleName} {
		assets = append(assets, filepath.Join(in.Dir, n))
	}
	notes := fmt.Sprintf("DocScan rules %s (%s, built by Anthophila_Hive).\n\n"+
		"- `%s` — the rules bundle for a manual install: `DocScan-Install.ps1 -Rules <file or URL>`\n"+
		"- `%s` + `%s` + `%s` — for the DocScanUpdater service\n\n"+
		"Signed with ed25519; DocScan installs only signed rules. Checked with DocScan's own install path before publishing.",
		in.Version, in.Source, install.BundleName, install.PackageName, install.ManifestName, install.SigName)
	if err := f.Create(in.Version, commit, "DocScan rules "+in.Version, notes, assets); err != nil {
		return res, err
	}
	base := f.DownloadBase(in.Version)
	res.Location = base
	e.say("release %s: %s", in.Version, base)
	co := e.Verify
	co.Published, co.Token = true, e.PCsToken
	if res.Report, err = contract.VerifyRules(base, co); err != nil {
		return res, fmt.Errorf("release created, but its files do not download correctly: %w", err)
	}
	return res, nil
}

// commitTree — дерево правил у гілку репозиторію правил (без force; критичні правила — ніколи).
func commitTree(t workspace.Target, in ReleaseInput, e Env) (string, error) {
	if t.Repo == "" || t.Branch == "" {
		return "", fmt.Errorf("target %s: commit_tree needs repo and branch", t.ID)
	}
	work, err := os.MkdirTemp("", "hive-rules-repo-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	r := &gitx.Repo{Auth: e.Auth}
	if _, err := r.Run("clone", "-q", "--branch", t.Branch, t.Repo, work); err != nil {
		return "", err
	}
	wr := &gitx.Repo{Dir: work, Auth: e.Auth}
	for _, kv := range [][2]string{{"user.name", "Anthophila_Hive"}, {"user.email", "hive@localhost"}, {"commit.gpgsign", "false"}, {"core.autocrlf", "false"}} {
		wr.Run("config", kv[0], kv[1])
	}
	// прибрати все, крім .git, README.md, tools/ репозиторію, — і покласти дерево пакета
	ents, _ := os.ReadDir(work)
	for _, en := range ents {
		if n := en.Name(); n != ".git" && n != "README.md" && n != "tools" && !strings.HasPrefix(n, ".") {
			os.RemoveAll(filepath.Join(work, n))
		}
	}
	for p, b := range in.Tree {
		if strings.HasPrefix(p, "critical/") || p == "VERSION.txt" {
			continue
		}
		dst := filepath.Join(work, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(dst), 0o755)
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return "", err
		}
	}
	if in.Report != nil {
		os.MkdirAll(filepath.Join(work, "tools"), 0o755)
		os.WriteFile(filepath.Join(work, "tools", "vendor-report.md"), in.Report, 0o644)
	}
	if _, err := os.Stat(filepath.Join(work, "critical")); err == nil {
		return "", fmt.Errorf("refusing to commit critical/ into the rules repository")
	}
	c, err := wr.CommitAll("DocScan rules "+in.Version+" (Anthophila_Hive)", "")
	if err != nil {
		return "", err
	}
	if _, err := wr.Run("push", "-q", "origin", "HEAD:refs/heads/"+t.Branch); err != nil {
		return "", err
	}
	return c, nil
}

// CurrentReleaseVersion — найбільший v-тег релізів цілі ("" — немає).
func CurrentReleaseVersion(t workspace.Target, e Env) (string, error) {
	token := ""
	if e.Auth != nil {
		token = e.Auth.Token
	}
	f, err := NewForge(t, token)
	if err != nil {
		return "", err
	}
	tags, err := f.Tags()
	if err != nil {
		return "", err
	}
	best := ""
	for tg := range tags {
		if manifest.ValidVersion(tg) && (best == "" || manifest.Compare(tg, best) > 0) {
			best = tg
		}
	}
	return best, nil
}

// ZipFiles — вміст zip (пакет правил) як карта шлях -> байти.
func ZipFiles(p string) (map[string][]byte, error) {
	zr, err := zipOpen(p)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := map[string][]byte{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !manifest.SafePath(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 512<<20))
		rc.Close()
		if err != nil {
			return nil, err
		}
		out[f.Name] = b
	}
	return out, nil
}

func zipOpen(p string) (*zip.ReadCloser, error) { return zip.OpenReader(p) }
