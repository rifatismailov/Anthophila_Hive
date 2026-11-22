package web

import (
	"archive/zip"
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/auth"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/hive"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func setup(t *testing.T) (*Server, *httptest.Server, string) {
	t.Helper()
	d := t.TempDir()
	src, _ := gitx.Init(filepath.Join(d, "src"))
	for n, s := range map[string]string{
		"docscan-index.yar": "include \"file-index.yar\"\n", "file-index.yar": "include \"general/a.yar\"\n",
		"general/a.yar": "rule Vendor_A : apt { meta: author = \"x\" strings: $a = \"vendor-a\" condition: $a }\nrule Vendor_B { condition: false }\n",
	} {
		p := filepath.Join(src.Dir, n)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(s), 0o644)
	}
	src.CommitAll("rules", "")
	a, err := hive.Open(filepath.Join(d, "data"), yaraexec.FromEnv())
	if err != nil {
		t.Fatal(err)
	}
	w, _ := a.CreateWS(workspace.Config{Name: "org", Visibility: "private", VersionFloor: "v1.0.0"}, "t")
	_, seed, _ := a.NewKey(w, "rules", "env:HIVE_WEB_TEST_KEY", "t")
	t.Setenv("HIVE_WEB_TEST_KEY", seed)
	_, lseed, _ := a.NewKey(w, "lists", "env:HIVE_WEB_TEST_LKEY", "t")
	t.Setenv("HIVE_WEB_TEST_LKEY", lseed)
	if err := a.AddSource(w, workspace.Source{ID: "docscan-rules", URL: src.Dir, Ref: "main"}, "t"); err != nil {
		t.Fatal(err)
	}
	w.Cfg.Targets = []workspace.Target{{ID: "share", Kind: "folder", Path: filepath.Join(d, "share")}, {ID: "lists", Kind: "lists-folder", Path: filepath.Join(d, "lists")}}
	w.SaveConfig()
	w.Commit("targets", "t")
	s, err := New(a, "org")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	if err := a.Auth.Add("admin", auth.Admin, "the admin password"); err != nil {
		t.Fatal(err)
	}
	sessions[ts.URL] = login(t, s, ts, "admin", "the admin password", "")
	return s, ts, d
}

// клієнт з входом
type client struct {
	c    *http.Client
	csrf string
}

var sessions = map[string]*client{}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var preRe = regexp.MustCompile(`name="pre" value="([^"]+)"`)

// login — вхід через форму; повертає клієнта з сесією і її CSRF-токеном.
func login(t *testing.T, s *Server, ts *httptest.Server, name, pass, code string) *client {
	t.Helper()
	c := newClient()
	resp, err := c.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := preRe.FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("no login form:\n%s", b)
	}
	resp, err = c.PostForm(ts.URL+"/login", url.Values{"pre": {m[1]}, "name": {name}, "password": {pass}, "totp": {code}, "next": {"/"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		return &client{c: c, csrf: "login failed: " + string(b)}
	}
	u, _ := url.Parse(ts.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookie {
			ss, err := s.app.Auth.Session(ck.Value, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			return &client{c: c, csrf: ss.CSRF}
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func get(t *testing.T, ts *httptest.Server, path string) string {
	t.Helper()
	resp, err := sessions[ts.URL].c.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d\n%s", path, resp.StatusCode, b)
	}
	return string(b)
}

func postAs(t *testing.T, cl *client, ts *httptest.Server, path string, v url.Values) (int, string, string) {
	t.Helper()
	v.Set("csrf", cl.csrf)
	if v.Get("ws") == "" {
		v.Set("ws", "org")
	}
	resp, err := cl.c.PostForm(ts.URL+path, v)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b), resp.Header.Get("Location")
}

func postForm(t *testing.T, s *Server, ts *httptest.Server, path string, v url.Values) (int, string, string) {
	t.Helper()
	return postAs(t, sessions[ts.URL], ts, path, v)
}

func TestPagesAndProtection(t *testing.T) {
	_, ts, _ := setup(t)
	for _, p := range []string{"/", "/sources", "/library", "/library?q=Vendor&kind=detection", "/own", "/own/edit?template=malware",
		"/own/edit?template=critical", "/lists", "/releases", "/ws/create",
		"/rule?origin=docscan-rules&file=general%2Fa.yar&name=Vendor_A"} {
		body := get(t, ts, p)
		if strings.Contains(body, "template:") || !strings.Contains(body, "</html>") {
			t.Fatalf("%s: broken page\n%s", p, body)
		}
	}
	if !strings.Contains(get(t, ts, "/library?q=Vendor"), "Vendor_B") {
		t.Fatal("library search")
	}
	// без токена форми
	code, _, _ := postAs(t, &client{c: sessions[ts.URL].c, csrf: "wrong"}, ts, "/decide", url.Values{})
	if code != http.StatusForbidden {
		t.Fatalf("POST without csrf: %d", code)
	}
	// без входу
	anon := newClient()
	resp, _ := anon.Get(ts.URL + "/library")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("anonymous GET: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = anon.PostForm(ts.URL+"/decide", url.Values{})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous POST: %d", resp.StatusCode)
	}
}

func TestFlowThroughForms(t *testing.T) {
	s, ts, d := setup(t)
	// рішення
	code, _, loc := postForm(t, s, ts, "/decide", url.Values{"origin": {"docscan-rules"}, "file": {"general/a.yar"}, "name": {"Vendor_B"}, "status": {"drop"}, "reason": {"FP"}})
	if code != http.StatusSeeOther || !strings.Contains(get(t, ts, loc), "Відкинуто") {
		t.Fatalf("decide: %d %s", code, loc)
	}
	// власне правило з помилкою — не зберігається
	if s.app.Tools.Configured() {
		_, body, _ := postForm(t, s, ts, "/own/save", url.Values{"new": {"1"}, "kind": {"org"}, "name": {"inc"}, "text": {"rule ORG_X { condition: nosuch }"}, "action": {"save"}})
		if !strings.Contains(body, "nosuch") || strings.Contains(body, "Збережено") {
			t.Fatalf("bad rule saved:\n%s", body)
		}
	}
	_, body, _ := postForm(t, s, ts, "/own/save", url.Values{"new": {"1"}, "kind": {"org"}, "name": {"inc"}, "text": {"rule ORG_X { strings: $a = \"inc-marker\" condition: $a }"}, "action": {"save"}})
	if !strings.Contains(body, "Збережено") {
		t.Fatalf("good rule not saved:\n%s", body)
	}
	// тестовий файл (multipart)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range map[string]string{"csrf": sessions[ts.URL].csrf, "ws": "org", "kind": "org", "name": "inc.yar", "rule": "ORG_X", "expect": "match", "sample_kind": "malware"} {
		mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("file", "dropper.exe")
	fw.Write([]byte("MZ inc-marker"))
	mw.Close()
	resp, err := sessions[ts.URL].c.Post(ts.URL+"/own/test/add", mw.FormDataContentType(), &buf)
	if err != nil || resp.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("test add: %v %d %s", err, resp.StatusCode, b)
	}
	if !strings.Contains(get(t, ts, "/own/edit?kind=org&name=inc.yar"), "dropper.exe") {
		t.Fatal("test not listed")
	}
	// зразок не в git простору
	ws := filepath.Join(d, "data", "workspaces", "org")
	out, _ := (&gitx.Repo{Dir: ws}).Run("grep", "-l", "inc-marker", "HEAD", "--", "tests.yaml")
	if out != "" {
		t.Fatal("sample content in git")
	}
	// список
	code, _, _ = postForm(t, s, ts, "/lists/add", url.Values{"kind": {"black"}, "sha256": {strings.Repeat("2", 64)}, "comment": {"dropper"}})
	if code != http.StatusSeeOther {
		t.Fatalf("lists add %d", code)
	}
	code, _, _ = postForm(t, s, ts, "/lists/add", url.Values{"kind": {"white"}, "path": {`C:\Users\*\Downloads\*`}, "comment": {"bad"}})
	if code != http.StatusBadRequest {
		t.Fatalf("white list allowing a whole folder accepted: %d", code)
	}
	_, body, _ = postForm(t, s, ts, "/lists/publish", url.Values{"target": {"lists"}, "confirm": {"no"}})
	if !strings.Contains(body, "Введіть") {
		t.Fatal("no confirmation page for lists")
	}
	if code, body, _ = postForm(t, s, ts, "/lists/publish", url.Values{"target": {"lists"}, "confirm": {"yes"}}); code != http.StatusSeeOther {
		t.Fatalf("lists publish %d %s", code, body)
	}
	if !s.app.Tools.Configured() {
		return
	}
	// збирання і публікація
	code, body, loc = postForm(t, s, ts, "/build", url.Values{"bump": {"patch"}})
	if code != http.StatusSeeOther {
		t.Fatalf("build %d %s", code, body)
	}
	page := get(t, ts, loc)
	if !regexp.MustCompile(`v1\.0\.1`).MatchString(page) || !strings.Contains(page, "r-pass") {
		t.Fatalf("release page:\n%s", page)
	}
	_, body, _ = postForm(t, s, ts, "/publish", url.Values{"v": {"v1.0.1"}, "target": {"share"}, "confirm": {"v1.0.0"}})
	if !strings.Contains(body, "Введіть версію") {
		t.Fatal("wrong version typed, but no confirmation page")
	}
	if code, body, _ = postForm(t, s, ts, "/publish", url.Values{"v": {"v1.0.1"}, "target": {"share"}, "confirm": {" v1.0.1 "}}); code != http.StatusSeeOther {
		t.Fatalf("publish %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(d, "share", "rules-manifest.json")); err != nil {
		t.Fatal("not published")
	}
	// завантажити на свій ПК: усе одним zip — ті самі байти, що в теці публікації
	if !strings.Contains(get(t, ts, "/release?v=v1.0.1"), "/release/download?ws=org&amp;v=v1.0.1&amp;file=rules-manifest.sig") {
		t.Fatal("no download links on the release page")
	}
	all := get(t, ts, "/release/download?ws=org&v=v1.0.1&file=all")
	zr, err := zip.NewReader(strings.NewReader(all), int64(len(all)))
	if err != nil || len(zr.File) != 4 {
		t.Fatalf("download zip: %v", err)
	}
	for _, f := range zr.File {
		rc, _ := f.Open()
		got, _ := io.ReadAll(rc)
		rc.Close()
		want, _ := os.ReadFile(filepath.Join(d, "share", f.Name))
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from the published file", f.Name)
		}
	}
	if sig := get(t, ts, "/release/download?ws=org&v=v1.0.1&file=rules-manifest.sig"); len(sig) == 0 {
		t.Fatal("single file")
	}
	for _, bad := range []string{"../../hive.db", "hive.yaml", ""} {
		resp, _ := sessions[ts.URL].c.Get(ts.URL + "/release/download?ws=org&v=v1.0.1&file=" + url.QueryEscape(bad))
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 && !strings.Contains(string(b), "unknown file") {
			t.Fatalf("file %q served", bad)
		}
	}
	s.app.Auth.Add("ed", auth.Editor, "the editor password")
	ed := login(t, s, ts, "ed", "the editor password", "")
	if resp, _ := ed.c.Get(ts.URL + "/release/download?ws=org&v=v1.0.1&file=all"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("editor download: %d", resp.StatusCode)
	}
}

func TestLabDupesSettingsPages(t *testing.T) {
	s, ts, d := setup(t)
	for _, p := range []string{"/lab", "/dupes", "/dupes?level=L1", "/settings"} {
		if body := get(t, ts, p); strings.Contains(body, "template:") || !strings.Contains(body, "</html>") {
			t.Fatalf("%s: broken page\n%s", p, body)
		}
	}
	if !s.app.Tools.Configured() {
		return
	}
	clean := filepath.Join(d, "clean")
	os.MkdirAll(clean, 0o755)
	os.WriteFile(filepath.Join(clean, "a.txt"), []byte("vendor-a in a clean letter"), 0o644)
	if code, body, _ := postForm(t, s, ts, "/lab/set/add", url.Values{"id": {"clean"}, "kind": {"clean"}, "path": {clean}}); code != http.StatusSeeOther {
		t.Fatalf("set add %d %s", code, body)
	}
	if code, body, _ := postForm(t, s, ts, "/lab/config", url.Values{"sets": {"clean"}, "mode": {"fast"}}); code != http.StatusSeeOther {
		t.Fatalf("lab config %d %s", code, body)
	}
	if code, body, _ := postForm(t, s, ts, "/build", url.Values{"bump": {"patch"}}); code != http.StatusSeeOther {
		t.Fatalf("build %d %s", code, body)
	}
	if !strings.Contains(get(t, ts, "/release?v=v1.0.1"), "ще не проганявся") {
		t.Fatal("release page does not ask for the lab")
	}
	code, body, loc := postForm(t, s, ts, "/lab/run", url.Values{"candidate": {"v1.0.1"}, "baseline": {"none"}})
	if code != http.StatusSeeOther {
		t.Fatalf("lab run %d %s", code, body)
	}
	rep := get(t, ts, loc)
	if !strings.Contains(rep, "G2") || !strings.Contains(rep, "Vendor_A") {
		t.Fatalf("report:\n%s", rep)
	}
	_, body, _ = postForm(t, s, ts, "/verify", url.Values{"path": {filepath.Join(d, "data", "out", "org", "v1.0.1")}})
	if !strings.Contains(body, "R03") || !strings.Contains(body, "PASS") {
		t.Fatalf("verify:\n%s", body)
	}
	_, body, _ = postForm(t, s, ts, "/reproduce", url.Values{"v": {"v1.0.1"}})
	if !strings.Contains(body, "not a published release") {
		t.Fatalf("reproduce of an unpublished release:\n%s", body)
	}
	if code, _, _ := postForm(t, s, ts, "/target/delete", url.Values{"id": {"share"}}); code != http.StatusSeeOther {
		t.Fatalf("target delete %d", code)
	}
	if strings.Contains(get(t, ts, "/settings"), "/share") {
		t.Fatal("target not deleted")
	}
}

func TestVendorPageWithoutGenerator(t *testing.T) {
	_, ts, _ := setup(t)
	body := get(t, ts, "/vendor")
	if !strings.Contains(body, "ще немає генератора") || strings.Contains(body, "template:") {
		t.Fatalf("vendor page:\n%s", body)
	}
}

func TestServerRolesTOTPKeystoreFourEyes(t *testing.T) {
	s, ts, d := setup(t)
	adm := sessions[ts.URL]
	// користувачі різних ролей — через сторінку адміністратора
	for _, u := range [][2]string{{"viewer1", "viewer"}, {"editor1", "editor"}, {"reviewer1", "reviewer"}, {"publisher1", "publisher"}} {
		if code, body, _ := postAs(t, adm, ts, "/users/add", url.Values{"name": {u[0]}, "role": {u[1]}, "password": {"a temporary password"}}); code != http.StatusSeeOther {
			t.Fatalf("add %s: %d %s", u[0], code, body)
		}
	}
	viewer := login(t, s, ts, "viewer1", "a temporary password", "")
	editor := login(t, s, ts, "editor1", "a temporary password", "")
	// переглядач бачить, але не змінює
	resp, _ := viewer.c.Get(ts.URL + "/library?ws=org")
	if resp.StatusCode != 200 {
		t.Fatalf("viewer GET %d", resp.StatusCode)
	}
	if code, _, _ := postAs(t, viewer, ts, "/decide", url.Values{"origin": {"docscan-rules"}, "file": {"general/a.yar"}, "name": {"Vendor_B"}, "status": {"drop"}, "reason": {"x"}}); code != http.StatusForbidden {
		t.Fatalf("viewer decided: %d", code)
	}
	if code, _, _ := postAs(t, editor, ts, "/users/add", url.Values{"name": {"x2"}, "role": {"admin"}, "password": {"a temporary password"}}); code != http.StatusForbidden {
		t.Fatalf("editor added a user: %d", code)
	}
	if code, _, _ := postAs(t, editor, ts, "/publish", url.Values{"v": {"v1.0.1"}, "target": {"share"}, "confirm": {"v1.0.1"}}); code != http.StatusForbidden {
		t.Fatalf("editor published: %d", code)
	}
	// невідомий маршрут POST — лише адміністратор
	if code, _, _ := postAs(t, editor, ts, "/no/such/action", url.Values{}); code != http.StatusForbidden {
		t.Fatalf("unknown POST for an editor: %d", code)
	}
	// неправильний пароль
	if c := login(t, s, ts, "editor1", "wrong password!!", ""); !strings.HasPrefix(c.csrf, "login failed") {
		t.Fatal("wrong password accepted")
	}
	// TOTP через профіль
	page := get(t, ts, "/profile")
	m := regexp.MustCompile(`name="secret" value="([A-Z2-7]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no TOTP secret:\n%s", page)
	}
	code6, _ := auth.TOTPCode(m[1], time.Now().Unix()/30)
	if c, body, _ := postAs(t, adm, ts, "/profile/totp", url.Values{"secret": {m[1]}, "code": {code6}, "current": {"the admin password"}}); c != http.StatusSeeOther {
		t.Fatalf("enable TOTP: %d %s", c, body)
	}
	if c := login(t, s, ts, "admin", "the admin password", ""); !strings.HasPrefix(c.csrf, "login failed") || !strings.Contains(c.csrf, "one-time code") {
		t.Fatalf("no TOTP asked: %s", c.csrf)
	}
	next, _ := auth.TOTPCode(m[1], time.Now().Unix()/30+1) // наступний крок (поточний уже використано)
	if c := login(t, s, ts, "admin", "the admin password", next); strings.HasPrefix(c.csrf, "login failed") {
		t.Fatalf("TOTP login failed: %s", c.csrf)
	}
	// сховище ключів і ключ простору в ньому — через веб
	if c, body, _ := postAs(t, adm, ts, "/keys/init", url.Values{"passphrase": {"the keystore passphrase"}, "passphrase2": {"the keystore passphrase"}}); c != http.StatusSeeOther {
		t.Fatalf("keystore init %d %s", c, body)
	}
	if c, body, _ := postAs(t, adm, ts, "/key/new", url.Values{"kind": {"rules"}, "ref": {"hive:org-rules"}, "keystore_password": {"the keystore passphrase"}}); c != 200 || !strings.Contains(body, "Секрет записано") {
		t.Fatalf("key in keystore: %d %s", c, body)
	}
	b, _ := os.ReadFile(filepath.Join(d, "data", "keys", "org-rules.json"))
	if !strings.Contains(string(b), `"kind": "ed25519-seed"`) {
		t.Fatalf("keystore file:\n%s", b)
	}
	if !s.app.Tools.Configured() {
		return
	}
	// «чотири ока»: увімкнути, editor збирає, publisher публікує
	w, _ := s.app.WS("org")
	w.Cfg.FourEyes = true
	w.SaveConfig()
	w.Commit("four eyes", "admin")
	if c, body, _ := postAs(t, editor, ts, "/build", url.Values{"bump": {"patch"}}); c != http.StatusBadRequest || !strings.Contains(body, "passphrase") {
		t.Fatalf("build without the keystore passphrase: %d", c)
	}
	if c, body, _ := postAs(t, editor, ts, "/build", url.Values{"bump": {"patch"}, "keystore_password": {"the keystore passphrase"}}); c != http.StatusSeeOther {
		t.Fatalf("build %d %s", c, body)
	}
	pub := login(t, s, ts, "publisher1", "a temporary password", "")
	if c, body, _ := postAs(t, pub, ts, "/publish", url.Values{"v": {"v1.0.1"}, "target": {"share"}, "confirm": {"v1.0.1"}}); c != http.StatusSeeOther {
		t.Fatalf("publisher publish: %d %s", c, body)
	}
	rel := get(t, ts, "/release?ws=org&v=v1.0.1")
	if !strings.Contains(rel, "editor1") {
		t.Fatal("builder not shown")
	}
	// той, хто збирав, не схвалює
	ed2 := login(t, s, ts, "editor1", "a temporary password", "")
	s.app.Auth.SetRole("editor1", auth.Reviewer)
	if c, body, _ := postAs(t, ed2, ts, "/approve", url.Values{"v": {"v1.0.1"}, "note": {"mine"}}); c != http.StatusBadRequest || !strings.Contains(body, "another person") {
		t.Fatalf("builder approved: %d", c)
	}
}

func TestServeRefusals(t *testing.T) {
	a, err := hive.Open(t.TempDir(), yaraexec.Tools{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Serve(a, Options{Listen: "127.0.0.1:0"}); err == nil || !strings.Contains(err.Error(), "first admin") {
		t.Fatalf("no users: %v", err)
	}
	a.Auth.Add("admin", auth.Admin, "the admin password")
	if err := Serve(a, Options{Listen: "0.0.0.0:0"}); err == nil || !strings.Contains(err.Error(), "tls") {
		t.Fatalf("plain HTTP on the network: %v", err)
	}
}

// Регресія (Firefox): сторінку входу відкрито двічі (дві вкладки / повторне завантаження) — форма з першої
// вкладки має працювати.
func TestLoginTwoTabs(t *testing.T) {
	_, ts, _ := setup(t)
	c := newClient()
	page := func() string {
		resp, _ := c.Get(ts.URL + "/login")
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return preRe.FindStringSubmatch(string(b))[1]
	}
	first := page()
	second := page()
	if first != second {
		t.Fatalf("each login page gets its own token: %s vs %s", first, second)
	}
	resp, _ := c.PostForm(ts.URL+"/login", url.Values{"pre": {first}, "name": {"admin"}, "password": {"the admin password"}, "next": {"/"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login from the first tab: %d", resp.StatusCode)
	}
}

// Регресія: посилання зі сторінок мають відкриватися (раніше шлях з «/» кодувався двічі: critical%252Fzsu.yar).
func TestLinksFromPagesOpen(t *testing.T) {
	s, ts, _ := setup(t)
	if fs, ok, err := s.app.SaveOwnRule(mustWS(t, s), "critical", "zsu.yar", "rule crit_x { strings: $a = \"службов\" condition: $a }\n", "admin"); !ok || err != nil {
		t.Fatalf("%+v %v", fs, err)
	}
	hrefRe := regexp.MustCompile(`href="(/(?:rule|own/edit)\?[^"]+)"`)
	seen := 0
	for _, page := range []string{"/library?ws=org", "/library?ws=org&kind=critical", "/own?ws=org"} {
		for _, m := range hrefRe.FindAllStringSubmatch(get(t, ts, page), -1) {
			link := strings.ReplaceAll(m[1], "&amp;", "&")
			if strings.Contains(link, "%25") {
				t.Errorf("%s: double-escaped link %s", page, link)
			}
			get(t, ts, link) // 200, інакше тест падає
			seen++
		}
	}
	if seen < 3 {
		t.Fatalf("only %d links checked", seen)
	}
	// посилання «відкрити в редакторі» зі сторінки критичного правила
	body := get(t, ts, "/rule?ws=org&origin=critical&file=critical%2Fzsu.yar&name=crit_x")
	m := regexp.MustCompile(`href="(/own/edit\?[^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no editor link")
	}
	if !strings.Contains(get(t, ts, strings.ReplaceAll(m[1], "&amp;", "&")), "crit_x") {
		t.Fatal("editor did not open the file")
	}
}

func mustWS(t *testing.T, s *Server) *workspace.WS {
	w, err := s.app.WS("org")
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestDocsPageAndHelpLinks(t *testing.T) {
	_, ts, _ := setup(t)
	body := get(t, ts, "/docs?ws=org")
	if strings.Contains(body, "template:") || !strings.Contains(body, "Документація") {
		t.Fatalf("docs page:\n%s", body)
	}
	// кожна сторінка веде «? довідкою» на розділ, що існує
	for _, p := range []string{"/", "/sources", "/vendor", "/library", "/own", "/lists", "/dupes", "/lab", "/releases", "/settings", "/keys", "/profile", "/users"} {
		a := docAnchor(p)
		if !strings.Contains(body, `id="`+a+`"`) {
			t.Errorf("%s: no section #%s in the docs", p, a)
		}
		if page := get(t, ts, p+"?ws=org"); !strings.Contains(page, "#"+a+`"`) {
			t.Errorf("%s: no help link to #%s", p, a)
		}
	}
}

// Додати файли в наявний набір через веб: кілька за раз, лише для читання, оригінальна тека не змінюється;
// viewer не може; прибрати можна.
func TestLabSetAddFiles(t *testing.T) {
	s, ts, d := setup(t)
	mal := filepath.Join(d, "mal")
	os.MkdirAll(mal, 0o755)
	os.WriteFile(filepath.Join(mal, "s1.bin"), []byte("xx"), 0o644)
	if code, body, _ := postForm(t, s, ts, "/lab/set/add", url.Values{"id": {"malware"}, "kind": {"malware"}, "path": {mal}}); code != http.StatusSeeOther {
		t.Fatalf("set add %d %s", code, body)
	}
	upload := func(cl *client, files map[string]string) (int, string) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		mw.WriteField("csrf", cl.csrf)
		mw.WriteField("ws", "org")
		mw.WriteField("id", "malware")
		for n, c := range files {
			fw, _ := mw.CreateFormFile("file", n)
			fw.Write([]byte(c))
		}
		mw.Close()
		resp, err := cl.c.Post(ts.URL+"/lab/set/files", mw.FormDataContentType(), &buf)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, body := upload(sessions[ts.URL], map[string]string{"miner.exe": "MZ miner", `C:\temp\drop.dll`: "MZ dll"}); code != http.StatusSeeOther {
		t.Fatalf("upload %d %s", code, body)
	}
	added := filepath.Join(d, "data", "lab", "added", "malware")
	for _, n := range []string{"miner.exe", "drop.dll"} {
		fi, err := os.Stat(filepath.Join(added, n))
		if err != nil || fi.Mode().Perm() != 0o400 {
			t.Fatalf("%s: %v %v", n, err, fi)
		}
	}
	if ents, _ := os.ReadDir(mal); len(ents) != 1 {
		t.Fatal("original folder changed")
	}
	page := get(t, ts, "/lab")
	if !strings.Contains(page, "miner.exe") || !strings.Contains(page, "додано через веб: 2") {
		t.Fatalf("lab page does not list added files:\n%s", page)
	}
	sets, _ := s.app.DB.LabSets()
	if sets[0].Files != 3 {
		t.Fatalf("inventory %d", sets[0].Files)
	}
	// той самий вміст — без змін; інший вміст під тим самим ім'ям — відмова; недозволені імена
	if code, _ := upload(sessions[ts.URL], map[string]string{"miner.exe": "MZ miner"}); code != http.StatusSeeOther {
		t.Fatal("same file again refused")
	}
	if code, _ := upload(sessions[ts.URL], map[string]string{"miner.exe": "other"}); code == http.StatusSeeOther {
		t.Fatal("other content under the same name accepted")
	}
	for _, n := range []string{".hidden", "expected.tsv", "../../x"} {
		upload(sessions[ts.URL], map[string]string{n: "x"})
	}
	if ents, _ := os.ReadDir(added); len(ents) != 3 { // miner.exe, drop.dll і «../../x», обрізане до x у теці набору
		t.Fatalf("bad names written: %v", ents)
	}
	if _, err := os.Stat(filepath.Join(d, "data", "lab", "x")); err == nil {
		t.Fatal("path traversal")
	}
	// viewer — ні
	s.app.Auth.Add("viewer", auth.Viewer, "the viewer password")
	v := login(t, s, ts, "viewer", "the viewer password", "")
	if code, _ := upload(v, map[string]string{"v.exe": "x"}); code != http.StatusForbidden {
		t.Fatalf("viewer upload: %d", code)
	}
	// прибрати
	if code, body, _ := postForm(t, s, ts, "/lab/set/file/remove", url.Values{"id": {"malware"}, "name": {"drop.dll"}}); code != http.StatusSeeOther {
		t.Fatalf("remove %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(added, "drop.dll")); err == nil {
		t.Fatal("not removed")
	}
	// прибрати набір — разом з доданими
	postForm(t, s, ts, "/lab/set/remove", url.Values{"id": {"malware"}})
	if _, err := os.Stat(added); err == nil {
		t.Fatal("added files left after the set was removed")
	}
}
