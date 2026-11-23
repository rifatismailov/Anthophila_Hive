// Package web — веб-інтерфейс Hive (MVP-a): html/template, без JavaScript-залежностей, лише на loopback.
//
// Безпека локального сервера: слухає тільки 127.0.0.1 / ::1; Host має бути локальним (захист від DNS rebinding);
// кожна форма POST несе CSRF-токен, випадковий на кожен запуск; дії виконуються по одній (м'ютекс).
// Публікація — лише з окремої сторінки підтвердження, де людина вводить версію.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/auth"
	"github.com/rifatismailov/Anthophila_Hive/internal/checks"
	"github.com/rifatismailov/Anthophila_Hive/internal/contract"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/orglists"
	"github.com/rifatismailov/Anthophila_Hive/internal/hive"
	"github.com/rifatismailov/Anthophila_Hive/internal/lists"
	"github.com/rifatismailov/Anthophila_Hive/internal/publish"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server — веб-інтерфейс над App.
type Server struct {
	app  *hive.App
	ws   string
	mu   sync.Mutex
	tpl  *template.Template
	opts Options
	lim  *limiter
}

// Options — як слухати (PLAN.md, розділ 11: сервер організації).
type Options struct {
	Listen      string // адреса, напр. 0.0.0.0:8740 (у Docker) або 127.0.0.1:8740
	TLSCert     string // сертифікат і ключ HTTPS (PEM)
	TLSKey      string
	BehindProxy bool   // HTTPS завершує reverse proxy: довіряти X-Forwarded-Proto / X-Forwarded-For
	Workspace   string // простір за замовчуванням
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// Serve — запустити веб-інтерфейс.
func Serve(a *hive.App, o Options) error {
	if a.Auth.Count() == 0 {
		return fmt.Errorf("no users yet - create the first admin: hive user add --name admin --role admin")
	}
	tls := o.TLSCert != "" && o.TLSKey != ""
	if !tls && !o.BehindProxy && !loopback(o.Listen) {
		return fmt.Errorf("%s: plain HTTP on the network leaks passwords and the keystore passphrase - give --tls-cert/--tls-key, or --behind-proxy when an HTTPS reverse proxy is in front", o.Listen)
	}
	s, err := New(a, o.Workspace)
	if err != nil {
		return err
	}
	s.opts = o
	srv := &http.Server{Addr: o.Listen, Handler: s, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Minute, WriteTimeout: 60 * time.Minute}
	if tls {
		fmt.Printf("Anthophila_Hive: https://%s/\n", o.Listen)
		return srv.ListenAndServeTLS(o.TLSCert, o.TLSKey)
	}
	fmt.Printf("Anthophila_Hive: http://%s/%s\n", o.Listen, map[bool]string{true: " (HTTPS at the reverse proxy)", false: ""}[o.BehindProxy])
	return srv.ListenAndServe()
}

// New — сервер (для тестів — без прослуховування).
func New(a *hive.App, ws string) (*Server, error) {
	s := &Server{app: a, ws: ws, lim: &limiter{m: map[string]*attempt{}}}
	funcs := template.FuncMap{
		"short": func(s string) string {
			if len(s) > 8 {
				return s[:8]
			}
			return s
		},
		"join":      strings.Join,
		"add":       func(a, b int) int { return a + b },
		"q":         url.QueryEscape,
		"keyid":     keyID,
		"ts":        func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
		"lower":     strings.ToLower,
		"list4":     func(a ...any) []any { return a },
		"mb":        func(b int64) float64 { return float64(b) / 1e6 },
		"utc":       func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04Z") },
		"hasPrefix": strings.HasPrefix,
		"docAnchor": docAnchor,
	}
	var err error
	s.tpl, err = template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return s, nil
}

func keyID(pub string) string {
	k, err := manifest.ParseKey(pub)
	if err != nil {
		return "—"
	}
	return manifest.KeyID(k)
}

// postRole — мінімальна роль для дії (POST); переглядати (GET) може будь-хто з входом.
var postRole = map[string]auth.Role{
	"/decide": auth.Editor, "/own/save": auth.Editor, "/own/delete": auth.Editor, "/own/test/add": auth.Editor,
	"/own/test/remove": auth.Editor, "/own/test/run": auth.Editor, "/lists/add": auth.Editor, "/lists/remove": auth.Editor,
	"/sources/add": auth.Editor, "/sources/pin": auth.Editor, "/import/critical": auth.Editor, "/import/list": auth.Editor,
	"/build": auth.Editor, "/lab/run": auth.Editor, "/dupes/keep": auth.Editor, "/dupes/drop-in": auth.Editor,
	"/vendor/update": auth.Editor, "/vendor/pin": auth.Editor, "/vendor/regenerate": auth.Editor, "/vendor/import": auth.Editor,
	"/vendor/history": auth.Editor, "/vendor/fetch": auth.Editor, "/reproduce": auth.Editor, "/verify": auth.Editor,
	"/lab/accept": auth.Reviewer, "/approve": auth.Reviewer,
	"/publish": auth.Publisher, "/lists/publish": auth.Publisher, "/editions/save": auth.Admin,
	"/ws/create": auth.Admin, "/key/new": auth.Admin, "/target/add": auth.Admin, "/target/delete": auth.Admin,
	"/lab/set/add": auth.Admin, "/lab/set/remove": auth.Admin, "/lab/set/files": auth.Editor, "/lab/set/file/remove": auth.Editor, "/lab/config": auth.Admin, "/settings/floor": auth.Admin,
	"/users/add": auth.Admin, "/users/role": auth.Admin, "/users/disable": auth.Admin, "/users/password": auth.Admin,
	"/keys/init": auth.Admin, "/keys/token": auth.Admin, "/keys/rekey": auth.Admin, "/keys/delete": auth.Admin,
	"/profile/password": auth.Viewer, "/profile/totp": auth.Viewer, "/logout": auth.Viewer,
}

type ctxKey struct{}

// sess — сесія запиту.
func sess(r *http.Request) *auth.Session {
	s, _ := r.Context().Value(ctxKey{}).(*auth.Session)
	return s
}

// who — хто діє (ім'я користувача сесії).
func who(r *http.Request) string {
	if s := sess(r); s != nil {
		return s.User.Name
	}
	return ""
}

func (s *Server) secure(r *http.Request) bool {
	return r.TLS != nil || s.opts.BehindProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) clientIP(r *http.Request) string {
	if s.opts.BehindProxy {
		if f := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); f != "" {
			return f
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

const sessionCookie = "hive_session"

// ServeHTTP — вхід, ролі, CSRF, маршрути.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	if strings.HasPrefix(r.URL.Path, "/static/") {
		w.Header().Set("Cache-Control", "max-age=3600")
		http.FileServer(http.FS(assets)).ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/login" {
		s.login(w, r)
		return
	}
	var ss *auth.Session
	if c, err := r.Cookie(sessionCookie); err == nil {
		ss, _ = s.app.Auth.Session(c.Value, time.Now())
	}
	if ss == nil {
		if r.Method == http.MethodPost {
			http.Error(w, "the session has ended - sign in again", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, ss))
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
		if err := r.ParseMultipartForm(64 << 20); err != nil && err != http.ErrNotMultipart {
			s.fail(w, r, err)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(ss.CSRF)) != 1 {
			http.Error(w, "bad form token (reload the page)", http.StatusForbidden)
			return
		}
		need, ok := postRole[r.URL.Path]
		if !ok {
			need = auth.Admin // нова дія без запису в таблиці — лише адміністратор
		}
		if ss.User.Role < need {
			w.WriteHeader(http.StatusForbidden)
			s.render(w, r, "error", "Немає прав", fmt.Errorf("this action needs the role %s (you are %s)", need, ss.User.Role))
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		hivePass, kdbxPass := r.FormValue("keystore_password"), r.FormValue("kdbx_password")
		s.app.Unlock = func(what string) ([]byte, error) {
			pw := kdbxPass
			if what == "hive" {
				pw = hivePass
			}
			if pw == "" {
				return nil, fmt.Errorf("enter the keystore passphrase in the form")
			}
			return []byte(pw), nil
		}
		defer func() { s.app.Unlock = nil }()
	}
	routes := map[string]func(http.ResponseWriter, *http.Request){
		"/": s.home, "/ws/create": s.wsCreate, "/key/new": s.keyNew, "/target/add": s.targetAdd,
		"/library": s.library, "/rule": s.rule, "/decide": s.decide,
		"/own": s.own, "/own/edit": s.ownEdit, "/own/save": s.ownSave, "/own/delete": s.ownDelete,
		"/own/test/add": s.testAdd, "/own/test/remove": s.testRemove, "/own/test/run": s.testRun,
		"/lists": s.lists, "/lists/add": s.listsAdd, "/lists/remove": s.listsRemove, "/lists/publish": s.listsPublish,
		"/sources": s.sources, "/sources/add": s.sourcesAdd, "/sources/pin": s.sourcesPin,
		"/import/critical": s.importCritical, "/import/list": s.importList,
		"/releases": s.releases, "/build": s.build, "/release": s.release, "/release/download": s.releaseDownload, "/editions": s.editionsPage, "/editions/save": s.editionsSave, "/publish": s.publish, "/approve": s.approve,
		"/logout": s.logout, "/docs": s.docs,
	}
	for _, m := range []map[string]func(http.ResponseWriter, *http.Request){s.labRoutes(), s.vendorRoutes(), s.accountRoutes()} {
		for k, v := range m {
			routes[k] = v
		}
	}
	f, ok := routes[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	f(w, r)
}

// page — спільні дані сторінки.
type page struct {
	Title    string
	CSRF     string
	WS       *workspace.WS
	All      []string
	Flash    string
	Error    string
	Tools    bool
	Data     any
	KeePass  bool // у формі потрібне поле пароля KeePassXC
	Keystore bool // у формі потрібне поле пароля сховища ключів Hive
	User     *auth.User
	Can      map[string]bool // editor / reviewer / publisher / admin
	Path     string          // поточна сторінка (активний пункт навігації)
	Sandbox  string          // пісочниця ОС для лабораторії
	KeysOK   bool            // пароль сховища ключів задано
	Now      time.Time
	Version  string
}

func (s *Server) wsOf(r *http.Request) (*workspace.WS, error) {
	name := r.FormValue("ws")
	if name == "" {
		name = s.ws
	}
	return s.app.WS(name)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	p := page{Title: title, All: s.app.Workspaces(), Tools: s.app.Tools.Configured(), Data: data,
		Flash: r.FormValue("flash"), Can: map[string]bool{}, Path: r.URL.Path, Sandbox: yaraexec.SandboxKind(),
		KeysOK: s.app.Keys.Initialized(), Now: time.Now(), Version: hive.Version}
	if ss := sess(r); ss != nil {
		p.CSRF, p.User = ss.CSRF, ss.User
		for _, x := range auth.Roles() {
			p.Can[x.String()] = ss.User.Role >= x
		}
	}
	p.WS, _ = s.wsOf(r)
	p.Keystore = true // ключі й токени на сервері — у сховищі Hive
	if p.WS != nil {
		for _, ref := range []string{p.WS.Cfg.RulesKey.Secret, p.WS.Cfg.ListsKey.Secret} {
			if strings.HasPrefix(ref, "keepassxc:") {
				p.KeePass = true
			}
		}
	}
	if e, ok := data.(error); ok {
		p.Error, p.Data = e.Error(), nil
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, p); err != nil {
		fmt.Fprintf(os.Stderr, "template %s: %v\n", name, err)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, e error) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "error", "Помилка", e)
}

func (s *Server) back(w http.ResponseWriter, r *http.Request, path, flash string, kv ...string) {
	v := url.Values{}
	if ws, err := s.wsOf(r); err == nil {
		v.Set("ws", ws.Cfg.Name)
	}
	if flash != "" {
		v.Set("flash", flash)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	http.Redirect(w, r, path+"?"+v.Encode(), http.StatusSeeOther)
}

func post(r *http.Request) bool { return r.Method == http.MethodPost }

// ---------------------------------------------------------------- головна

type homeData struct {
	Sources  []workspace.Source
	Counts   map[string]int
	Releases []store.Release
	Pubs     []store.Publication
	Audit    []store.AuditEntry
	Tests    int
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.render(w, r, "welcome", "Anthophila_Hive", nil)
		return
	}
	d := homeData{Counts: map[string]int{}}
	d.Sources, _ = ws.Sources()
	for _, k := range []string{"detection", "policy", "critical"} {
		_, d.Counts[k], _ = s.app.DB.FindRules(store.RuleQuery{WS: ws.Cfg.Name, Kind: k, Limit: 1})
	}
	_, d.Counts["org"], _ = s.app.DB.FindRules(store.RuleQuery{WS: ws.Cfg.Name, Origin: "org", Limit: 1})
	dec, _ := ws.Decisions()
	d.Counts["dropped"] = len(dec)
	tests, _ := ws.Tests()
	d.Tests = len(tests)
	d.Releases, _ = s.app.DB.Releases(ws.Cfg.Name)
	if len(d.Releases) > 5 {
		d.Releases = d.Releases[:5]
	}
	d.Pubs, _ = s.app.DB.Publications(ws.Cfg.Name)
	if len(d.Pubs) > 5 {
		d.Pubs = d.Pubs[:5]
	}
	d.Audit, _ = s.app.DB.AuditLog(ws.Cfg.Name, 12)
	s.render(w, r, "home", "Огляд", d)
}

func (s *Server) wsCreate(w http.ResponseWriter, r *http.Request) {
	if !post(r) {
		s.render(w, r, "welcome", "Новий простір", nil)
		return
	}
	ws, err := s.app.CreateWS(workspace.Config{Name: r.FormValue("name"), Visibility: r.FormValue("visibility"), VersionFloor: r.FormValue("floor"),
		FourEyes: r.FormValue("four_eyes") == "on"}, who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/?ws="+url.QueryEscape(ws.Cfg.Name)+"&flash="+url.QueryEscape("простір створено"), http.StatusSeeOther)
}

type keyData struct{ Kind, Ref, Pub, SeedOnce string }

func (s *Server) keyNew(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	kind, ref := r.FormValue("kind"), r.FormValue("ref")
	pub, seed, err := s.app.NewKey(ws, kind, ref, who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "key", "Новий ключ", keyData{Kind: kind, Ref: ref, Pub: pub, SeedOnce: seed})
}

func (s *Server) targetAdd(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	t := workspace.Target{ID: r.FormValue("id"), Kind: r.FormValue("kind"), Path: r.FormValue("path"), Repo: r.FormValue("repo"),
		Branch: r.FormValue("branch"), Token: r.FormValue("token"), PCsURL: r.FormValue("pcs_url"), PCsToken: r.FormValue("pcs_token"),
		PCsTokenSupported: r.FormValue("pcs_token_supported") == "on", Public: r.FormValue("public") == "on",
		Forge: r.FormValue("forge"), Project: r.FormValue("project"), API: r.FormValue("api"),
		CommitTree: r.FormValue("commit_tree") == "on", DownloadURL: r.FormValue("download_url")}
	for _, id := range strings.FieldsFunc(r.FormValue("editions"), func(c rune) bool { return c == ',' || c == ' ' }) {
		t.Editions = append(t.Editions, id)
	}
	if err := s.app.SaveTarget(ws, t, who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/", "ціль "+t.ID+" збережено")
}

// ---------------------------------------------------------------- бібліотека

type libData struct {
	Q, Origin, Kind string
	Rules           []store.Rule
	Total, Page     int
	Pages           int
	Dropped         map[string]workspace.Decision
	Origins         []string
}

func (s *Server) library(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := libData{Q: r.FormValue("q"), Origin: r.FormValue("origin"), Kind: r.FormValue("kind"), Dropped: map[string]workspace.Decision{}}
	d.Page, _ = strconv.Atoi(r.FormValue("page"))
	const per = 100
	d.Rules, d.Total, err = s.app.DB.FindRules(store.RuleQuery{WS: ws.Cfg.Name, Text: d.Q, Origin: d.Origin, Kind: d.Kind, Limit: per, Offset: d.Page * per})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Pages = (d.Total + per - 1) / per
	dec, _ := ws.Decisions()
	for _, x := range dec {
		d.Dropped[x.Source+"|"+x.File+"|"+x.Rule] = x
	}
	srcs, _ := ws.Sources()
	for _, x := range srcs {
		d.Origins = append(d.Origins, x.ID)
	}
	d.Origins = append(d.Origins, "org", "critical")
	s.render(w, r, "library", "Бібліотека", d)
}

type ruleData struct {
	Origin, File, Name, Text string
	Rule                     *store.Rule
	Decision                 *workspace.Decision
	Own                      bool
	History                  []hive.RuleHistoryLine
	Dropped                  string // відкинуте генератором: причина
}

func (s *Server) rule(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := ruleData{Origin: r.FormValue("origin"), File: r.FormValue("file"), Name: r.FormValue("name")}
	d.Own = d.Origin == "org" || d.Origin == "critical"
	d.History, _ = s.app.RuleHistory(ws, d.Name)
	if d.Origin == "vendor" {
		// відкинуте генератором: тексту в пакеті немає — причина і історія
		rs, _, _ := s.app.DB.FindRules(store.RuleQuery{WS: ws.Cfg.Name, Origin: "vendor", Text: d.Name, Limit: 50})
		for _, x := range rs {
			if x.Name == d.Name && x.File == d.File {
				d.Dropped = x.Meta["hive_dropped"]
			}
		}
		s.render(w, r, "rule", d.Name, d)
		return
	}
	if d.Text, err = s.app.RuleText(ws, d.Origin, d.File, d.Name); err != nil {
		s.fail(w, r, err)
		return
	}
	rs, _, _ := s.app.DB.FindRules(store.RuleQuery{WS: ws.Cfg.Name, Text: d.Name, Origin: d.Origin, Limit: 50})
	for i := range rs {
		if rs[i].File == d.File && rs[i].Name == d.Name {
			d.Rule = &rs[i]
		}
	}
	dec, _ := ws.Decisions()
	for i := range dec {
		if dec[i].Source == d.Origin && dec[i].File == d.File && dec[i].Rule == d.Name {
			d.Decision = &dec[i]
		}
	}
	s.render(w, r, "rule", d.Name, d)
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	d := workspace.Decision{Source: r.FormValue("origin"), File: r.FormValue("file"), Rule: r.FormValue("name"), Status: r.FormValue("status"), Reason: r.FormValue("reason")}
	if err := s.app.Decide(ws, d, who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/rule", "рішення збережено", "origin", d.Source, "file", d.File, "name", d.Rule)
}

// ---------------------------------------------------------------- власні правила

type ownData struct {
	Org, Critical []string
	Tests         map[string]int
}

func (s *Server) own(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := ownData{Org: ws.OwnFiles("org"), Critical: ws.OwnFiles("critical"), Tests: map[string]int{}}
	tests, _ := ws.Tests()
	for _, t := range tests {
		d.Tests[t.Scope]++
	}
	s.render(w, r, "own", "Власні правила", d)
}

type editData struct {
	Kind, Name, Text string
	New              bool
	Findings         []checks.Finding
	Saved            bool
	Tests            []workspace.TestCase
	Rules            []string
	Results          []checks.TestResult
	Template         string
}

const tplMalware = `rule ORG_Mal_FAMILY_YYYYMM
{
    meta:
        description = "Що це за ШПЗ і де знайдено (інцидент, дата)"
        author      = "служба безпеки"
        date        = "DATE"
        reference   = "номер інциденту / звіт"
        hash        = "sha256 зразка"
    strings:
        $s1 = "унікальний рядок зі зразка" ascii wide
        $s2 = { 4D 5A 90 00 }            // байти: hex
        $s3 = /https?:\/\/[a-z0-9.-]{4,60}\/gate\.php/ nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($s*)
}
`

const tplCritical = `rule ORG_CATEGORY_WHAT
{
    meta:
        description = "Який вид критичної інформації (з переліку організації)"
        category    = "classified"
        owner       = "хто відповідає за цей вид інформації"
        author      = "служба безпеки"
        date        = "DATE"
    strings:
        // текст нормалізований: малі літери, один пробіл; кирилиця — 2 байти на літеру
        $a = /службов[^ ]{0,12} користуванн[^ ]{0,8}/
        $b = "для внутрішнього використання"
    condition:
        any of them
}
`

func (s *Server) ownEdit(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := editData{Kind: r.FormValue("kind"), Name: r.FormValue("name"), Template: r.FormValue("template")}
	if d.Kind != "org" && d.Kind != "critical" {
		d.Kind = "org"
	}
	if d.Name == "" {
		d.New = true
		switch d.Template {
		case "malware":
			d.Kind, d.Text = "org", strings.ReplaceAll(tplMalware, "DATE", time.Now().Format("2006-01-02"))
		case "critical":
			d.Kind, d.Text = "critical", strings.ReplaceAll(tplCritical, "DATE", time.Now().Format("2006-01-02"))
		}
	} else {
		b, err := os.ReadFile(ws.OwnPath(d.Kind, d.Name))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		d.Text = string(b)
		if d.Kind == "critical" {
			d.Findings = checks.LintCritical(d.Text)
		}
	}
	s.fillTests(ws, &d)
	s.render(w, r, "edit", "Редактор", d)
}

func (s *Server) fillTests(ws *workspace.WS, d *editData) {
	names := map[string]bool{}
	for _, x := range yaraparse.Parse(d.Text).Rules {
		names[x.Name] = true
		d.Rules = append(d.Rules, x.Name)
	}
	tests, _ := ws.Tests()
	for _, t := range tests {
		if t.Scope == "rule" && names[t.Rule] {
			d.Tests = append(d.Tests, t)
		}
	}
}

func (s *Server) ownSave(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	d := editData{Kind: r.FormValue("kind"), Name: strings.TrimSpace(r.FormValue("name")), Text: strings.ReplaceAll(r.FormValue("text"), "\r\n", "\n")}
	d.New = r.FormValue("new") == "1"
	if d.Name != "" && !strings.HasSuffix(d.Name, ".yar") {
		d.Name += ".yar"
	}
	if d.New {
		if _, err := os.Stat(ws.OwnPath(d.Kind, d.Name)); err == nil {
			d.Findings = []checks.Finding{{Level: "error", Text: "файл " + d.Name + " уже є — відкрийте його або оберіть інше ім'я"}}
			s.fillTests(ws, &d)
			s.render(w, r, "edit", "Редактор", d)
			return
		}
	}
	if r.FormValue("action") == "check" {
		d.Findings, err = s.app.OwnRuleCheck(ws, d.Kind, d.Name, d.Text)
	} else {
		d.Findings, d.Saved, err = s.app.SaveOwnRule(ws, d.Kind, d.Name, d.Text, who(r))
		if d.Saved {
			d.New = false
		}
	}
	if err != nil {
		d.Findings = append(d.Findings, checks.Finding{Level: "error", Text: err.Error()})
	}
	s.fillTests(ws, &d)
	s.render(w, r, "edit", "Редактор", d)
}

func (s *Server) ownDelete(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	if err := s.app.DeleteOwnRule(ws, r.FormValue("kind"), r.FormValue("name"), who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/own", "файл прибрано")
}

func (s *Server) testAdd(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	f, h, err := r.FormFile("file")
	if err != nil {
		s.fail(w, r, fmt.Errorf("choose a file: %w", err))
		return
	}
	defer f.Close()
	tc := workspace.TestCase{Scope: "rule", Rule: r.FormValue("rule"), Expect: r.FormValue("expect"), Name: h.Filename, Kind: r.FormValue("sample_kind")}
	if err := s.app.AddTest(ws, tc, f, who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/own/edit", "тестовий файл додано (у сховище, не в git)", "kind", r.FormValue("kind"), "name", r.FormValue("name"))
}

func (s *Server) testRemove(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	if err := s.app.RemoveTest(ws, "rule", r.FormValue("rule"), r.FormValue("blob"), who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/own/edit", "тест прибрано", "kind", r.FormValue("kind"), "name", r.FormValue("name"))
}

func (s *Server) testRun(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	d := editData{Kind: r.FormValue("kind"), Name: r.FormValue("name")}
	b, err := os.ReadFile(ws.OwnPath(d.Kind, d.Name))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.Text = string(b)
	if d.Results, err = s.app.RunTests(ws, d.Kind, d.Name); err != nil {
		d.Findings = []checks.Finding{{Level: "error", Text: err.Error()}}
	}
	s.fillTests(ws, &d)
	s.render(w, r, "edit", "Редактор", d)
}

// ---------------------------------------------------------------- списки

type listsData struct {
	White, Black *orglists.List
	Warn         map[string][]string // "white:3" -> зауваження
	All          []lists.Warning
	Targets      []workspace.Target
	Confirm      *workspace.Target
}

func (s *Server) listsPage(w http.ResponseWriter, r *http.Request, ws *workspace.WS, confirm *workspace.Target) {
	d := listsData{Warn: map[string][]string{}}
	var err error
	d.White, d.Black, d.All, err = s.app.Lists(ws)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, x := range d.All {
		k := fmt.Sprintf("%s:%d", x.Kind, x.Index)
		d.Warn[k] = append(d.Warn[k], x.Text)
	}
	for _, t := range ws.Cfg.Targets {
		if strings.HasPrefix(t.Kind, "lists-") {
			d.Targets = append(d.Targets, t)
		}
	}
	d.Confirm = confirm
	s.render(w, r, "lists", "Списки", d)
}

func (s *Server) lists(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.listsPage(w, r, ws, nil)
}

func (s *Server) listsAdd(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	kind := r.FormValue("kind")
	white, black, _, err := s.app.Lists(ws)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	l := map[string]*orglists.List{"white": white, "black": black}[kind]
	if l == nil {
		s.fail(w, r, fmt.Errorf("kind %q", kind))
		return
	}
	e := orglists.Entry{Path: strings.TrimSpace(r.FormValue("path")), LnkTarget: strings.TrimSpace(r.FormValue("lnk_target")),
		SHA256: strings.TrimSpace(r.FormValue("sha256")), Comment: strings.TrimSpace(r.FormValue("comment")),
		Added: time.Now().Format("2006-01-02"), By: hive.Who()}
	if f, h, err := r.FormFile("file"); err == nil {
		// хеш файлу; сам файл ніде не зберігається
		sha, err := lists.SHA256(io.LimitReader(f, 4<<30))
		f.Close()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		e.SHA256 = sha
		if e.Comment == "" {
			e.Comment = h.Filename
		}
	}
	l.Entries = append(l.Entries, e)
	if err := s.app.SaveList(ws, kind, l, "add "+entryText(e), who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lists", "запис додано")
}

func entryText(e orglists.Entry) string {
	var p []string
	for _, x := range []string{e.Path, e.LnkTarget, e.SHA256} {
		if x != "" {
			p = append(p, x)
		}
	}
	return strings.Join(p, " + ")
}

func (s *Server) listsRemove(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	kind := r.FormValue("kind")
	i, _ := strconv.Atoi(r.FormValue("index"))
	white, black, _, _ := s.app.Lists(ws)
	l := map[string]*orglists.List{"white": white, "black": black}[kind]
	if l == nil || i < 0 || i >= len(l.Entries) {
		s.fail(w, r, fmt.Errorf("no entry %d", i))
		return
	}
	e := l.Entries[i]
	l.Entries = append(l.Entries[:i], l.Entries[i+1:]...)
	if err := s.app.SaveList(ws, kind, l, "remove "+entryText(e), who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lists", "запис прибрано")
}

func (s *Server) listsPublish(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := ws.Target(r.FormValue("target"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !post(r) || strings.TrimSpace(r.FormValue("confirm")) != "yes" {
		s.listsPage(w, r, ws, t) // сторінка підтвердження
		return
	}
	res, err := s.app.PublishLists(ws, t.ID, who(r), nil)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lists", "списки підписано й опубліковано: "+res.Location)
}

// ---------------------------------------------------------------- джерела та імпорт

type sourcesData struct {
	Sources []workspace.Source
	Preview *pinPreview
}

type pinPreview struct {
	ID, Ref, Commit string
	Changes         []string
}

func (s *Server) sources(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := sourcesData{}
	d.Sources, _ = ws.Sources()
	s.render(w, r, "sources", "Джерела", d)
}

func (s *Server) sourcesAdd(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	src := workspace.Source{ID: r.FormValue("id"), URL: r.FormValue("url"), Ref: r.FormValue("ref"), Commit: r.FormValue("commit"),
		Token: r.FormValue("token"), License: r.FormValue("license")}
	if err := s.app.AddSource(ws, src, who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/sources", "джерело додано й закріплено")
}

func (s *Server) sourcesPin(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id := r.FormValue("id")
	if post(r) && r.FormValue("commit") != "" {
		if err := s.app.Pin(ws, id, r.FormValue("commit"), who(r)); err != nil {
			s.fail(w, r, err)
			return
		}
		s.back(w, r, "/sources", "джерело закріплено на новому коміті")
		return
	}
	if !post(r) {
		s.back(w, r, "/sources", "")
		return
	}
	commit, ch, err := s.app.PinPreview(ws, id, r.FormValue("ref"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := sourcesData{Preview: &pinPreview{ID: id, Ref: r.FormValue("ref"), Commit: commit}}
	for _, c := range ch {
		d.Preview.Changes = append(d.Preview.Changes, c.Status+" "+c.Path)
	}
	d.Sources, _ = ws.Sources()
	s.render(w, r, "sources", "Джерела", d)
}

func (s *Server) importCritical(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	nr, nt, err := s.app.ImportCritical(ws, r.FormValue("repo"), who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/sources", fmt.Sprintf("критичні правила: %d файлів, тестових документів: %d", nr, nt))
}

func (s *Server) importList(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer f.Close()
	tmp, err := os.CreateTemp("", "hive-list-*.json")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer os.Remove(tmp.Name())
	io.Copy(tmp, io.LimitReader(f, lists.MaxSize+1))
	tmp.Close()
	n, err := s.app.ImportList(ws, r.FormValue("kind"), tmp.Name(), who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lists", fmt.Sprintf("імпортовано %d записів", n))
}

// ---------------------------------------------------------------- релізи

type releasesData struct {
	Releases []store.Release
	Pubs     []store.Publication
	Next     string
	Floor    string
	NextErr  string
}

func (s *Server) releases(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := releasesData{}
	d.Releases, _ = s.app.DB.Releases(ws.Cfg.Name)
	d.Pubs, _ = s.app.DB.Publications(ws.Cfg.Name)
	if d.Next, d.Floor, err = s.app.NextVersion(ws, "patch", false); err != nil {
		d.NextErr = err.Error()
	}
	s.render(w, r, "releases", "Релізи", d)
}

func (s *Server) build(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return
	}
	res, err := s.app.Build(ws, r.FormValue("bump"), r.FormValue("offline") != "on", who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/release", "зібрано "+res.Version, "v", res.Version)
}

type releaseData struct {
	Rel       *store.Release
	Report    *contract.Report
	Critical  *checks.SetResult
	Notes     []string
	Source    string
	Targets   []workspace.Target
	Confirm   *workspace.Target
	Pubs      []store.Publication
	Result    *publish.Result
	Err       string
	Lab       *releaseLab
	Approvals []store.Approval
	Editions  []hive.EditionBuild
	Plan      *hive.EditionPlan // підтвердження публікації в ціль редакцій
}

type releaseLab struct {
	Required bool
	Run      *store.LabRun
}

func (s *Server) releaseData(ws *workspace.WS, v string) (*releaseData, error) {
	rel, err := s.app.DB.Release(ws.Cfg.Name, v)
	if err != nil {
		return nil, err
	}
	d := &releaseData{Rel: rel}
	var rep struct {
		Contract *contract.Report  `json:"contract"`
		Critical *checks.SetResult `json:"critical"`
		Notes    []string          `json:"notes"`
		Source   string            `json:"source"`
	}
	if err := json.Unmarshal([]byte(rel.Report), &rep); err == nil {
		d.Report, d.Critical, d.Notes, d.Source = rep.Contract, rep.Critical, rep.Notes, rep.Source
	}
	for _, t := range ws.Cfg.Targets {
		if t.Kind == "folder" || t.Kind == "mirror-branch" || t.Kind == "release" || hive.IsEditionsTarget(t) {
			d.Targets = append(d.Targets, t)
		}
	}
	d.Editions = s.app.ReleaseEditions(rel)
	d.Approvals, _ = s.app.DB.Approvals(ws.Cfg.Name, rel.Version, rel.PkgSHA)
	d.Lab = &releaseLab{Required: len(ws.Cfg.Lab.Sets) > 0}
	runs, _ := s.app.DB.LabRuns(ws.Cfg.Name)
	for i := range runs {
		if runs[i].CandSHA == rel.PkgSHA {
			d.Lab.Run = &runs[i]
			break
		}
	}
	all, _ := s.app.DB.Publications(ws.Cfg.Name)
	for _, p := range all {
		if (p.What == "rules" || p.What == "editions") && p.Version == v {
			d.Pubs = append(d.Pubs, p)
		}
	}
	return d, nil
}

func (s *Server) release(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.releaseData(ws, r.FormValue("v"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "release", d.Rel.Version, d)
}

func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v := r.FormValue("v")
	d, err := s.releaseData(ws, v)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := ws.Target(r.FormValue("target"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if hive.IsEditionsTarget(*t) {
		plan, err := s.app.PlanEditions(ws, d.Rel, t.ID)
		if err != nil {
			d.Err = err.Error()
			w.WriteHeader(http.StatusBadRequest)
			s.render(w, r, "release", v, d)
			return
		}
		d.Plan = plan
	}
	if !post(r) || strings.TrimSpace(r.FormValue("confirm")) != v || (d.Plan != nil && d.Plan.NeedsAck && r.FormValue("ack_public") != "on") {
		d.Confirm = t // сторінка підтвердження: людина вводить версію (і для публічної цілі — окремо погоджується)
		s.render(w, r, "release", v, d)
		return
	}
	var res *publish.Result
	var perr error
	if d.Plan != nil {
		res, perr = s.app.PublishEditions(ws, v, t.ID, who(r), r.FormValue("ack_public") == "on", nil)
	} else {
		res, perr = s.app.Publish(ws, v, t.ID, who(r), nil)
	}
	d, _ = s.releaseData(ws, v)
	d.Result = res
	if perr != nil {
		d.Err = perr.Error()
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, "release", v, d)
		return
	}
	s.back(w, r, "/release", "опубліковано "+v+" → "+t.ID, "v", v)
}

func sandboxName() string {
	if k := yaraexec.SandboxKind(); k != "" {
		return k
	}
	return "немає (yara запускається без пісочниці ОС)"
}

// docs — сторінка документації.
func (s *Server) docs(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "docs", "Документація", nil)
}

// docAnchor — розділ документації для сторінки (кнопка «? довідка» у верхній смузі).
func docAnchor(path string) string {
	switch {
	case path == "/":
		return "start"
	case path == "/sources" || strings.HasPrefix(path, "/vendor"):
		return "sources"
	case path == "/library" || path == "/rule" || path == "/decide":
		return "library"
	case strings.HasPrefix(path, "/own"):
		return "own"
	case strings.HasPrefix(path, "/lists"):
		return "lists"
	case strings.HasPrefix(path, "/dupes"):
		return "dupes"
	case strings.HasPrefix(path, "/lab"):
		return "lab"
	case strings.HasPrefix(path, "/editions"):
		return "editions"
	case path == "/releases" || path == "/release" || path == "/release/download" || path == "/publish" || path == "/build" || path == "/approve":
		return "release"
	case path == "/settings" || path == "/keys" || path == "/users" || path == "/ws/create":
		return "admin"
	case path == "/profile":
		return "roles"
	}
	return "start"
}
