// Package hive — дії Anthophila_Hive (той самий код для CLI і веб-інтерфейсу): простори, ключі, джерела, імпорт,
// власні правила й тести, рішення, списки, збирання, публікація, відтворення релізу.
package hive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/auth"
	"github.com/rifatismailov/Anthophila_Hive/internal/blobs"
	"github.com/rifatismailov/Anthophila_Hive/internal/build"
	"github.com/rifatismailov/Anthophila_Hive/internal/checks"
	"github.com/rifatismailov/Anthophila_Hive/internal/contract"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/orglists"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/lists"
	"github.com/rifatismailov/Anthophila_Hive/internal/publish"
	"github.com/rifatismailov/Anthophila_Hive/internal/secrets"
	"github.com/rifatismailov/Anthophila_Hive/internal/source"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
	"gopkg.in/yaml.v3"
)

// Version — версія Hive (записується в .lock релізу).
const Version = "0.3.0"

// App — дані Hive в одній теці.
type App struct {
	Data   string
	DB     *store.DB
	Blobs  blobs.Store
	Cache  source.Cache
	Tools  yaraexec.Tools
	Unlock secrets.Unlock // пароль сховища ключів / бази KeePassXC на час однієї дії (CLI — з терміналу, веб — з форми)
	Keys   secrets.Keystore
	Auth   *auth.Store
}

// DefaultData — ~/.anthophila-hive або HIVE_DATA. Поза будь-яким git-репозиторієм: там зразки й документи.
func DefaultData() string {
	if d := os.Getenv("HIVE_DATA"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".anthophila-hive")
}

// Open — відкрити (створити) теку даних.
func Open(data string, tools yaraexec.Tools) (*App, error) {
	if err := os.MkdirAll(data, 0o700); err != nil {
		return nil, err
	}
	db, err := store.Open(filepath.Join(data, "hive.db"))
	if err != nil {
		return nil, err
	}
	a := &App{Data: data, DB: db, Blobs: blobs.Store{Root: filepath.Join(data, "blobs")},
		Cache: source.Cache{Root: filepath.Join(data, "cache", "sources")}, Tools: tools,
		Keys: secrets.Keystore{Dir: filepath.Join(data, "keys")}}
	secrets.UseKeystore(&a.Keys)
	if a.Auth, err = auth.Open(db.DB); err != nil {
		return nil, err
	}
	// індекс бібліотеки старішого формату (без хешів дублікатів) — перебудувати
	for _, name := range a.Workspaces() {
		if n, _ := db.StaleRules(name); n > 0 {
			if w, err := a.WS(name); err == nil {
				if err := a.Reindex(w); err != nil {
					return nil, fmt.Errorf("reindex %s: %w", name, err)
				}
			}
		}
	}
	return a, nil
}

// Who — хто діє (CLI: користувач ОС).
func Who() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "unknown"
}

func (a *App) wsDir(name string) string { return filepath.Join(a.Data, "workspaces", name) }

// Workspaces — назви просторів.
func (a *App) Workspaces() []string {
	ents, _ := os.ReadDir(filepath.Join(a.Data, "workspaces"))
	var out []string
	for _, e := range ents {
		if _, err := os.Stat(filepath.Join(a.wsDir(e.Name()), "hive.yaml")); err == nil {
			out = append(out, e.Name())
		}
	}
	return out
}

// WS — відкрити простір ("" — єдиний наявний).
func (a *App) WS(name string) (*workspace.WS, error) {
	if name == "" {
		all := a.Workspaces()
		if len(all) != 1 {
			return nil, fmt.Errorf("%d workspaces (%s): choose one with --ws", len(all), strings.Join(all, ", "))
		}
		name = all[0]
	}
	if !workspace.ValidID(name) {
		return nil, fmt.Errorf("workspace %q: no such workspace", name)
	}
	return workspace.Open(a.wsDir(name))
}

// CreateWS — новий простір.
func (a *App) CreateWS(cfg workspace.Config, who string) (*workspace.WS, error) {
	if cfg.VersionFloor != "" && !manifest.ValidVersion(cfg.VersionFloor) {
		return nil, fmt.Errorf("version floor %q is not vX.Y.Z", cfg.VersionFloor)
	}
	w, err := workspace.Create(a.wsDir(cfg.Name), cfg)
	if err == nil {
		a.DB.Audit(cfg.Name, who, "create", cfg.Visibility)
	}
	return w, err
}

func (a *App) commit(w *workspace.WS, msg, who string) error {
	_, err := w.Commit(msg, who)
	return err
}

// ---------------------------------------------------------------- ключі

// NewKey — новий ключ ed25519 для правил (kind "rules") або списків ("lists"). Секрет кладеться за посиланням ref:
// keychain:… — у системне сховище; env:… / keepassxc:… — Hive його не зберігає: seed повертається ОДИН раз, щоб
// людина поклала його у сховище сама. Публічна частина записується в hive.yaml.
func (a *App) NewKey(w *workspace.WS, kind, ref, who string) (pub, seedOnce string, err error) {
	r, err := secrets.Parse(ref)
	if err != nil {
		return "", "", err
	}
	seed, pub, err := manifest.NewSeed()
	if err != nil {
		return "", "", err
	}
	switch r.Kind {
	case "keychain":
		if err := secrets.StoreKeychain(r.Name, r.Entry, []byte(seed)); err != nil {
			return "", "", err
		}
	case "hive":
		if a.Unlock == nil {
			return "", "", fmt.Errorf("the keystore passphrase is needed to store the key")
		}
		pass, err := a.Unlock("hive")
		if err != nil {
			return "", "", err
		}
		err = a.Keys.Put(r.Name, "ed25519-seed", pub, []byte(seed), pass, who, false)
		secrets.Wipe(pass)
		if err != nil {
			return "", "", err
		}
	default:
		seedOnce = seed
	}
	k := workspace.Key{Public: pub, Secret: ref}
	switch kind {
	case "rules":
		k.Previous = prevKeys(w.Cfg.RulesKey)
		w.Cfg.RulesKey = k
	case "lists":
		k.Previous = prevKeys(w.Cfg.ListsKey)
		w.Cfg.ListsKey = k
	default:
		return "", "", fmt.Errorf("key kind %q: rules or lists", kind)
	}
	if err := w.SaveConfig(); err != nil {
		return "", "", err
	}
	pk, _ := manifest.ParseKey(pub)
	a.DB.Audit(w.Cfg.Name, who, "key", fmt.Sprintf("new %s key %s (%s)", kind, manifest.KeyID(pk), ref))
	return pub, seedOnce, a.commit(w, "new "+kind+" signing key "+manifest.KeyID(pk), who)
}

func (a *App) seed(k workspace.Key, what string) (string, error) {
	if k.Public == "" || k.Secret == "" {
		return "", fmt.Errorf("the workspace has no %s signing key (hive key new)", what)
	}
	b, err := secrets.Get(k.Secret, a.Unlock)
	if err != nil {
		return "", err
	}
	s := string(b)
	secrets.Wipe(b)
	pub, err := manifest.PublicKeyOf(s)
	if err != nil {
		return "", fmt.Errorf("%s key %s: %w", what, k.Secret, err)
	}
	if pub != k.Public {
		return "", fmt.Errorf("%s key %s does not match the public key of the workspace", what, k.Secret)
	}
	return s, nil
}

func (a *App) auth(ref string) (*gitx.Auth, error) {
	if ref == "" {
		return nil, nil
	}
	b, err := secrets.Get(ref, a.Unlock)
	if err != nil {
		return nil, err
	}
	return &gitx.Auth{Token: string(b)}, nil
}

// ---------------------------------------------------------------- джерела

// AddSource — додати джерело: завантажити, закріпити ref (або заданий коміт), проіндексувати.
func (a *App) AddSource(w *workspace.WS, s workspace.Source, who string) error {
	if s.Kind == "" {
		s.Kind = "git"
	}
	if s.Role == "" {
		s.Role = "rules-tree"
	}
	if s.Role != "rules-tree" {
		return fmt.Errorf("source role %q: MVP-a supports rules-tree only", s.Role)
	}
	srcs, _ := w.Sources()
	for _, x := range srcs {
		if x.ID != s.ID && x.Role == "rules-tree" {
			return fmt.Errorf("the workspace already has a rules tree (%s): MVP-a builds from one", x.ID)
		}
	}
	if s.Ref == "" {
		s.Ref = "HEAD"
	}
	auth, err := a.auth(s.Token)
	if err != nil {
		return err
	}
	r, err := a.Cache.Fetch(s, auth)
	if err != nil {
		return err
	}
	want := s.Commit
	if want == "" {
		want = s.Ref
	}
	c, err := r.Resolve(want)
	if err != nil || c == "" {
		return fmt.Errorf("source %s: %q is not a commit there", s.ID, want)
	}
	s.Commit, s.Pinned = c, time.Now().UTC().Format(time.RFC3339)
	if err := w.SaveSource(s); err != nil {
		return err
	}
	if err := a.commit(w, fmt.Sprintf("source %s pinned at %s", s.ID, c[:8]), who); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "source", fmt.Sprintf("%s %s @ %s", s.ID, s.URL, c[:8]))
	return a.Reindex(w)
}

// PinPreview — що зміниться, якщо закріпити ref (завантажує джерело).
func (a *App) PinPreview(w *workspace.WS, id, ref string) (string, []source.Change, error) {
	s, err := a.source(w, id)
	if err != nil {
		return "", nil, err
	}
	auth, err := a.auth(s.Token)
	if err != nil {
		return "", nil, err
	}
	r, err := a.Cache.Fetch(*s, auth)
	if err != nil {
		return "", nil, err
	}
	c, err := r.Resolve(ref)
	if err != nil || c == "" {
		return "", nil, fmt.Errorf("%q is not a commit of %s", ref, id)
	}
	ch, err := a.Cache.Diff(*s, s.Commit, c)
	return c, ch, err
}

// Pin — закріпити джерело на коміті.
func (a *App) Pin(w *workspace.WS, id, commit, who string) error {
	s, err := a.source(w, id)
	if err != nil {
		return err
	}
	r, err := a.Cache.Repo(*s)
	if err != nil {
		return err
	}
	c, err := r.Resolve(commit)
	if err != nil || c == "" {
		return fmt.Errorf("%q is not a commit of %s", commit, id)
	}
	old := s.Commit
	s.Commit, s.Pinned = c, time.Now().UTC().Format(time.RFC3339)
	if err := w.SaveSource(*s); err != nil {
		return err
	}
	if err := a.commit(w, fmt.Sprintf("source %s: %s -> %s", id, short(old), c[:8]), who); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "pin", fmt.Sprintf("%s %s -> %s", id, short(old), c[:8]))
	return a.Reindex(w)
}

func (a *App) source(w *workspace.WS, id string) (*workspace.Source, error) {
	srcs, err := w.Sources()
	if err != nil {
		return nil, err
	}
	for i := range srcs {
		if srcs[i].ID == id {
			return &srcs[i], nil
		}
	}
	return nil, fmt.Errorf("no source %q", id)
}

func (a *App) rulesTree(w *workspace.WS) (*workspace.Source, error) {
	srcs, err := w.Sources()
	if err != nil {
		return nil, err
	}
	for i := range srcs {
		if srcs[i].Role == "rules-tree" {
			return &srcs[i], nil
		}
	}
	return nil, fmt.Errorf("the workspace has no rules tree source yet (hive source add)")
}

// Reindex — індекс бібліотеки: правила джерела на закріпленому коміті + власні.
func (a *App) Reindex(w *workspace.WS) error {
	srcs, err := w.Sources()
	if err != nil {
		return err
	}
	for _, s := range srcs {
		if s.Role == "rules-tree" {
			if done, err := a.indexVendor(w, s); err != nil {
				return err
			} else if done {
				continue
			}
		}
		tmp, err := os.MkdirTemp("", "hive-index-")
		if err != nil {
			return err
		}
		err = a.Cache.Extract(s, tmp)
		if err == nil {
			var rules []store.Rule
			if rules, err = source.Index(tmp, s.ID, ""); err == nil {
				err = a.DB.ReplaceRules(w.Cfg.Name, s.ID, rules)
			}
		}
		os.RemoveAll(tmp)
		if err != nil {
			return err
		}
	}
	return a.ReindexOwn(w)
}

// ReindexOwn — індекс лише власних правил (швидко: після збереження власного файлу).
func (a *App) ReindexOwn(w *workspace.WS) error {
	for _, x := range []struct{ origin, dir, prefix string }{{"org", filepath.Join(w.Dir, "rules", "org"), "org/"}, {"critical", filepath.Join(w.Dir, "critical"), "critical/"}} {
		rules, err := source.Index(x.dir, x.origin, x.prefix)
		if err != nil {
			return err
		}
		if err := a.DB.ReplaceRules(w.Cfg.Name, x.origin, rules); err != nil {
			return err
		}
	}
	return nil
}

// RuleText — текст правила з бібліотеки (джерело на закріпленому коміті або власний файл).
func (a *App) RuleText(w *workspace.WS, origin, file, name string) (string, error) {
	var src []byte
	switch origin {
	case "org":
		b, err := os.ReadFile(w.OwnPath("org", strings.TrimPrefix(file, "org/")))
		if err != nil {
			return "", err
		}
		src = b
	case "critical":
		b, err := os.ReadFile(w.OwnPath("critical", strings.TrimPrefix(file, "critical/")))
		if err != nil {
			return "", err
		}
		src = b
	default:
		s, err := a.source(w, origin)
		if err != nil {
			return "", err
		}
		r, err := a.Cache.Repo(*s)
		if err != nil {
			return "", err
		}
		if src, err = r.Show(s.Commit, file); err != nil || src == nil {
			return "", fmt.Errorf("%s: no %s at %s", origin, file, short(s.Commit))
		}
	}
	for _, r := range yaraparse.Parse(string(src)).Rules {
		if r.Name == name {
			return strings.TrimLeft(r.Text(string(src)), "\r\n"), nil
		}
	}
	return "", fmt.Errorf("no rule %s in %s", name, file)
}

// Decide — рішення по правилу джерела (status "drop" + причина; "" — знову брати).
func (a *App) Decide(w *workspace.WS, d workspace.Decision, who string) error {
	d.By = who
	if err := w.SetDecision(d); err != nil {
		return err
	}
	verb := "take"
	if d.Status == "drop" {
		verb = "drop: " + d.Reason
	}
	a.DB.Audit(w.Cfg.Name, who, "decision", fmt.Sprintf("%s %s:%s %s", d.Source, d.File, d.Rule, verb))
	return a.commit(w, fmt.Sprintf("%s %s (%s)", map[bool]string{true: "drop", false: "take"}[d.Status == "drop"], d.Rule, d.File), who)
}

// ---------------------------------------------------------------- імпорт

// ImportCritical — критичні правила й тести з чекауту docscan-critical: critical/*.yar → простір, tests/match і
// tests/no-match → сховище файлів (у git — лише sha256).
func (a *App) ImportCritical(w *workspace.WS, repo, who string) (nRules, nTests int, err error) {
	names, _ := filepath.Glob(filepath.Join(repo, "critical", "*"))
	for _, p := range names {
		n := filepath.Base(p)
		if strings.HasPrefix(n, ".") {
			continue
		}
		if !contract.CriticalNameRe.MatchString(n) {
			return 0, 0, fmt.Errorf("critical/%s: not NAME.yar", n)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return 0, 0, err
		}
		if err := os.WriteFile(w.OwnPath("critical", n), b, 0o644); err != nil {
			return 0, 0, err
		}
		nRules++
	}
	tests, _ := w.Tests()
	for _, exp := range []string{"match", "no-match"} {
		root := filepath.Join(repo, "tests", exp)
		err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || strings.HasPrefix(fi.Name(), ".") {
				return nil
			}
			sha, _, err := a.Blobs.PutFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			tests = append(tests, workspace.TestCase{Scope: "critical", Expect: exp, Blob: sha, Name: filepath.ToSlash(rel), Kind: "document",
				Added: time.Now().UTC().Format("2006-01-02"), By: who})
			nTests++
			return nil
		})
		if err != nil {
			return 0, 0, err
		}
	}
	if err := w.SaveTests(tests); err != nil {
		return 0, 0, err
	}
	if err := a.commit(w, fmt.Sprintf("import critical rules (%d files) and %d test documents from %s", nRules, nTests, filepath.Base(repo)), who); err != nil {
		return 0, 0, err
	}
	a.DB.Audit(w.Cfg.Name, who, "import", fmt.Sprintf("critical: %d files, %d tests", nRules, nTests))
	return nRules, nTests, a.ReindexOwn(w)
}

// ImportList — список з файлу (перевірка orglists.Parse; serial не переноситься: його ставить підпис).
func (a *App) ImportList(w *workspace.WS, kind, path, who string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	l, err := orglists.Parse(b, kind)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	if err := lists.Save(filepath.Join(w.Dir, "lists"), kind, l); err != nil {
		return 0, err
	}
	a.DB.Audit(w.Cfg.Name, who, "import", fmt.Sprintf("%s list: %d entries", kind, len(l.Entries)))
	return len(l.Entries), a.commit(w, fmt.Sprintf("import %s list (%d entries)", kind, len(l.Entries)), who)
}

// ---------------------------------------------------------------- власні правила

var ownNameRe = contract.CriticalNameRe

// OwnRuleCheck — лінтер (критичні) + компіляція DocScan; конфлікт назв з бібліотекою.
func (a *App) OwnRuleCheck(w *workspace.WS, kind, name, text string) ([]checks.Finding, error) {
	if !ownNameRe.MatchString(name) {
		return nil, fmt.Errorf("file name %q: NAME.yar of A-Z a-z 0-9 _ - .", name)
	}
	var fs []checks.Finding
	if kind == "critical" {
		fs = append(fs, checks.LintCritical(text)...)
	}
	// назви
	for _, r := range yaraparse.Parse(text).Rules {
		others, _ := a.DB.RulesNamed(w.Cfg.Name, r.Name)
		for _, o := range others {
			sameFile := (o.Origin == kind && strings.TrimPrefix(strings.TrimPrefix(o.File, "org/"), "critical/") == name)
			if sameFile {
				continue
			}
			clash := (kind == "critical" && o.Kind == "critical") || (kind == "org" && o.Kind != "critical")
			if clash {
				fs = append(fs, checks.Finding{Line: r.Line, Level: "error", Text: fmt.Sprintf("назва %s уже є в %s (%s) — назви мають бути унікальні", r.Name, o.File, o.Origin)})
			}
		}
	}
	if !a.Tools.Configured() {
		fs = append(fs, checks.Finding{Level: "warn", Text: "DocScan yara / yarac не задано — компіляцію не перевірено"})
		return fs, nil
	}
	other := map[string]string{}
	if kind == "critical" {
		for _, n := range w.OwnFiles("critical") {
			if b, err := os.ReadFile(w.OwnPath("critical", n)); err == nil {
				other[n] = string(b)
			}
		}
	}
	cf, err := checks.CompileOwn(a.Tools, kind, name, text, other)
	if err != nil {
		return nil, err
	}
	return append(cf, fs...), nil
}

// SaveOwnRule — зберегти власний файл правил, якщо в ньому немає помилок (простір завжди компілюється).
func (a *App) SaveOwnRule(w *workspace.WS, kind, name, text, who string) ([]checks.Finding, bool, error) {
	if kind != "org" && kind != "critical" {
		return nil, false, fmt.Errorf("kind %q: org or critical", kind)
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	fs, err := a.OwnRuleCheck(w, kind, name, text)
	if err != nil {
		return nil, false, err
	}
	if checks.HasErrors(fs) {
		return fs, false, nil
	}
	if err := os.WriteFile(w.OwnPath(kind, name), []byte(text), 0o644); err != nil {
		return nil, false, err
	}
	if err := a.commit(w, fmt.Sprintf("%s rules %s", kind, name), who); err != nil {
		return nil, false, err
	}
	a.DB.Audit(w.Cfg.Name, who, "rule", fmt.Sprintf("save %s/%s", kind, name))
	return fs, true, a.ReindexOwn(w)
}

// DeleteOwnRule — прибрати власний файл правил.
func (a *App) DeleteOwnRule(w *workspace.WS, kind, name, who string) error {
	if err := os.Remove(w.OwnPath(kind, name)); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "rule", fmt.Sprintf("delete %s/%s", kind, name))
	if err := a.commit(w, fmt.Sprintf("delete %s rules %s", kind, name), who); err != nil {
		return err
	}
	return a.ReindexOwn(w)
}

// AddTest — тестовий файл до правила (scope rule) або до набору критичних (scope critical). Файл — у сховище.
func (a *App) AddTest(w *workspace.WS, tc workspace.TestCase, r io.Reader, who string) error {
	if tc.Expect != "match" && tc.Expect != "no-match" {
		return fmt.Errorf("expect %q: match or no-match", tc.Expect)
	}
	if tc.Scope == "rule" && tc.Rule == "" {
		return fmt.Errorf("a rule test needs the rule name")
	}
	sha, _, err := a.Blobs.Put(r)
	if err != nil {
		return err
	}
	tc.Blob, tc.By, tc.Added = sha, who, time.Now().UTC().Format("2006-01-02")
	tc.Name = filepath.Base(strings.ReplaceAll(tc.Name, `\`, "/"))
	tests, _ := w.Tests()
	if err := w.SaveTests(append(tests, tc)); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "test", fmt.Sprintf("%s %s %s %s (%s)", tc.Scope, tc.Rule, tc.Expect, tc.Name, sha[:12]))
	return a.commit(w, fmt.Sprintf("test %s %s: %s", tc.Rule, tc.Expect, tc.Name), who)
}

// RemoveTest — прибрати тест (файл у сховищі лишається: його можуть використовувати інші тести).
func (a *App) RemoveTest(w *workspace.WS, scope, rule, blob, who string) error {
	tests, _ := w.Tests()
	var out []workspace.TestCase
	for _, t := range tests {
		if !(t.Scope == scope && t.Rule == rule && t.Blob == blob) {
			out = append(out, t)
		}
	}
	if err := w.SaveTests(out); err != nil {
		return err
	}
	return a.commit(w, "remove test "+blob[:12], who)
}

// RunTests — тести правил одного власного файлу (scope rule, правила цього файлу).
func (a *App) RunTests(w *workspace.WS, kind, name string) ([]checks.TestResult, error) {
	if !a.Tools.Configured() {
		return nil, fmt.Errorf("DocScan yara / yarac are not set")
	}
	b, err := os.ReadFile(w.OwnPath(kind, name))
	if err != nil {
		return nil, err
	}
	rules := map[string]bool{}
	for _, r := range yaraparse.Parse(string(b)).Rules {
		rules[r.Name] = true
	}
	tests, _ := w.Tests()
	tmp, err := os.MkdirTemp("", "hive-tests-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	var files []checks.TestFile
	for i, t := range tests {
		if t.Scope != "rule" || !rules[t.Rule] {
			continue
		}
		d := filepath.Join(tmp, fmt.Sprint(i))
		os.MkdirAll(d, 0o700)
		p, err := a.Blobs.Materialize(t.Blob, d, t.Name)
		if err != nil {
			return nil, err
		}
		files = append(files, checks.TestFile{Path: p, Name: t.Name, Expect: t.Expect, Rule: t.Rule})
	}
	rulesPath := w.OwnPath(kind, name)
	if kind == "critical" {
		rulesPath = filepath.Join(w.Dir, "critical")
	}
	return checks.RunRuleTests(a.Tools, kind, rulesPath, files)
}

// ---------------------------------------------------------------- списки

// Lists — робочі копії списків і зауваження.
func (a *App) Lists(w *workspace.WS) (white, black *orglists.List, warns []lists.Warning, err error) {
	dir := filepath.Join(w.Dir, "lists")
	if white, err = lists.Load(dir, "white"); err != nil {
		return
	}
	if black, err = lists.Load(dir, "black"); err != nil {
		return
	}
	return white, black, lists.Warnings(white, black), nil
}

// SaveList — зберегти робочу копію (перевірка orglists.Parse).
func (a *App) SaveList(w *workspace.WS, kind string, l *orglists.List, msg, who string) error {
	if err := lists.Save(filepath.Join(w.Dir, "lists"), kind, l); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "list", kind+": "+msg)
	return a.commit(w, kind+" list: "+msg, who)
}

// SignLists — підписати обидва списки ключем списків (serial більший за той, що на цілі, якщо ціль задана).
func (a *App) SignLists(w *workspace.WS, published map[string]int64) ([]*lists.Signed, error) {
	seed, err := a.seed(w.Cfg.ListsKey, "lists")
	if err != nil {
		return nil, err
	}
	white, black, _, err := a.Lists(w)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []*lists.Signed
	for _, x := range []struct {
		kind string
		l    *orglists.List
	}{{"white", white}, {"black", black}} {
		s, err := lists.Sign(x.l, x.kind, seed, w.Cfg.ListsKey.Public, published[x.kind], now)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// PublishLists — підписати й опублікувати списки (лише явна дія людини).
func (a *App) PublishLists(w *workspace.WS, targetID, who string, say func(string, ...any)) (*publish.Result, error) {
	t, err := w.Target(targetID)
	if err != nil {
		return nil, err
	}
	e, err := a.env(w, *t, say)
	if err != nil {
		return nil, err
	}
	cur, err := publish.CurrentSerials(*t, e)
	if err != nil {
		return nil, err
	}
	signed, err := a.SignLists(w, cur)
	if err != nil {
		return nil, err
	}
	res, err := publish.Lists(w.Cfg, *t, signed, []string{w.Cfg.ListsKey.Public}, e)
	status := "ok"
	if err != nil {
		status = err.Error()
	}
	for _, s := range signed {
		loc := t.Path
		if res != nil {
			loc = res.Location
		}
		a.DB.AddPublication(store.Publication{WS: w.Cfg.Name, What: s.Kind + "list", Version: fmt.Sprint(s.Serial), Target: t.ID, At: time.Now(), By: who, Location: loc, Result: status})
	}
	a.DB.Audit(w.Cfg.Name, who, "publish", fmt.Sprintf("lists -> %s: %s", t.ID, status))
	return res, err
}

// ---------------------------------------------------------------- збирання

// NextVersion — більша за: version_floor, усі опубліковані релізи простору, версії на всіх цілях правил.
func (a *App) NextVersion(w *workspace.WS, bump string, checkTargets bool) (next, floor string, err error) {
	cands := []string{w.Cfg.VersionFloor}
	rs, _ := a.DB.Releases(w.Cfg.Name)
	for _, r := range rs {
		if r.Status == "published" {
			cands = append(cands, r.Version)
		}
	}
	locks, _ := filepath.Glob(filepath.Join(w.Dir, "releases", "v*.lock"))
	for _, l := range locks {
		cands = append(cands, strings.TrimSuffix(filepath.Base(l), ".lock"))
	}
	if checkTargets {
		for _, t := range w.Cfg.Targets {
			if t.Kind != "folder" && t.Kind != "mirror-branch" && t.Kind != "release" && !IsEditionsTarget(t) {
				continue
			}
			e, err := a.env(w, t, nil)
			if err != nil {
				return "", "", err
			}
			var v string
			if t.Kind == "release" {
				v, err = publish.CurrentReleaseVersion(t, e)
			} else if IsEditionsTarget(t) {
				var cur map[string]publish.EditionState
				cur, err = publish.CurrentEditions(t, e)
				v = editionsVersion(cur)
			} else {
				v, err = publish.CurrentRulesVersion(t, e)
			}
			if err != nil {
				return "", "", fmt.Errorf("target %s: %w (the version on the target decides the next number)", t.ID, err)
			}
			cands = append(cands, v)
		}
	}
	for _, c := range cands {
		if manifest.ValidVersion(c) && (floor == "" || manifest.Compare(c, floor) > 0) {
			floor = c
		}
	}
	if floor == "" {
		return "v1.0.0", "", nil
	}
	var v [3]int
	fmt.Sscanf(floor, "v%d.%d.%d", &v[0], &v[1], &v[2])
	switch bump {
	case "", "patch":
		v[2]++
	case "minor":
		v[1], v[2] = v[1]+1, 0
	case "major":
		v[0], v[1], v[2] = v[0]+1, 0, 0
	default:
		return "", "", fmt.Errorf("bump %q: patch, minor or major", bump)
	}
	return fmt.Sprintf("v%d.%d.%d", v[0], v[1], v[2]), floor, nil
}

// input — дерева джерела й простору на коміті wsCommit (для збирання й відтворення).
func (a *App) input(w *workspace.WS, wsCommit, tmp string) (build.Input, error) {
	wsTree := filepath.Join(tmp, "ws")
	if err := w.Repo.Extract(wsCommit, wsTree); err != nil {
		return build.Input{}, err
	}
	snap, err := workspace.Open(wsTree)
	if err != nil {
		return build.Input{}, err
	}
	src, err := a.rulesTree(snap)
	if err != nil {
		return build.Input{}, err
	}
	srcTree := filepath.Join(tmp, "src")
	if err := a.Cache.Extract(*src, srcTree); err != nil {
		return build.Input{}, err
	}
	dec, err := snap.Decisions()
	if err != nil {
		return build.Input{}, err
	}
	return build.Input{SourceTree: srcTree, SourceID: src.ID, SourceCommit: src.Commit, WSTree: wsTree, WSCommit: wsCommit, Decisions: dec}, nil
}

// BuildResult — збирання + запис у БД.
type BuildResult struct {
	*build.Result
	Floor string
}

// Build — кандидат релізу: наступна версія, пакет, підпис ключем простору, контракт, критичні тести.
func (a *App) Build(w *workspace.WS, bump string, checkTargets bool, who string) (*BuildResult, error) {
	if st, _ := w.Repo.Line("status", "--porcelain"); st != "" {
		if _, err := w.Commit("uncommitted changes before build", who); err != nil {
			return nil, err
		}
	}
	head, err := w.Head()
	if err != nil {
		return nil, err
	}
	version, floor, err := a.NextVersion(w, bump, checkTargets)
	if err != nil {
		return nil, err
	}
	seed, err := a.seed(w.Cfg.RulesKey, "rules")
	if err != nil {
		return nil, err
	}
	defer func() { seed = "" }()
	tmp, err := os.MkdirTemp("", "hive-build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	in, err := a.input(w, head, tmp)
	if err != nil {
		return nil, err
	}
	if in.VendorTree, _, err = a.vendorTree(in.WSTree, in.SourceTree); err != nil {
		return nil, fmt.Errorf("vendor generator: %w", err)
	}
	tests, _ := w.Tests()
	td := filepath.Join(tmp, "tests")
	for i, t := range tests {
		if t.Scope != "critical" {
			continue
		}
		d := filepath.Join(td, fmt.Sprint(i))
		os.MkdirAll(d, 0o700)
		p, err := a.Blobs.Materialize(t.Blob, d, t.Name)
		if err != nil {
			return nil, err
		}
		in.Critical = append(in.Critical, build.CriticalTest{Path: p, Expect: t.Expect})
	}
	out := filepath.Join(a.Data, "out", w.Cfg.Name, version)
	os.RemoveAll(out)
	created := time.Now().UTC().Truncate(time.Second)
	newer := floor
	if newer == "" {
		newer = "v0.0.0" // перший реліз: на ПК правил цього простору ще немає
	}
	r, err := build.Build(in, build.Options{Version: version, Created: created, Seed: seed, PublicKey: w.Cfg.RulesKey.Public,
		Tools: a.Tools, NewerThan: newer, OutDir: out})
	if err != nil {
		return nil, err
	}
	res := resultOf(r)
	notes := r.Notes
	var eds []EditionBuild
	if HasEditionsTarget(w.Cfg) {
		bo := build.Options{Version: version, Created: created, Seed: seed, PublicKey: w.Cfg.RulesKey.Public, Tools: a.Tools, NewerThan: newer, OutDir: out}
		if eds, err = a.buildEditions(w, in, bo, r, res); err != nil {
			return nil, err
		}
		for _, e := range eds {
			if e.Rules && e.Result != "PASS" && res == "PASS" {
				res = e.Result
				notes = append(notes, fmt.Sprintf("edition %s (%s): %s", e.ID, e.Variant, e.Result))
			}
		}
		notes = append(notes, fmt.Sprintf("%d edition(s) built", len(eds)))
	}
	rep, _ := json.Marshal(struct {
		Contract *contract.Report  `json:"contract"`
		Critical *checks.SetResult `json:"critical,omitempty"`
		Notes    []string          `json:"notes,omitempty"`
		Source   string            `json:"source"`
		Editions []EditionBuild    `json:"editions,omitempty"`
	}{r.Contract, r.Critical, notes, in.SourceID + "@" + in.SourceCommit, eds})
	if err := a.DB.PutRelease(store.Release{WS: w.Cfg.Name, Version: version, Status: "built", Created: created, WSCommit: head,
		KeyID: r.KeyID, Files: r.Files, PkgSHA: r.PkgSHA, Dir: out, Result: res, Report: string(rep), BuiltBy: who}); err != nil {
		return nil, err
	}
	a.DB.Audit(w.Cfg.Name, who, "build", fmt.Sprintf("%s %s (%d files)", version, res, r.Files))
	return &BuildResult{Result: r, Floor: floor}, nil
}

// Lock — releases/vX.Y.Z.lock: усе, щоб відтворити пакет.
type Lock struct {
	Version      string            `yaml:"version"`
	Created      string            `yaml:"created"`
	Workspace    string            `yaml:"workspace"`
	WSCommit     string            `yaml:"workspace_commit"`
	Source       string            `yaml:"source"`
	SourceURL    string            `yaml:"source_url"`
	SourceCommit string            `yaml:"source_commit"`
	KeyID        string            `yaml:"key_id"`
	Hive         string            `yaml:"hive"`
	Yara         string            `yaml:"yara,omitempty"`
	Files        int               `yaml:"files"`
	Assets       map[string]string `yaml:"assets"` // ім'я -> sha256 (самі файли — у сховищі)
	Published    []string          `yaml:"published"`
}

// Publish — опублікувати зібраний реліз у ціль (лише явна дія людини). Перша публікація заморожує реліз:
// .lock у git простору, тег vX.Y.Z на коміт, з якого зібрано, активи — у сховище.
func (a *App) Publish(w *workspace.WS, version, targetID, who string, say func(string, ...any)) (*publish.Result, error) {
	rel, err := a.DB.Release(w.Cfg.Name, version)
	if err != nil {
		return nil, err
	}
	if rel.Result == "FAIL" {
		return nil, fmt.Errorf("%s did not pass the checks (contract / critical tests) - it cannot be published", version)
	}
	if rel.Result != "PASS" {
		return nil, fmt.Errorf("%s was not fully checked (%s): set DocScan yara / yarac and build again", version, rel.Result)
	}
	if err := a.labGate(w, rel); err != nil {
		return nil, err
	}
	if err := a.fourEyes(w, rel, t0(w, targetID), who); err != nil {
		return nil, err
	}
	t, err := w.Target(targetID)
	if err != nil {
		return nil, err
	}
	e, err := a.env(w, *t, say)
	if err != nil {
		return nil, err
	}
	if IsEditionsTarget(*t) {
		return a.PublishEditions(w, version, targetID, who, false, say)
	}
	var res *publish.Result
	if t.Kind == "release" {
		tree, zerr := publish.ZipFiles(filepath.Join(rel.Dir, install.PackageName))
		if zerr != nil {
			return nil, zerr
		}
		report, _ := os.ReadFile(filepath.Join(w.Dir, "vendor", "report.md"))
		res, err = publish.Release(w.Cfg, *t, publish.ReleaseInput{Dir: rel.Dir, Version: version, Tree: tree, Report: report,
			Source: w.Cfg.Name + " @ " + short(rel.WSCommit)}, e)
	} else {
		res, err = publish.Rules(w.Cfg, *t, rel.Dir, version, e)
	}
	status := "ok"
	if err != nil {
		status = err.Error()
	} else if (res.Report != nil && res.Report.Result() == "FAIL") || (res.PCs != nil && res.PCs.Result() == "FAIL") {
		status = "published, but the check of the target FAILED"
	}
	loc := t.Path
	if res != nil {
		loc = res.Location
	}
	a.DB.AddPublication(store.Publication{WS: w.Cfg.Name, What: "rules", Version: version, Target: t.ID, At: time.Now(), By: who, Location: loc, Result: status})
	a.DB.Audit(w.Cfg.Name, who, "publish", fmt.Sprintf("rules %s -> %s: %s", version, t.ID, status))
	if err != nil {
		return res, err
	}
	if ferr := a.freeze(w, rel, t.ID, who); ferr != nil {
		return res, fmt.Errorf("published, but the release record failed: %w", ferr)
	}
	if status != "ok" {
		return res, fmt.Errorf("%s", status)
	}
	return res, nil
}

func (a *App) freeze(w *workspace.WS, rel *store.Release, target, who string) error {
	p := filepath.Join(w.Dir, "releases", rel.Version+".lock")
	var l Lock
	if b, err := os.ReadFile(p); err == nil {
		yaml.Unmarshal(b, &l)
	} else {
		tmp, err := os.MkdirTemp("", "hive-freeze-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		snapTree := filepath.Join(tmp, "ws")
		if err := w.Repo.Extract(rel.WSCommit, snapTree); err != nil {
			return err
		}
		snap, _ := workspace.Open(snapTree)
		src, err := a.rulesTree(snap)
		if err != nil {
			return err
		}
		l = Lock{Version: rel.Version, Created: rel.Created.UTC().Format(time.RFC3339), Workspace: w.Cfg.Name, WSCommit: rel.WSCommit,
			Source: src.ID, SourceURL: src.URL, SourceCommit: src.Commit, KeyID: rel.KeyID, Hive: Version, Files: rel.Files, Assets: map[string]string{}}
		if a.Tools.Configured() {
			if inf, err := a.Tools.Probe(); err == nil {
				l.Yara = inf.Version
			}
		}
		for _, n := range []string{install.PackageName, install.ManifestName, install.SigName, install.BundleName} {
			sha, _, err := a.Blobs.PutFile(filepath.Join(rel.Dir, n))
			if err != nil {
				return err
			}
			l.Assets[n] = sha
		}
		for n, p := range editionAssets(rel, a.ReleaseEditions(rel)) {
			sha, _, err := a.Blobs.PutFile(p)
			if err != nil {
				return err
			}
			l.Assets[n] = sha
		}
	}
	l.Published = append(l.Published, fmt.Sprintf("%s %s by %s", time.Now().UTC().Format(time.RFC3339), target, who))
	b, _ := yaml.Marshal(l)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return err
	}
	if err := a.commit(w, "release "+rel.Version+" published to "+target, who); err != nil {
		return err
	}
	w.Repo.Run("tag", "-f", rel.Version, rel.WSCommit)
	rel.Status = "published"
	return a.DB.PutRelease(*rel)
}

// Reproduce — зібрати опублікований реліз заново з .lock і звірити sha256 кожного файлу з підписаним маніфестом.
func (a *App) Reproduce(w *workspace.WS, version string) (int, []string, error) {
	b, err := os.ReadFile(filepath.Join(w.Dir, "releases", version+".lock"))
	if err != nil {
		return 0, nil, fmt.Errorf("%s is not a published release of %s", version, w.Cfg.Name)
	}
	var l Lock
	if err := yaml.Unmarshal(b, &l); err != nil {
		return 0, nil, err
	}
	mp, err := a.Blobs.Path(l.Assets[install.ManifestName])
	if err != nil {
		return 0, nil, err
	}
	mb, _ := os.ReadFile(mp)
	var m manifest.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		return 0, nil, err
	}
	tmp, err := os.MkdirTemp("", "hive-reproduce-")
	if err != nil {
		return 0, nil, err
	}
	defer os.RemoveAll(tmp)
	in, err := a.input(w, l.WSCommit, tmp)
	if err != nil {
		return 0, nil, err
	}
	if in.SourceCommit != l.SourceCommit {
		return 0, nil, fmt.Errorf("source commit %s, the lock says %s", in.SourceCommit, l.SourceCommit)
	}
	if in.VendorTree, _, err = a.vendorTree(in.WSTree, in.SourceTree); err != nil {
		return 0, nil, fmt.Errorf("vendor generator: %w", err)
	}
	files, _, err := build.Files(in)
	if err != nil {
		return 0, nil, err
	}
	created, _ := time.Parse(time.RFC3339, l.Created)
	nCrit := 0
	for p := range files {
		if strings.HasPrefix(p, "critical/") {
			nCrit++
		}
	}
	files["VERSION.txt"] = []byte(build.VersionLine(l.Version, in.SourceCommit, in.WSCommit, nCrit, created))
	var diff []string
	for p, want := range m.Files {
		got, ok := files[p]
		switch {
		case !ok:
			diff = append(diff, "missing "+p)
		case sha(got) != want:
			diff = append(diff, "differs "+p)
		}
	}
	for p := range files {
		if _, ok := m.Files[p]; !ok {
			diff = append(diff, "extra "+p)
		}
	}
	sort.Strings(diff)
	return len(m.Files), diff, nil
}

func (a *App) env(w *workspace.WS, t workspace.Target, say func(string, ...any)) (publish.Env, error) {
	e := publish.Env{WorkDir: filepath.Join(a.Data, "cache", "publish", w.Cfg.Name), Say: say, Verify: a.verifyOptions(w)}
	var err error
	if e.Auth, err = a.auth(t.Token); err != nil {
		return e, err
	}
	if t.PCsToken != "" {
		b, err := secrets.Get(t.PCsToken, a.Unlock)
		if err != nil {
			return e, err
		}
		e.PCsToken = string(b)
	}
	return e, nil
}

// VerifyOptions — ключі простору й DocScan для перевірки після публікації.
func (a *App) verifyOptions(w *workspace.WS) contract.Options {
	o := contract.Options{Keys: []string{w.Cfg.RulesKey.Public}}
	if a.Tools.Configured() {
		o.Compiler = a.Tools
	}
	return o
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func short(c string) string {
	if len(c) > 8 {
		return c[:8]
	}
	return c
}

// prevKeys — історія публічних ключів після заміни.
func prevKeys(old workspace.Key) []string {
	out := append([]string(nil), old.Previous...)
	if old.Public != "" {
		out = append(out, old.Public)
	}
	return out
}

func t0(w *workspace.WS, id string) workspace.Target {
	t, err := w.Target(id)
	if err != nil {
		return workspace.Target{ID: id}
	}
	return *t
}

// fourEyes — «чотири ока» (якщо увімкнено в просторі): публікує не той, хто зібрав; публічна ціль — лише після
// схвалення саме цього пакета рецензентом, який його не збирав.
func (a *App) fourEyes(w *workspace.WS, rel *store.Release, t workspace.Target, who string) error {
	if !w.Cfg.FourEyes {
		return nil
	}
	if rel.BuiltBy != "" && rel.BuiltBy == who {
		return fmt.Errorf("four eyes: %s built %s - another person publishes it", who, rel.Version)
	}
	if !t.Public {
		return nil
	}
	aps, _ := a.DB.Approvals(w.Cfg.Name, rel.Version, rel.PkgSHA)
	for _, ap := range aps {
		if ap.By != rel.BuiltBy {
			return nil
		}
	}
	return fmt.Errorf("four eyes: %s goes to a public target - a reviewer (not %s, who built it) has to approve it first", rel.Version, rel.BuiltBy)
}

// Approve — рецензент схвалює реліз (саме цей пакет: sha). Того, хто зібрав, як рецензента не рахують.
func (a *App) Approve(w *workspace.WS, version, who, note string) error {
	rel, err := a.DB.Release(w.Cfg.Name, version)
	if err != nil {
		return err
	}
	if rel.Result != "PASS" {
		return fmt.Errorf("%s is not green (%s) - nothing to approve", version, rel.Result)
	}
	if rel.BuiltBy == who {
		return fmt.Errorf("%s built %s - another person reviews it", who, version)
	}
	if err := a.DB.AddApproval(store.Approval{WS: w.Cfg.Name, Version: version, PkgSHA: rel.PkgSHA, By: who, At: time.Now(), Note: note}); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "approve", version+" "+rel.PkgSHA[:12]+": "+note)
	return nil
}

// PutToken — токен (git push, API релізів, читання дзеркала) у сховище ключів: hive:<назва>.
func (a *App) PutToken(name string, value []byte, who string, replace bool) error {
	if a.Unlock == nil {
		return fmt.Errorf("the keystore passphrase is needed")
	}
	pass, err := a.Unlock("hive")
	if err != nil {
		return err
	}
	defer secrets.Wipe(pass)
	if err := a.Keys.Put(name, "token", "", value, pass, who, replace); err != nil {
		return err
	}
	a.DB.Audit("*", who, "secret", "store token hive:"+name)
	return nil
}
