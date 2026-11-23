// Package workspace — робочий простір організації: git-репозиторій з усім, що вирішує людина (PLAN.md, розділ 3).
//
//	hive.yaml            назва, видимість, ключі (публічні частини + посилання на секрети), цілі публікації
//	sources/<id>.yaml    джерела правил (закріплений коміт)
//	decisions.yaml       рішення по правилах джерел (відкинути + причина)
//	rules/org/*.yar      власні правила виявлення (у пакеті — org/*.yar)
//	critical/*.yar       правила критичної інформації (у пакеті — critical/*.yar)
//	tests.yaml           тестові файли правил — лише sha256 у сховищі, самі файли не в git
//	lists/whitelist.json, lists/blacklist.json   робочі копії списків (непідписані)
//	releases/vX.Y.Z.lock опубліковані релізи: усе, щоб відтворити пакет
//
// Кожна зміна — коміт (автор — хто зробив дію). Зразки ШПЗ і документи сюди не потрапляють: Commit відмовляє,
// якщо в теці з'явився бінарний файл.
package workspace

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/lab"
	"github.com/rifatismailov/Anthophila_Hive/internal/vendor"
)

// Key — ключ підпису: публічна частина (ed25519:<base64>) і посилання на секрет (internal/secrets).
type Key struct {
	Public   string   `yaml:"public,omitempty"`
	Secret   string   `yaml:"secret,omitempty"`
	Previous []string `yaml:"previous,omitempty"` // попередні публічні ключі (після заміни): ними перевіряються старі релізи
}

// Target — куди публікується пакет або списки.
type Target struct {
	ID   string `yaml:"id"`
	Kind string `yaml:"kind"` // mirror-branch | folder | lists-branch | lists-folder | editions-branch | editions-folder
	// mirror-branch / lists-branch
	Repo   string `yaml:"repo,omitempty"`   // URL git-репозиторію дзеркала (або шлях до bare-репозиторію)
	Branch string `yaml:"branch,omitempty"` // напр. docscan-rules / docscan-lists
	Token  string `yaml:"token,omitempty"`  // посилання на секрет токена запису (push)
	// folder / lists-folder
	Path string `yaml:"path,omitempty"` // тека або UNC, яку ПК читають як rules.mirror.url / lists.url
	// звідки читають ПК (для перевірки після публікації); "" — перевіряється саме записане
	PCsURL   string `yaml:"pcs_url,omitempty"`
	PCsToken string `yaml:"pcs_token,omitempty"` // посилання на токен ЛИШЕ НА ЧИТАННЯ, з яким читають ПК
	// ПК підтримують rules.mirror.token (DocScan з цією зміною вже стоїть на ПК цілі) — без цього приватний
	// набір у закриту гілку не публікується (PLAN.md 9.2.5)
	PCsTokenSupported bool `yaml:"pcs_token_supported,omitempty"`
	Public            bool `yaml:"public,omitempty"` // публічна ціль: приватні критичні правила сюди не йдуть
	// release — реліз на GitHub / Forgejo
	Forge       string `yaml:"forge,omitempty"`        // github | forgejo
	Project     string `yaml:"project,omitempty"`      // owner/repo
	API         string `yaml:"api,omitempty"`          // forgejo: https://host
	CommitTree  bool   `yaml:"commit_tree,omitempty"`  // покласти дерево правил комітом у Repo / Branch перед тегом
	DownloadURL string `yaml:"download_url,omitempty"` // база адрес файлів релізу (за замовчуванням — сервісу)
	// editions-branch / editions-folder — які редакції публікувати (порожньо — усі редакції простору)
	Editions []string `yaml:"editions,omitempty"`
}

// Config — hive.yaml.
type Config struct {
	Name         string   `yaml:"name"`
	Visibility   string   `yaml:"visibility"` // public | private
	RulesKey     Key      `yaml:"rules_key"`
	ListsKey     Key      `yaml:"lists_key"`
	VersionFloor string   `yaml:"version_floor,omitempty"` // остання офіційна версія на ПК: перша своя має бути більшою
	Targets      []Target `yaml:"targets,omitempty"`
	Lab          Lab      `yaml:"lab,omitempty"`
	// FourEyes — публікує не той, хто зібрав реліз; у публічну ціль — лише після схвалення рецензентом (не тим, хто
	// зібрав). Для сервера організації — увімкнено.
	FourEyes bool `yaml:"four_eyes,omitempty"`
	// Editions — редакції пакета (editions.go); порожньо — DefaultEditions.
	Editions []Edition `yaml:"editions,omitempty"`
}

// Lab — лабораторія простору: які набори Hive обов'язкові перед публікацією і пороги.
type Lab struct {
	Sets         []string `yaml:"sets,omitempty"`          // id наборів (hive lab set add); порожньо — лабораторія не вимагається
	Mode         string   `yaml:"mode,omitempty"`          // fast | full (перед релізом)
	SlowerYellow int      `yaml:"slower_yellow,omitempty"` // % сповільнення — жовте (30)
	SlowerRed    int      `yaml:"slower_red,omitempty"`    // % сповільнення — червоне (100)
}

// Source — sources/<id>.yaml. MVP-a: лише kind=git, role=rules-tree (готове дерево правил як yara-docscan-rules).
type Source struct {
	ID      string `yaml:"id"`
	Kind    string `yaml:"kind"` // git
	Role    string `yaml:"role"` // rules-tree
	URL     string `yaml:"url"`
	Ref     string `yaml:"ref"`    // гілка / тег, за якою закріплено
	Commit  string `yaml:"commit"` // закріплений коміт — саме його бере збирання
	License string `yaml:"license,omitempty"`
	Token   string `yaml:"token,omitempty"` // посилання на секрет (закритий репозиторій)
	Pinned  string `yaml:"pinned_at,omitempty"`
}

// Decision — рішення по правилу джерела.
type Decision struct {
	Source string `yaml:"source"`
	File   string `yaml:"file"` // шлях у дереві джерела
	Rule   string `yaml:"rule"`
	Status string `yaml:"status"` // drop
	Reason string `yaml:"reason"`
	By     string `yaml:"by"`
	At     string `yaml:"at"`
}

// TestCase — тестовий файл: для набору критичних правил (scope critical) або для одного правила (scope rule).
type TestCase struct {
	Scope  string `yaml:"scope"`          // critical | rule
	Rule   string `yaml:"rule,omitempty"` // для scope rule
	Expect string `yaml:"expect"`         // match | no-match
	Blob   string `yaml:"blob"`           // sha256 у сховищі
	Name   string `yaml:"name"`           // ім'я файлу (для --file-vars і для людей)
	Kind   string `yaml:"kind,omitempty"` // document | malware
	Added  string `yaml:"added,omitempty"`
	By     string `yaml:"by,omitempty"`
}

// WS — відкритий робочий простір.
type WS struct {
	Dir  string
	Repo *gitx.Repo
	Cfg  Config
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidID — ідентифікатор простору / джерела / цілі.
func ValidID(s string) bool { return idRe.MatchString(s) }

// Create — новий простір у dir.
func Create(dir string, cfg Config) (*WS, error) {
	if !ValidID(cfg.Name) {
		return nil, fmt.Errorf("workspace name %q: lowercase latin letters, digits, . _ -", cfg.Name)
	}
	if cfg.Visibility != "public" && cfg.Visibility != "private" {
		return nil, fmt.Errorf("visibility %q: public or private", cfg.Visibility)
	}
	if _, err := os.Stat(filepath.Join(dir, "hive.yaml")); err == nil {
		return nil, fmt.Errorf("%s: a workspace already exists", dir)
	}
	r, err := gitx.Init(dir)
	if err != nil {
		return nil, err
	}
	for _, d := range []string{"sources", "rules/org", "critical", "lists", "releases"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
		os.WriteFile(filepath.Join(dir, d, ".keep"), nil, 0o644)
	}
	w := &WS{Dir: dir, Repo: r, Cfg: cfg}
	if err := w.SaveConfig(); err != nil {
		return nil, err
	}
	if _, err := w.Commit("create workspace "+cfg.Name, ""); err != nil {
		return nil, err
	}
	return w, nil
}

// Open — наявний простір.
func Open(dir string) (*WS, error) {
	w := &WS{Dir: dir, Repo: &gitx.Repo{Dir: dir}}
	if err := readYAML(filepath.Join(dir, "hive.yaml"), &w.Cfg); err != nil {
		return nil, err
	}
	return w, nil
}

func readYAML(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(v); err != nil && err.Error() != "EOF" {
		return fmt.Errorf("%s: %w", filepath.Base(p), err)
	}
	return nil
}

func writeYAML(p string, v any) error {
	var b bytes.Buffer
	e := yaml.NewEncoder(&b)
	e.SetIndent(2)
	if err := e.Encode(v); err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(p), 0o755)
	return os.WriteFile(p, b.Bytes(), 0o644)
}

// SaveConfig — hive.yaml.
func (w *WS) SaveConfig() error { return writeYAML(filepath.Join(w.Dir, "hive.yaml"), w.Cfg) }

// Target — ціль за id.
func (w *WS) Target(id string) (*Target, error) {
	for i := range w.Cfg.Targets {
		if w.Cfg.Targets[i].ID == id {
			return &w.Cfg.Targets[i], nil
		}
	}
	return nil, fmt.Errorf("no target %q in %s", id, w.Cfg.Name)
}

// Sources — усі джерела.
func (w *WS) Sources() ([]Source, error) {
	ps, _ := filepath.Glob(filepath.Join(w.Dir, "sources", "*.yaml"))
	sort.Strings(ps)
	var out []Source
	for _, p := range ps {
		var s Source
		if err := readYAML(p, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// SaveSource — sources/<id>.yaml.
func (w *WS) SaveSource(s Source) error {
	if !ValidID(s.ID) {
		return fmt.Errorf("source id %q: lowercase latin letters, digits, . _ -", s.ID)
	}
	return writeYAML(filepath.Join(w.Dir, "sources", s.ID+".yaml"), s)
}

// Decisions — decisions.yaml.
func (w *WS) Decisions() ([]Decision, error) {
	var d []Decision
	if _, err := os.Stat(filepath.Join(w.Dir, "decisions.yaml")); err != nil {
		return nil, nil
	}
	return d, readYAML(filepath.Join(w.Dir, "decisions.yaml"), &d)
}

// SetDecision — додати / замінити рішення по правилу (status "" — прибрати рішення, правило знову береться).
func (w *WS) SetDecision(d Decision) error {
	all, err := w.Decisions()
	if err != nil {
		return err
	}
	var out []Decision
	for _, x := range all {
		if !(x.Source == d.Source && x.File == d.File && x.Rule == d.Rule) {
			out = append(out, x)
		}
	}
	if d.Status != "" {
		if d.Status != "drop" {
			return fmt.Errorf("decision %q: only drop is supported", d.Status)
		}
		if strings.TrimSpace(d.Reason) == "" {
			return fmt.Errorf("a dropped rule needs a reason")
		}
		if d.At == "" {
			d.At = time.Now().UTC().Format(time.RFC3339)
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Source+"\x00"+a.File+"\x00"+a.Rule < b.Source+"\x00"+b.File+"\x00"+b.Rule
	})
	return writeYAML(filepath.Join(w.Dir, "decisions.yaml"), out)
}

// Tests — tests.yaml.
func (w *WS) Tests() ([]TestCase, error) {
	var t []TestCase
	if _, err := os.Stat(filepath.Join(w.Dir, "tests.yaml")); err != nil {
		return nil, nil
	}
	return t, readYAML(filepath.Join(w.Dir, "tests.yaml"), &t)
}

// SaveTests — tests.yaml (відсортовано, без повторів).
func (w *WS) SaveTests(t []TestCase) error {
	seen := map[string]bool{}
	var out []TestCase
	for _, x := range t {
		k := x.Scope + "\x00" + x.Rule + "\x00" + x.Blob + "\x00" + x.Name
		if !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Scope+a.Rule+a.Expect+a.Name < b.Scope+b.Rule+b.Expect+b.Name
	})
	return writeYAML(filepath.Join(w.Dir, "tests.yaml"), out)
}

// OwnFiles — власні правила: kind "org" (rules/org) або "critical"; імена файлів .yar.
func (w *WS) OwnFiles(kind string) []string {
	ps, _ := filepath.Glob(filepath.Join(w.Dir, ownDir(kind), "*.yar"))
	var out []string
	for _, p := range ps {
		out = append(out, filepath.Base(p))
	}
	sort.Strings(out)
	return out
}

func ownDir(kind string) string {
	if kind == "critical" {
		return "critical"
	}
	return filepath.Join("rules", "org")
}

// OwnPath — шлях до власного файлу правил.
func (w *WS) OwnPath(kind, name string) string {
	return filepath.Join(w.Dir, ownDir(kind), filepath.Base(name))
}

// Commit — зафіксувати всі зміни (author — хто зробив дію). Бінарні файли в git не потрапляють.
func (w *WS) Commit(msg, author string) (string, error) {
	if bad := w.binaryFiles(); len(bad) > 0 {
		return "", fmt.Errorf("refusing to commit binary files into the workspace (samples and documents belong in the blob store): %s", strings.Join(bad, ", "))
	}
	return w.Repo.CommitAll(msg, author)
}

// Head — поточний коміт.
func (w *WS) Head() (string, error) { return w.Repo.Line("rev-parse", "HEAD") }

// binaryFiles — файли з нульовими байтами або сигнатурами PE / OLE / ZIP / PDF / RTF у робочій теці (крім .git).
func (w *WS) binaryFiles() []string {
	var bad []string
	filepath.Walk(w.Dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() {
			if fi.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		head := make([]byte, 8192)
		n, _ := f.Read(head)
		f.Close()
		head = head[:n]
		if IsBinary(head) {
			rel, _ := filepath.Rel(w.Dir, p)
			bad = append(bad, rel)
		}
		return nil
	})
	return bad
}

// IsBinary — початок файлу схожий на документ / виконуваний файл / архів, а не на текст правил.
func IsBinary(head []byte) bool {
	for _, sig := range [][]byte{{'M', 'Z'}, {0xD0, 0xCF, 0x11, 0xE0}, {'P', 'K', 3, 4}, []byte("%PDF"), []byte("{\\rtf"), {0x7F, 'E', 'L', 'F'}, {0x4C, 0, 0, 0, 1, 0x14, 2, 0}} {
		if bytes.HasPrefix(head, sig) {
			return true
		}
	}
	return bytes.IndexByte(head, 0) >= 0
}

// Accepted — lab/accepted.yaml: перевірені людиною спрацювання.
func (w *WS) Accepted() ([]lab.Accepted, error) {
	var a []lab.Accepted
	if _, err := os.Stat(filepath.Join(w.Dir, "lab", "accepted.yaml")); err != nil {
		return nil, nil
	}
	return a, readYAML(filepath.Join(w.Dir, "lab", "accepted.yaml"), &a)
}

// SaveAccepted — записати список прийнятих.
func (w *WS) SaveAccepted(a []lab.Accepted) error {
	return writeYAML(filepath.Join(w.Dir, "lab", "accepted.yaml"), a)
}

// Vendor — генератор вендорних правил простору (vendor/config.yaml + vendor/selection.txt); nil — генератора немає
// (дерево правил береться з джерела як є).
func (w *WS) Vendor() (*vendor.Config, []vendor.Selection, error) {
	p := filepath.Join(w.Dir, "vendor", "config.yaml")
	if _, err := os.Stat(p); err != nil {
		return nil, nil, nil
	}
	var c vendor.Config
	if err := readYAML(p, &c); err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(filepath.Join(w.Dir, "vendor", "selection.txt"))
	if err != nil {
		return nil, nil, err
	}
	sel, err := vendor.ParseSelection(string(b))
	return &c, sel, err
}

// SaveVendorConfig — vendor/config.yaml.
func (w *WS) SaveVendorConfig(c *vendor.Config) error {
	return writeYAML(filepath.Join(w.Dir, "vendor", "config.yaml"), c)
}
