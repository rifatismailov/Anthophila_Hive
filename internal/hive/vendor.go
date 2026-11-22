package hive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/build"
	"github.com/rifatismailov/Anthophila_Hive/internal/gitx"
	"github.com/rifatismailov/Anthophila_Hive/internal/source"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/vendor"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"gopkg.in/yaml.v3"
)

func (a *App) vendorCache() vendor.Cache {
	return vendor.Cache{Root: filepath.Join(a.Data, "cache", "vendor")}
}

// ImportVendor — генератор вендорних правил з build_vendor_rules.py і vendor-selection.txt (зазвичай — з чекауту
// yara-docscan-rules: tools/). from — тека з уже завантаженими джерелами (vendor-sources), щоб не качати.
func (a *App) ImportVendor(w *workspace.WS, script, selection, from, who string, say func(string, ...any)) (*vendor.Report, error) {
	cfg, err := vendor.ImportPython(script)
	if err != nil {
		return nil, err
	}
	selText, err := os.ReadFile(selection)
	if err != nil {
		return nil, err
	}
	if _, err := vendor.ParseSelection(string(selText)); err != nil {
		return nil, err
	}
	for i, s := range cfg.Sources {
		if say != nil {
			say("fetch %s @ %s", s.Name, first(s.Pin, 12))
		}
		sum, err := a.vendorCache().Fetch(s, from)
		if err != nil {
			return nil, err
		}
		if sum != "" {
			cfg.Sources[i].SHA256 = sum
		}
	}
	os.MkdirAll(filepath.Join(w.Dir, "vendor"), 0o755)
	if err := w.SaveVendorConfig(cfg); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(w.Dir, "vendor", "selection.txt"), selText, 0o644); err != nil {
		return nil, err
	}
	if err := a.commit(w, fmt.Sprintf("vendor generator: %d sources, %d drops, %d info rules (from %s)", len(cfg.Sources), len(cfg.Drop), len(cfg.Info), filepath.Base(script)), who); err != nil {
		return nil, err
	}
	a.DB.Audit(w.Cfg.Name, who, "vendor", "import from "+script)
	return a.VendorRegenerate(w, "import", who)
}

// FetchVendor — усі джерела генератора в кеш (мережа; для релізу — перевірка sha256).
func (a *App) FetchVendor(w *workspace.WS, from string, say func(string, ...any)) error {
	cfg, _, err := w.Vendor()
	if err != nil || cfg == nil {
		return fmt.Errorf("the workspace has no vendor generator (hive vendor import): %v", err)
	}
	for _, s := range cfg.Sources {
		if say != nil {
			say("fetch %s @ %s", s.Name, first(s.Pin, 12))
		}
		if _, err := a.vendorCache().Fetch(s, from); err != nil {
			return err
		}
	}
	return nil
}

// vendorTree — вихід генератора для дерева простору wsTree (знімок на коміті) і дерева правил srcTree. Кешується за
// хешем налаштувань, переліку, власного правила DocScan і версії Hive — повторне збирання не генерує заново.
func (a *App) vendorTree(wsTree, srcTree string) (string, *vendor.Report, error) {
	snap, err := workspace.Open(wsTree)
	if err != nil {
		return "", nil, err
	}
	cfg, sel, err := snap.Vendor()
	if err != nil || cfg == nil {
		return "", nil, err
	}
	h := sha256.New()
	for _, p := range []string{filepath.Join(wsTree, "vendor", "config.yaml"), filepath.Join(wsTree, "vendor", "selection.txt"), filepath.Join(srcTree, "maldoc", "vba_plaintext.yar")} {
		b, _ := os.ReadFile(p)
		h.Write(b)
		h.Write([]byte{0})
	}
	h.Write([]byte(Version))
	key := hex.EncodeToString(h.Sum(nil))[:24]
	out := filepath.Join(a.Data, "cache", "vendor-out", key)
	rep := &vendor.Report{}
	if b, err := os.ReadFile(filepath.Join(out, ".report.yaml")); err == nil && yaml.Unmarshal(b, rep) == nil {
		return out, rep, nil
	}
	tmp, err := os.MkdirTemp("", "hive-vendor-")
	if err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(tmp)
	trees, err := a.vendorCache().Trees(cfg, tmp)
	if err != nil {
		return "", nil, err
	}
	gen := out + ".tmp"
	os.RemoveAll(gen)
	rep, err = vendor.Build(cfg, sel, vendor.Inputs{Sources: trees, VBAPlaintext: filepath.Join(srcTree, "maldoc", "vba_plaintext.yar")}, gen, a.Tools)
	if err != nil {
		os.RemoveAll(gen)
		return "", nil, err
	}
	b, _ := yaml.Marshal(rep)
	os.WriteFile(filepath.Join(gen, ".report.yaml"), b, 0o644)
	os.RemoveAll(out)
	if err := os.Rename(gen, out); err != nil {
		return "", nil, err
	}
	return out, rep, nil
}

// snapshot — дерева простору (поточний коміт) і джерела правил у tmp.
func (a *App) snapshot(w *workspace.WS, tmp string) (wsTree, srcTree string, src *workspace.Source, err error) {
	head, err := w.Head()
	if err != nil {
		return "", "", nil, err
	}
	wsTree = filepath.Join(tmp, "ws")
	if err := w.Repo.Extract(head, wsTree); err != nil {
		return "", "", nil, err
	}
	if src, err = a.rulesTree(w); err != nil {
		return "", "", nil, err
	}
	srcTree = filepath.Join(tmp, "src")
	return wsTree, srcTree, src, a.Cache.Extract(*src, srcTree)
}

// VendorRegenerate — згенерувати за поточними налаштуваннями, записати vendor/report.md (історія — у git простору),
// переіндексувати бібліотеку.
func (a *App) VendorRegenerate(w *workspace.WS, why, who string) (*vendor.Report, error) {
	tmp, err := os.MkdirTemp("", "hive-vregen-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	wsTree, srcTree, _, err := a.snapshot(w, tmp)
	if err != nil {
		return nil, err
	}
	out, rep, err := a.vendorTree(wsTree, srcTree)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(out, "tools", "vendor-report.md"))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(w.Dir, "vendor", "report.md"), b, 0o644); err != nil {
		return nil, err
	}
	if err := a.commit(w, fmt.Sprintf("vendor report (%s): %d files, %d rules kept, %d dropped", why, rep.Files, rep.Rules, len(rep.Dropped)), who); err != nil {
		return nil, err
	}
	if head, err := w.Head(); err == nil {
		a.recordReport(w.Cfg.Name, "hive", head, time.Now().UTC().Format(time.RFC3339), "vendor report ("+why+")", string(b))
	}
	return rep, a.Reindex(w)
}

// indexVendor — індекс складеного дерева (джерело + генератор) і відкинутих генератором правил.
func (a *App) indexVendor(w *workspace.WS, src workspace.Source) (bool, error) {
	cfg, _, err := w.Vendor()
	if err != nil || cfg == nil {
		return false, err
	}
	tmp, err := os.MkdirTemp("", "hive-vindex-")
	if err != nil {
		return true, err
	}
	defer os.RemoveAll(tmp)
	wsTree, srcTree, _, err := a.snapshot(w, tmp)
	if err != nil {
		return true, err
	}
	out, rep, err := a.vendorTree(wsTree, srcTree)
	if err != nil {
		return true, err
	}
	files, _, err := build.Files(build.Input{SourceTree: srcTree, SourceID: src.ID, SourceCommit: src.Commit, WSTree: filepath.Join(tmp, "empty"), VendorTree: out})
	if err != nil {
		return true, err
	}
	comp := filepath.Join(tmp, "composed")
	for p, b := range files {
		f := filepath.Join(comp, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(f), 0o755)
		os.WriteFile(f, b, 0o644)
	}
	rules, err := source.Index(comp, src.ID, "")
	if err != nil {
		return true, err
	}
	if err := a.DB.ReplaceRules(w.Cfg.Name, src.ID, rules); err != nil {
		return true, err
	}
	var dropped []store.Rule
	for _, d := range rep.Dropped {
		// "<джерело>/<шлях>: <правило> — <причина>"
		loc, rest, ok1 := strings.Cut(d, ": ")
		name, reason, ok2 := strings.Cut(rest, " — ")
		if !ok1 || !ok2 {
			continue
		}
		dropped = append(dropped, store.Rule{Origin: "vendor", File: loc, Name: name, Kind: "dropped",
			Meta: map[string]string{"hive_dropped": reason}})
	}
	return true, a.DB.ReplaceRules(w.Cfg.Name, "vendor", dropped)
}

// VendorReport — останній звіт генератора (vendor/report.md).
func (a *App) VendorReport(w *workspace.WS) (string, error) {
	b, err := os.ReadFile(filepath.Join(w.Dir, "vendor", "report.md"))
	return string(b), err
}

// VendorUpdate — що зміниться, якщо закріпити джерело name на ref: правила вибраних файлів джерела (додані /
// прибрані / змінені), файли джерела, яких немає в переліку (кандидати), і вплив на згенерований набір.
type VendorUpdate struct {
	Source, From, To string
	Changes          []vendor.RuleChange
	NewFiles         []string // .yar нового коміту, яких немає в переліку
	KeptBefore       int
	KeptAfter        int
	Added, Removed   []string // правила згенерованого набору
}

// VendorUpdatePreview — завантажити джерело і порівняти закріплений коміт з ref (нічого не змінює).
func (a *App) VendorUpdatePreview(w *workspace.WS, name, ref string) (*VendorUpdate, error) {
	cfg, sel, err := w.Vendor()
	if err != nil || cfg == nil {
		return nil, fmt.Errorf("the workspace has no vendor generator")
	}
	var s *vendor.Source
	for i := range cfg.Sources {
		if cfg.Sources[i].Name == name {
			s = &cfg.Sources[i]
		}
	}
	if s == nil {
		return nil, fmt.Errorf("no vendor source %q", name)
	}
	if s.IsRelease() {
		return nil, fmt.Errorf("%s is a release zip: change its URL and pin (release:<tag>) in vendor/config.yaml", name)
	}
	vc := a.vendorCache()
	if _, err := vc.Fetch(*s, ""); err != nil {
		return nil, err
	}
	r, err := vc.Repo(*s)
	if err != nil {
		return nil, err
	}
	if _, err := r.Run("fetch", "-q", "--tags", "origin", "+refs/heads/*:refs/heads/*"); err != nil {
		return nil, err
	}
	to, err := r.Resolve(ref)
	if err != nil || to == "" {
		return nil, fmt.Errorf("%q is not a commit of %s", ref, name)
	}
	u := &VendorUpdate{Source: name, From: s.Pin, To: to}
	tmp, err := os.MkdirTemp("", "hive-vupd-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	oldT, newT := filepath.Join(tmp, "old"), filepath.Join(tmp, "new")
	if err := r.Extract(s.Pin, oldT); err != nil {
		return nil, err
	}
	if err := r.Extract(to, newT); err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	var files []string
	for _, x := range sel {
		if x.Source == name {
			files = append(files, x.Path)
			selected[x.Path] = true
		}
	}
	if u.Changes, err = vendor.DiffTrees(oldT, newT, files); err != nil {
		return nil, err
	}
	filepath.Walk(newT, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && source.IsRulesFile(p) {
			rel, _ := filepath.Rel(newT, p)
			if rel = filepath.ToSlash(rel); !selected[rel] {
				u.NewFiles = append(u.NewFiles, rel)
			}
		}
		return nil
	})
	sort.Strings(u.NewFiles)
	// вплив на згенерований набір: генератор з поточним і з новим комітом
	wsTree, srcTree, _, err := a.snapshot(w, filepath.Join(tmp, "snap"))
	if err != nil {
		return nil, err
	}
	before, _, err := a.vendorTree(wsTree, srcTree)
	if err != nil {
		return nil, err
	}
	s.Pin = to
	snap, _ := workspace.Open(wsTree)
	if err := snap.SaveVendorConfig(cfg); err != nil {
		return nil, err
	}
	after, _, err := a.vendorTree(wsTree, srcTree)
	if err != nil {
		return nil, fmt.Errorf("the generator fails with %s @ %s: %w", name, first(to, 12), err)
	}
	ch, err := vendor.DiffTrees(before, after, nil)
	if err != nil {
		return nil, err
	}
	names := func(dir string) int {
		rs, _ := source.Index(dir, "x", "")
		return len(rs)
	}
	u.KeptBefore, u.KeptAfter = names(before), names(after)
	for _, c := range ch {
		switch c.Status {
		case "added":
			u.Added = append(u.Added, c.File+":"+c.Rule)
		case "removed":
			u.Removed = append(u.Removed, c.File+":"+c.Rule)
		}
	}
	return u, nil
}

// VendorPin — закріпити джерело генератора на коміті (після перегляду), перегенерувати.
func (a *App) VendorPin(w *workspace.WS, name, commit, who string) (*vendor.Report, error) {
	cfg, _, err := w.Vendor()
	if err != nil || cfg == nil {
		return nil, fmt.Errorf("the workspace has no vendor generator")
	}
	found := false
	for i := range cfg.Sources {
		if cfg.Sources[i].Name == name {
			if cfg.Sources[i].IsRelease() {
				return nil, fmt.Errorf("%s is a release zip", name)
			}
			r, err := a.vendorCache().Repo(cfg.Sources[i])
			if err != nil {
				return nil, err
			}
			c, err := r.Resolve(commit)
			if err != nil || c == "" {
				return nil, fmt.Errorf("%q is not a commit of %s (preview it first)", commit, name)
			}
			a.DB.Audit(w.Cfg.Name, who, "vendor-pin", fmt.Sprintf("%s %s -> %s", name, first(cfg.Sources[i].Pin, 12), first(c, 12)))
			cfg.Sources[i].Pin = c
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("no vendor source %q", name)
	}
	if err := w.SaveVendorConfig(cfg); err != nil {
		return nil, err
	}
	if err := a.commit(w, fmt.Sprintf("vendor: pin %s at %s", name, first(commit, 12)), who); err != nil {
		return nil, err
	}
	return a.VendorRegenerate(w, "pin "+name, who)
}

func first(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// recordReport — версія звіту в історію (БД).
func (a *App) recordReport(ws, origin, rev, date, subject, text string) error {
	pr := vendor.ParseReport(text)
	var rules []store.ReportRule
	for _, e := range pr.Entries {
		rules = append(rules, store.ReportRule{Rule: e.Rule, File: e.File, Status: e.Status, Detail: e.Detail})
	}
	return a.DB.PutReportVersion(ws, store.ReportVersion{Origin: origin, Rev: rev, Date: date, Subject: subject, Counts: pr.Counts}, rules)
}

// ImportVendorHistory — історія vendor-report.md з git-репозиторію (напр. yara-docscan: docscan-project/rules/tools/
// vendor-report.md, або yara-docscan-rules: tools/vendor-report.md): кожна версія — лічильники і статус кожного
// правила. Повертає кількість версій.
func (a *App) ImportVendorHistory(w *workspace.WS, repo, path, who string) (int, error) {
	r := &gitx.Repo{Dir: repo}
	out, err := r.Run("log", "--format=%H%x09%aI%x09%s", "--", path)
	if err != nil {
		return 0, err
	}
	n := 0
	origin := filepath.Base(repo)
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.SplitN(l, "\t", 3)
		if len(f) != 3 {
			continue
		}
		b, err := r.Show(f[0], path)
		if err != nil || b == nil {
			continue // файл у цьому коміті прибрано
		}
		if err := a.recordReport(w.Cfg.Name, origin, f[0], f[1], f[2], string(b)); err != nil {
			return n, err
		}
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("%s has no versions of %s", repo, path)
	}
	a.DB.Audit(w.Cfg.Name, who, "vendor-history", fmt.Sprintf("%d versions from %s:%s", n, origin, path))
	return n, nil
}

// RuleHistoryLine — правило в одній версії звіту.
type RuleHistoryLine struct {
	store.ReportVersion
	Status, Detail, File string
}

// RuleHistory — статус правила в кожній версії звіту генератора (відсутність у звіті = взято без змін, якщо файл
// правила був у переліку).
func (a *App) RuleHistory(w *workspace.WS, rule string) ([]RuleHistoryLine, error) {
	vs, err := a.DB.ReportVersions(w.Cfg.Name)
	if err != nil {
		return nil, err
	}
	st, err := a.DB.RuleInReports(w.Cfg.Name, rule)
	if err != nil {
		return nil, err
	}
	var out []RuleHistoryLine
	for _, v := range vs {
		l := RuleHistoryLine{ReportVersion: v, Status: "—"}
		if r, ok := st[v.Origin+"|"+v.Rev]; ok {
			l.Status, l.Detail, l.File = r.Status, r.Detail, r.File
		}
		out = append(out, l)
	}
	return out, nil
}
