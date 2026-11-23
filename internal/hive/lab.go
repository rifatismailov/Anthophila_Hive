package hive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/dupes"
	"github.com/rifatismailov/Anthophila_Hive/internal/lab"
	"github.com/rifatismailov/Anthophila_Hive/internal/publish"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

// ---------------------------------------------------------------- набори

// AddLabSet — зареєструвати набір: тека за посиланням (ref) або копія у сховище Hive (copy). ШПЗ і конфіденційні
// набори не можна брати з git-репозиторію (вони ніколи не мають туди потрапляти).
func (a *App) AddLabSet(id, kind, path string, copyIt, confidential bool, who string) (*store.LabSet, error) {
	if !workspace.ValidID(id) {
		return nil, fmt.Errorf("set id %q: lowercase latin letters, digits, . _ -", id)
	}
	if !lab.ValidKind(kind) {
		return nil, fmt.Errorf("set kind %q: %s", kind, strings.Join(lab.Kinds, " | "))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", path)
	}
	if kind == "critical-labelled" {
		if _, err := os.Stat(filepath.Join(abs, "expected.tsv")); err != nil {
			return nil, fmt.Errorf("a labelled set needs %s/expected.tsv (gen_sensitive_dataset.py format)", path)
		}
	}
	if out, err := exec.Command("git", "-C", abs, "rev-parse", "--is-inside-work-tree").Output(); err == nil && strings.TrimSpace(string(out)) == "true" && (kind == "malware" || confidential) {
		return nil, fmt.Errorf("%s is inside a git working tree: malware samples and confidential documents never belong in git - move them out first", path)
	}
	s := store.LabSet{ID: id, Kind: kind, Mode: "ref", Path: abs, Confidential: confidential, Added: time.Now().UTC().Format(time.RFC3339), By: who}
	if copyIt {
		dst := filepath.Join(a.Data, "lab", "sets", id)
		if _, err := os.Stat(dst); err == nil {
			return nil, fmt.Errorf("set %s already has a copy in %s", id, dst)
		}
		if err := lab.CopySet(abs, dst); err != nil {
			os.RemoveAll(dst)
			return nil, err
		}
		s.Mode, s.Path = "copy", dst
	}
	if s.Files, s.Bytes, err = lab.Inventory(s.Path); err != nil {
		return nil, err
	}
	if s.Files == 0 {
		return nil, fmt.Errorf("%s has no files", path)
	}
	if err := a.DB.PutLabSet(s); err != nil {
		return nil, err
	}
	a.DB.Audit("*", who, "lab-set", fmt.Sprintf("add %s %s %s (%d files)", id, kind, s.Mode, s.Files))
	return &s, nil
}

// RemoveLabSet — прибрати набір (копію у сховищі — теж; оригінал теки за посиланням не чіпається).
func (a *App) RemoveLabSet(id, who string) error {
	sets, _ := a.DB.LabSets()
	for _, s := range sets {
		if s.ID == id {
			if s.Mode == "copy" && strings.HasPrefix(s.Path, filepath.Join(a.Data, "lab", "sets")) {
				filepath.Walk(s.Path, func(p string, fi os.FileInfo, err error) error {
					if err == nil {
						os.Chmod(p, 0o700)
					}
					return nil
				})
				os.RemoveAll(s.Path)
			}
			removeTree(a.addedDir(id))
			a.DB.Audit("*", who, "lab-set", "remove "+id)
			return a.DB.DeleteLabSet(id)
		}
	}
	return fmt.Errorf("no set %q", id)
}

// SetLabConfig — які набори обов'язкові для простору, режим, пороги.
func (a *App) SetLabConfig(w *workspace.WS, cfg workspace.Lab, who string) error {
	all, _ := a.DB.LabSets()
	known := map[string]bool{}
	for _, s := range all {
		known[s.ID] = true
	}
	for _, id := range cfg.Sets {
		if !known[id] {
			return fmt.Errorf("no lab set %q (hive lab set add)", id)
		}
	}
	if cfg.Mode != "" && cfg.Mode != "fast" && cfg.Mode != "full" {
		return fmt.Errorf("mode %q: fast or full", cfg.Mode)
	}
	w.Cfg.Lab = cfg
	if err := w.SaveConfig(); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "lab-config", fmt.Sprintf("sets %v mode %s", cfg.Sets, cfg.Mode))
	return a.commit(w, "lab: sets "+strings.Join(cfg.Sets, ", "), who)
}

func (a *App) labSets(w *workspace.WS) ([]lab.Set, error) {
	all, err := a.DB.LabSets()
	if err != nil {
		return nil, err
	}
	by := map[string]store.LabSet{}
	for _, s := range all {
		by[s.ID] = s
	}
	var out []lab.Set
	for _, id := range w.Cfg.Lab.Sets {
		s, ok := by[id]
		if !ok {
			return nil, fmt.Errorf("lab set %q of the workspace is not registered", id)
		}
		out = append(out, lab.Set{ID: s.ID, Kind: s.Kind, Mode: s.Mode, Path: s.Path, Extra: a.addedDir(s.ID), Confidential: s.Confidential, Files: s.Files, Bytes: s.Bytes})
	}
	return out, nil
}

// ---------------------------------------------------------------- прогін

// packageTree — пакет (реліз простору vX.Y.Z або шлях до bundle / теки релізу) розпакований з перевіркою підпису
// (ключ простору або офіційний ключ DocScan) і кожного файлу.
func (a *App) packageTree(w *workspace.WS, ref, tmp string) (tree, pkgSHA, label string, err error) {
	src := ref
	label = ref
	if manifest.ValidVersion(ref) {
		rel, err := a.DB.Release(w.Cfg.Name, ref)
		if err != nil {
			return "", "", "", err
		}
		src = rel.Dir
		if _, err := os.Stat(filepath.Join(src, install.ManifestName)); err != nil {
			return "", "", "", fmt.Errorf("release %s: no files in %s", ref, src)
		}
	}
	b, err := install.ReadBundle(src)
	if err != nil {
		return "", "", "", err
	}
	keys := append(append([]string{w.Cfg.RulesKey.Public}, w.Cfg.RulesKey.Previous...), manifest.OfficialKeys...)
	m, _, pkg, err := install.VerifyManifest(b.Files, keys)
	if err != nil {
		return "", "", "", fmt.Errorf("%s: %w", ref, err)
	}
	tree = filepath.Join(tmp, "pkg-"+m.Package.SHA256[:12])
	if err := install.Stage(m, pkg, tree); err != nil {
		return "", "", "", err
	}
	if !manifest.ValidVersion(ref) {
		label = m.Version + " (" + filepath.Base(ref) + ")"
	}
	return tree, m.Package.SHA256, label, nil
}

// LabResult — прогін зі звітом.
type LabResult struct {
	Run    *store.LabRun
	Report *lab.Report
}

func (a *App) labDir(ws string) string { return filepath.Join(a.Data, "lab", "reports", ws) }

// RunLab — кандидат (версія простору) проти базового: "" — останній опублікований реліз простору, "none" — без
// порівняння, vX.Y.Z — реліз простору, шлях — bundle / тека релізу (напр. офіційний реліз DocScan).
func (a *App) RunLab(w *workspace.WS, candidate, baseline, mode, who string, say func(string, ...any)) (*LabResult, error) {
	sets, err := a.labSets(w)
	if err != nil {
		return nil, err
	}
	if len(sets) == 0 {
		return nil, fmt.Errorf("the workspace has no lab sets (hive lab config --sets …)")
	}
	if mode == "" {
		mode = w.Cfg.Lab.Mode
	}
	if baseline == "" {
		rs, _ := a.DB.Releases(w.Cfg.Name)
		for _, r := range rs {
			if r.Status == "published" && r.Version != candidate {
				baseline = r.Version
				break
			}
		}
		if baseline == "" {
			baseline = "none"
		}
	}
	tmp, err := os.MkdirTemp("", "hive-lab-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	ctree, csha, clabel, err := a.packageTree(w, candidate, tmp)
	if err != nil {
		return nil, err
	}
	rn := lab.Runner{Tools: a.Tools, Cache: filepath.Join(a.Data, "lab", "cache"), Work: tmp, Say: say}
	cpr, err := rn.Run(ctree, csha, clabel, sets, mode)
	if err != nil {
		return nil, err
	}
	var bpr *lab.PackageResult
	bsha, blabel := "", "none"
	if baseline != "none" {
		btree, s, l, err := a.packageTree(w, baseline, tmp)
		if err != nil {
			return nil, fmt.Errorf("baseline: %w", err)
		}
		bsha, blabel = s, l
		if bpr, err = rn.Run(btree, bsha, blabel, sets, mode); err != nil {
			return nil, err
		}
	}
	acc, _ := w.Accepted()
	rep := lab.Compare(cpr, bpr, sets, acc, a.thresholds(w))
	run := &store.LabRun{WS: w.Cfg.Name, Candidate: clabel, CandSHA: csha, Baseline: blabel, BaseSHA: bsha, Mode: cpr.Mode,
		Created: time.Now(), Result: rep.Result, By: who}
	dir := a.labDir(w.Cfg.Name)
	os.MkdirAll(dir, 0o700)
	stamp := time.Now().UTC().Format("20060102-150405")
	run.Report = filepath.Join(dir, stamp+"-"+candidate+".json")
	if err := writeJSON(run.Report, labFile{Report: rep, Cand: cpr, Base: bpr, Sets: sets}); err != nil {
		return nil, err
	}
	if run.ID, err = a.DB.AddLabRun(*run); err != nil {
		return nil, err
	}
	a.DB.Audit(w.Cfg.Name, who, "lab", fmt.Sprintf("%s vs %s (%s): %s", clabel, blabel, cpr.Mode, rep.Result))
	return &LabResult{Run: run, Report: rep}, nil
}

// labFile — звіт прогону з сирими результатами (щоб перерахувати після прийняття спрацювання). Зберігається назавжди.
type labFile struct {
	Report *lab.Report        `json:"report"`
	Cand   *lab.PackageResult `json:"candidate"`
	Base   *lab.PackageResult `json:"baseline,omitempty"`
	Sets   []lab.Set          `json:"sets"`
}

func writeJSON(p string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func (a *App) thresholds(w *workspace.WS) lab.Thresholds {
	return lab.Thresholds{SlowerYellow: w.Cfg.Lab.SlowerYellow, SlowerRed: w.Cfg.Lab.SlowerRed}
}

// LabReport — звіт прогону.
func (a *App) LabReport(w *workspace.WS, id int64) (*LabResult, error) {
	run, err := a.DB.LabRunByID(w.Cfg.Name, id)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(run.Report)
	if err != nil {
		return nil, err
	}
	var f labFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return &LabResult{Run: run, Report: f.Report}, nil
}

// Accept — людина прийняла перевірене спрацювання (ключ пункту звіту) з причиною: запис у lab/accepted.yaml, звіт
// перераховується.
func (a *App) Accept(w *workspace.WS, id int64, key, reason, who string) (*LabResult, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("an accepted hit needs a reason")
	}
	p := strings.Split(key, "|")
	if len(p) != 4 || len(p[3]) != 64 {
		return nil, fmt.Errorf("bad key %q", key)
	}
	run, err := a.DB.LabRunByID(w.Cfg.Name, id)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(run.Report)
	if err != nil {
		return nil, err
	}
	var f labFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	acc, _ := w.Accepted()
	acc = append(acc, lab.Accepted{Gate: p[0], Rule: p[1], Body: p[2], SHA256: p[3], Reason: reason, By: who, At: time.Now().UTC().Format(time.RFC3339)})
	if err := w.SaveAccepted(acc); err != nil {
		return nil, err
	}
	if err := a.commit(w, fmt.Sprintf("lab: accept %s %s on %s", p[0], p[1], p[3][:12]), who); err != nil {
		return nil, err
	}
	f.Report = lab.Compare(f.Cand, f.Base, f.Sets, acc, a.thresholds(w))
	if err := writeJSON(run.Report, f); err != nil {
		return nil, err
	}
	a.DB.SetLabRunResult(id, f.Report.Result)
	run.Result = f.Report.Result
	a.DB.Audit(w.Cfg.Name, who, "lab-accept", fmt.Sprintf("%s %s %s: %s", p[0], p[1], p[3][:12], reason))
	return &LabResult{Run: run, Report: f.Report}, nil
}

// labGate — перед публікацією: якщо простір вимагає лабораторію, має бути прогін саме цього пакета без червоного.
func (a *App) labGate(w *workspace.WS, rel *store.Release) error {
	if len(w.Cfg.Lab.Sets) == 0 {
		return nil
	}
	runs, _ := a.DB.LabRuns(w.Cfg.Name)
	for _, r := range runs {
		if r.CandSHA != rel.PkgSHA {
			continue
		}
		if r.Result == lab.Red {
			return fmt.Errorf("the lab run #%d of %s is red - fix it or accept the checked hits", r.ID, rel.Version)
		}
		return nil
	}
	return fmt.Errorf("%s has no lab run (hive lab run --candidate %s): the workspace requires the lab before publishing", rel.Version, rel.Version)
}

// ---------------------------------------------------------------- дублікати

// DupGroup — група дублікатів з рішеннями.
type DupGroup struct {
	dupes.Group
	Dropped map[string]string // origin|file|name -> причина
}

// Dupes — групи L0 / L1 / L4 у бібліотеці простору.
func (a *App) Dupes(w *workspace.WS) ([]DupGroup, error) {
	rs, err := a.DB.AllRules(w.Cfg.Name)
	if err != nil {
		return nil, err
	}
	var ms []dupes.Member
	var sims []dupes.SimMember
	for _, r := range rs {
		if r.Kind == "policy" || r.Kind == "dropped" {
			continue
		}
		m := dupes.Member{Origin: r.Origin, File: r.File, Name: r.Name, Kind: r.Kind, Private: r.Private, TextHash: r.TextHash, BodyHash: r.BodyHash}
		ms = append(ms, m)
		sims = append(sims, dupes.SimMember{Member: m, Strings: r.Strings, Cond: r.Cond})
	}
	dec, _ := w.Decisions()
	dropped := map[string]string{}
	for _, d := range dec {
		dropped[d.Source+"|"+d.File+"|"+d.Rule] = d.Reason
	}
	var out []DupGroup
	for _, g := range append(dupes.Groups(ms), dupes.Similar(sims)...) {
		dg := DupGroup{Group: g, Dropped: map[string]string{}}
		for _, m := range g.Members {
			if r, ok := dropped[m.Origin+"|"+m.File+"|"+m.Name]; ok {
				dg.Dropped[m.Origin+"|"+m.File+"|"+m.Name] = r
			}
		}
		out = append(out, dg)
	}
	return out, nil
}

// usedNames — назви правил, на які посилаються умови інших правил джерела (їх не можна відкидати).
func (a *App) usedNames(w *workspace.WS) (map[string]bool, error) {
	src, err := a.rulesTree(w)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "hive-used-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := a.Cache.Extract(*src, tmp); err != nil {
		return nil, err
	}
	used := map[string]bool{}
	err = filepath.Walk(tmp, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !yaraparse.IsRulesFile(p) {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, r := range yaraparse.Parse(string(b)).Rules {
			for _, x := range yaraparse.ConditionWords(r) {
				used[x] = true
			}
		}
		return nil
	})
	return used, err
}

// KeepOne — у групі L0 / L1 лишити одне правило, решту правил джерела відкинути з причиною «duplicate of …».
// Повертає, скільки відкинуто і які лишилися (на них посилаються інші правила або це власні правила).
func (a *App) KeepOne(w *workspace.WS, level, key, keep, who string) (int, []string, error) {
	groups, err := a.Dupes(w)
	if err != nil {
		return 0, nil, err
	}
	for _, g := range groups {
		if g.Level == level && g.Key == key {
			n, skipped, err := a.dropDupes(w, []DupGroup{g}, func(m dupes.Member) bool { return m.Origin+"|"+m.File+"|"+m.Name == keep }, who, false)
			return n, skipped, err
		}
	}
	return 0, nil, fmt.Errorf("no duplicate group %s %s (reload)", level, key)
}

// DropDupesIn — для всіх груп L0 / L1: відкинути члени з файлів, шлях яких містить pattern, якщо в групі лишається
// хоч один член з іншого файлу (напр. копії YARA-Forge, коли те саме правило вже є в signature-base).
func (a *App) DropDupesIn(w *workspace.WS, pattern, who string) (int, []string, error) {
	return a.dropDupesIn(w, pattern, who, false)
}

// PlanDropDupesIn — що відкинула б DropDupesIn (нічого не змінює): кількість і перші рішення.
func (a *App) PlanDropDupesIn(w *workspace.WS, pattern string) (int, []string, error) {
	return a.dropDupesIn(w, pattern, "", true)
}

func (a *App) dropDupesIn(w *workspace.WS, pattern, who string, dry bool) (int, []string, error) {
	if strings.TrimSpace(pattern) == "" {
		return 0, nil, fmt.Errorf("give a file pattern")
	}
	groups, err := a.Dupes(w)
	if err != nil {
		return 0, nil, err
	}
	var sel []DupGroup
	for _, g := range groups {
		if g.Level != "L0" && g.Level != "L1" {
			continue // схожі й варіанти — лише рішенням по кожній групі
		}
		outside := false
		for _, m := range g.Members {
			if !strings.Contains(m.File, pattern) && g.Dropped[m.Origin+"|"+m.File+"|"+m.Name] == "" {
				outside = true
			}
		}
		if outside {
			sel = append(sel, g)
		}
	}
	return a.dropDupes(w, sel, func(m dupes.Member) bool { return !strings.Contains(m.File, pattern) }, who, dry)
}

// dropDupes — dry: нічого не змінювати, у другому значенні — заплановані рішення (до 50) і пропущені.
func (a *App) dropDupes(w *workspace.WS, groups []DupGroup, keep func(dupes.Member) bool, who string, dry bool) (int, []string, error) {
	var planned []string
	used, err := a.usedNames(w)
	if err != nil {
		return 0, nil, err
	}
	n := 0
	var skipped []string
	srcs, _ := w.Sources()
	isSource := map[string]bool{}
	for _, s := range srcs {
		isSource[s.ID] = true
	}
	for _, g := range groups {
		if g.Level == "L4" {
			return 0, nil, fmt.Errorf("an L4 group (same name, different rules) is resolved by renaming or editing, not by dropping")
		}
		var kept *dupes.Member
		for i, m := range g.Members {
			if keep(m) && g.Dropped[m.Origin+"|"+m.File+"|"+m.Name] == "" {
				kept = &g.Members[i]
				break
			}
		}
		if kept == nil {
			continue
		}
		for _, m := range g.Members {
			id := m.Origin + "|" + m.File + "|" + m.Name
			if keep(m) || g.Dropped[id] != "" {
				continue
			}
			switch {
			case !isSource[m.Origin]:
				skipped = append(skipped, m.File+":"+m.Name+" (own rule: edit it)")
				continue
			case used[m.Name] && m.Name != kept.Name:
				skipped = append(skipped, m.File+":"+m.Name+" (other rules use it)")
				continue
			}
			what := "duplicate of"
			switch g.Level {
			case "L2":
				what = "similar to"
			case "L3":
				what = "variant of"
			}
			d := workspace.Decision{Source: m.Origin, File: m.File, Rule: m.Name, Status: "drop", By: who,
				Reason: fmt.Sprintf("%s %s:%s (%s)", what, kept.File, kept.Name, g.Level)}
			n++
			if dry {
				if len(planned) < 50 {
					planned = append(planned, fmt.Sprintf("drop %s:%s — %s", m.File, m.Name, d.Reason))
				}
				continue
			}
			if err := w.SetDecision(d); err != nil {
				return n, skipped, err
			}
		}
	}
	if dry {
		sort.Strings(skipped)
		return n, append(planned, skipped...), nil
	}
	if n > 0 {
		if err := a.commit(w, fmt.Sprintf("drop %d duplicate rules", n), who); err != nil {
			return n, skipped, err
		}
		a.DB.Audit(w.Cfg.Name, who, "dupes", fmt.Sprintf("dropped %d duplicates", n))
	}
	sort.Strings(skipped)
	return n, skipped, nil
}

// ---------------------------------------------------------------- керування простором

// DeleteTarget — прибрати ціль публікації.
func (a *App) DeleteTarget(w *workspace.WS, id, who string) error {
	var out []workspace.Target
	found := false
	for _, t := range w.Cfg.Targets {
		if t.ID == id {
			found = true
			continue
		}
		out = append(out, t)
	}
	if !found {
		return fmt.Errorf("no target %q", id)
	}
	w.Cfg.Targets = out
	if err := w.SaveConfig(); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "target", "remove "+id)
	return a.commit(w, "remove target "+id, who)
}

// SaveTarget — додати / замінити ціль.
func (a *App) SaveTarget(w *workspace.WS, t workspace.Target, who string) error {
	if !workspace.ValidID(t.ID) {
		return fmt.Errorf("target id %q", t.ID)
	}
	switch t.Kind {
	case "folder", "lists-folder", "editions-folder":
		if t.Path == "" {
			return fmt.Errorf("target %s: a folder / UNC path is needed", t.ID)
		}
	case "mirror-branch", "lists-branch", "editions-branch":
		if t.Repo == "" || t.Branch == "" {
			return fmt.Errorf("target %s: repo and branch are needed", t.ID)
		}
	case "release":
		if _, err := publish.NewForge(t, ""); err != nil {
			return err
		}
		if t.CommitTree && (t.Repo == "" || t.Branch == "") {
			return fmt.Errorf("target %s: commit_tree needs repo and branch", t.ID)
		}
	default:
		return fmt.Errorf("target kind %q: folder | mirror-branch | release | lists-folder | lists-branch | editions-folder | editions-branch", t.Kind)
	}
	if IsEditionsTarget(t) {
		if _, err := w.Cfg.TargetEditions(t); err != nil {
			return err
		}
	} else if len(t.Editions) > 0 {
		t.Editions = nil
	}
	var out []workspace.Target
	for _, x := range w.Cfg.Targets {
		if x.ID != t.ID {
			out = append(out, x)
		}
	}
	w.Cfg.Targets = append(out, t)
	if err := w.SaveConfig(); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "target", t.ID+" "+t.Kind)
	return a.commit(w, "target "+t.ID+" ("+t.Kind+")", who)
}

// SetFloor — версія, що вже стоїть на ПК (перша власна має бути більшою).
func (a *App) SetFloor(w *workspace.WS, floor, who string) error {
	if floor != "" && !manifest.ValidVersion(floor) {
		return fmt.Errorf("%q is not vX.Y.Z", floor)
	}
	w.Cfg.VersionFloor = floor
	if err := w.SaveConfig(); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "settings", "version floor "+floor)
	return a.commit(w, "version floor "+floor, who)
}

// ParseRunID — id прогону з рядка.
func ParseRunID(s string) (int64, error) { return strconv.ParseInt(strings.TrimPrefix(s, "#"), 10, 64) }

// Resolved — у групі L0 / L1 лишилося не більше одного невідкинутого правила.
func (g DupGroup) Resolved() bool {
	if g.Level == "L4" {
		return false
	}
	return len(g.Members)-len(g.Dropped) <= 1
}

// ---------------------------------------------------------------- файли, додані в набір через веб

func (a *App) addedDir(id string) string { return filepath.Join(a.Data, "lab", "added", id) }

func removeTree(dir string) {
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil {
			os.Chmod(p, 0o700)
		}
		return nil
	})
	os.RemoveAll(dir)
}

// AddedFile — файл, доданий у набір.
type AddedFile struct {
	Name, SHA256 string
	Size         int64
	Added        time.Time
}

var addedNameRe = regexp.MustCompile(`^[^/\\\x00-\x1f]{1,200}$`)

// AddToLabSet — додати файл (зразок ШПЗ, документ) у наявний набір: у теку набору в сховищі Hive (оригінальна тека
// набору не змінюється). Ім'я зберігається (правила DocScan дивляться на ім'я й розширення), права — лише читання,
// без виконання. Той самий вміст під тим самим ім'ям — нічого не робиться; інший вміст під наявним ім'ям — помилка.
func (a *App) AddToLabSet(id, name string, r io.Reader, who string) (*AddedFile, error) {
	sets, _ := a.DB.LabSets()
	var set *store.LabSet
	for i := range sets {
		if sets[i].ID == id {
			set = &sets[i]
		}
	}
	if set == nil {
		return nil, fmt.Errorf("no lab set %q", id)
	}
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if !addedNameRe.MatchString(name) || strings.HasPrefix(name, ".") || name == "expected.tsv" {
		return nil, fmt.Errorf("file name %q is not allowed", name)
	}
	dir := a.addedDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".upload-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, 2<<30))
	tmp.Close()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("%s is empty", name)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	dst := filepath.Join(dir, name)
	if old, err := os.Open(dst); err == nil {
		oh := sha256.New()
		io.Copy(oh, old)
		old.Close()
		if hex.EncodeToString(oh.Sum(nil)) == sum {
			return &AddedFile{Name: name, SHA256: sum, Size: n}, nil
		}
		return nil, fmt.Errorf("%s already exists in set %s with other content - rename the file", name, id)
	}
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return nil, err
	}
	a.refreshInventory(*set)
	a.DB.Audit("*", who, "lab-set", fmt.Sprintf("add file to %s: %s (%d bytes, sha256 %s)", id, name, n, sum))
	return &AddedFile{Name: name, SHA256: sum, Size: n, Added: time.Now()}, nil
}

// RemoveFromLabSet — прибрати доданий через веб файл (файли оригінальної теки набору не прибираються).
func (a *App) RemoveFromLabSet(id, name, who string) error {
	name = filepath.Base(name)
	p := filepath.Join(a.addedDir(id), name)
	if _, err := os.Stat(p); err != nil || strings.HasPrefix(name, ".") {
		return fmt.Errorf("no added file %q in set %s", name, id)
	}
	os.Chmod(p, 0o600)
	if err := os.Remove(p); err != nil {
		return err
	}
	sets, _ := a.DB.LabSets()
	for _, s := range sets {
		if s.ID == id {
			a.refreshInventory(s)
		}
	}
	a.DB.Audit("*", who, "lab-set", fmt.Sprintf("remove added file from %s: %s", id, name))
	return nil
}

// AddedFiles — файли, додані в набір через веб.
func (a *App) AddedFiles(id string) []AddedFile {
	ents, _ := os.ReadDir(a.addedDir(id))
	var out []AddedFile
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		f := AddedFile{Name: e.Name(), Size: fi.Size(), Added: fi.ModTime()}
		if r, err := os.Open(filepath.Join(a.addedDir(id), e.Name())); err == nil {
			h := sha256.New()
			io.Copy(h, r)
			r.Close()
			f.SHA256 = hex.EncodeToString(h.Sum(nil))
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Added.After(out[j].Added) })
	return out
}

func (a *App) refreshInventory(s store.LabSet) {
	n, b, _ := lab.Inventory(s.Path)
	if st, err := os.Stat(a.addedDir(s.ID)); err == nil && st.IsDir() {
		n2, b2, _ := lab.Inventory(a.addedDir(s.ID))
		n, b = n+n2, b+b2
	}
	s.Files, s.Bytes = n, b
	a.DB.PutLabSet(s)
}
