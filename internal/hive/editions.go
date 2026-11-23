package hive

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/build"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/lists"
	"github.com/rifatismailov/Anthophila_Hive/internal/publish"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
)

// EditionBuild — редакція в зібраному релізі. Пакет правил редакції лежить у Dir (редакції з тим самим складом —
// той самий пакет); списки підписуються під час публікації (поточні робочі копії, serial більший за той, що на цілі).
type EditionBuild struct {
	workspace.Edition
	Variant   string   `json:"variant"`
	Dir       string   `json:"dir,omitempty"`
	PkgSHA    string   `json:"pkg_sha,omitempty"`
	Files     int      `json:"files,omitempty"`
	CritFiles int      `json:"crit_files,omitempty"` // файлів critical/ у пакеті
	OwnFiles  int      `json:"own_files,omitempty"`  // файлів org/ у пакеті
	Result    string   `json:"result"`               // PASS | FAIL | INCOMPLETE | "" (лише списки)
	Notes     []string `json:"notes,omitempty"`
}

// HasEditionsTarget — чи публікує простір редакції (тоді збирання збирає й пакети редакцій).
func HasEditionsTarget(c workspace.Config) bool {
	for _, t := range c.Targets {
		if IsEditionsTarget(t) {
			return true
		}
	}
	return false
}

// IsEditionsTarget — ціль editions-branch / editions-folder.
func IsEditionsTarget(t workspace.Target) bool { return strings.HasPrefix(t.Kind, "editions-") }

// buildEditions — пакети редакцій релізу: кожен склад правил (Variant) — один раз; склад основного пакета
// (rules+own+critical) — це сам основний пакет (main).
func (a *App) buildEditions(w *workspace.WS, in build.Input, o build.Options, main *build.Result, mainRes string) ([]EditionBuild, error) {
	built := map[string]*EditionBuild{}
	mainVariant := "rules+own+critical"
	var out []EditionBuild
	for _, e := range w.Cfg.EditionList() {
		eb := EditionBuild{Edition: e, Variant: e.Variant()}
		if !e.Rules {
			out = append(out, eb)
			continue
		}
		if b, ok := built[eb.Variant]; ok {
			eb.Dir, eb.PkgSHA, eb.Files, eb.CritFiles, eb.OwnFiles, eb.Result, eb.Notes = b.Dir, b.PkgSHA, b.Files, b.CritFiles, b.OwnFiles, b.Result, b.Notes
			out = append(out, eb)
			continue
		}
		var r *build.Result
		res := mainRes
		if eb.Variant == mainVariant {
			r = main
		} else {
			vi := in
			vi.NoOwn, vi.NoCritical = !e.Own, !e.Critical
			if vi.NoCritical {
				vi.Critical = nil
			}
			vo := o
			vo.OutDir = filepath.Join(o.OutDir, "variants", eb.Variant)
			var err error
			if r, err = build.Build(vi, vo); err != nil {
				return nil, fmt.Errorf("edition %s (%s): %w", e.ID, eb.Variant, err)
			}
			res = resultOf(r)
		}
		eb.Dir, eb.PkgSHA, eb.Files, eb.Result, eb.Notes = r.Dir, r.PkgSHA, r.Files, res, r.Notes
		for p := range r.FileSHA {
			switch {
			case strings.HasPrefix(p, "critical/"):
				eb.CritFiles++
			case strings.HasPrefix(p, "org/"):
				eb.OwnFiles++
			}
		}
		c := eb
		built[eb.Variant] = &c
		out = append(out, eb)
	}
	return out, nil
}

// resultOf — підсумок збирання так само, як для основного пакета.
func resultOf(r *build.Result) string {
	if r.OK() {
		return "PASS"
	}
	if r.Contract.Result() == "INCOMPLETE" && (r.Critical == nil || (len(r.Critical.Missed) == 0 && len(r.Critical.Unwanted) == 0)) {
		return "INCOMPLETE"
	}
	return "FAIL"
}

// ReleaseEditions — редакції зібраного релізу ("" — реліз зібрано без редакцій).
func (a *App) ReleaseEditions(rel *store.Release) []EditionBuild {
	var rep struct {
		Editions []EditionBuild `json:"editions"`
	}
	json.Unmarshal([]byte(rel.Report), &rep)
	return rep.Editions
}

// EditionPlan — що піде в ціль редакцій: для підтвердження людиною.
type EditionPlan struct {
	Target    workspace.Target
	Editions  []EditionBuild
	Sensitive map[string][]string // id -> дані організації в редакції (для публічної цілі)
	NeedsAck  bool                // публічна ціль, приватний простір, є дані організації
}

// PlanEditions — редакції релізу для цілі і чи потрібне явне підтвердження публічності.
func (a *App) PlanEditions(w *workspace.WS, rel *store.Release, targetID string) (*EditionPlan, error) {
	t, err := w.Target(targetID)
	if err != nil {
		return nil, err
	}
	if !IsEditionsTarget(*t) {
		return nil, fmt.Errorf("target %s is %s, not an editions target", t.ID, t.Kind)
	}
	want, err := w.Cfg.TargetEditions(*t)
	if err != nil {
		return nil, err
	}
	built := map[string]EditionBuild{}
	for _, e := range a.ReleaseEditions(rel) {
		built[e.ID] = e
	}
	p := &EditionPlan{Target: *t, Sensitive: map[string][]string{}}
	for _, e := range want {
		b, ok := built[e.ID]
		if !ok || (e.Rules && b.Variant != e.Variant()) {
			return nil, fmt.Errorf("edition %s is not in %s as configured now - build a new release", e.ID, rel.Version)
		}
		b.Edition = e // назва й опис — поточні (склад перевірено вище)
		if e.Rules && b.Result != "PASS" {
			return nil, fmt.Errorf("edition %s of %s is %s - it cannot be published", e.ID, rel.Version, b.Result)
		}
		p.Editions = append(p.Editions, b)
		if s := e.Sensitive(); len(s) > 0 {
			p.Sensitive[e.ID] = s
		}
	}
	p.NeedsAck = t.Public && w.Cfg.Visibility != "public" && len(p.Sensitive) > 0
	return p, nil
}

// PublishEditions — опублікувати редакції релізу в ціль editions-* (лише явна дія людини). ackPublic — людина
// окремо підтвердила, що дані організації (критичні правила, списки, власні правила) стануть публічними.
func (a *App) PublishEditions(w *workspace.WS, version, targetID, who string, ackPublic bool, say func(string, ...any)) (*publish.Result, error) {
	rel, err := a.DB.Release(w.Cfg.Name, version)
	if err != nil {
		return nil, err
	}
	if rel.Result != "PASS" {
		return nil, fmt.Errorf("%s is %s - it cannot be published", version, rel.Result)
	}
	if err := a.labGate(w, rel); err != nil {
		return nil, err
	}
	if err := a.fourEyes(w, rel, t0(w, targetID), who); err != nil {
		return nil, err
	}
	plan, err := a.PlanEditions(w, rel, targetID)
	if err != nil {
		return nil, err
	}
	if plan.NeedsAck && !ackPublic {
		return nil, fmt.Errorf("target %s is PUBLIC and workspace %s is private: editions with organisation data (%s) need an explicit confirmation",
			targetID, w.Cfg.Name, strings.Join(sortedKeys(plan.Sensitive), ", "))
	}
	t := plan.Target
	e, err := a.env(w, t, say)
	if err != nil {
		return nil, err
	}
	cur, err := publish.CurrentEditions(t, e)
	if err != nil {
		return nil, fmt.Errorf("target %s: %w", t.ID, err)
	}
	// списки — один раз (той самий підписаний файл у кожній редакції, що його має), serial більший за будь-який на цілі
	var white, black *lists.Signed
	needW, needB := false, false
	for _, eb := range plan.Editions {
		needW, needB = needW || eb.White, needB || eb.Black
	}
	if needW || needB {
		maxSerial := map[string]int64{}
		for _, c := range cur {
			for k, s := range c.Serials {
				if s > maxSerial[k] {
					maxSerial[k] = s
				}
			}
		}
		signed, err := a.SignLists(w, maxSerial)
		if err != nil {
			return nil, err
		}
		for _, s := range signed {
			if s.Kind == "white" {
				white = s
			} else {
				black = s
			}
		}
	}
	in := publish.EditionsInput{Workspace: w.Cfg.Name, Version: version, Created: rel.Created, RulesKey: w.Cfg.RulesKey.Public,
		ListsKey: w.Cfg.ListsKey.Public, Hive: Version, PublicAck: ackPublic}
	for _, eb := range plan.Editions {
		pe := publish.EditionFiles{ID: eb.ID, Title: eb.Title, Description: eb.Description, Contents: eb.Contents(),
			Critical: eb.CritFiles, Own: eb.OwnFiles, Files: eb.Files, PkgSHA: eb.PkgSHA}
		if eb.Rules {
			pe.RulesDir = eb.Dir
		}
		if eb.White {
			pe.Lists = append(pe.Lists, white)
		}
		if eb.Black {
			pe.Lists = append(pe.Lists, black)
		}
		in.Editions = append(in.Editions, pe)
	}
	res, err := publish.Editions(w.Cfg, t, in, cur, e)
	status := "ok"
	if err != nil {
		status = err.Error()
	}
	loc := t.Path
	if res != nil && res.Location != "" {
		loc = res.Location
	}
	ids := make([]string, 0, len(plan.Editions))
	for _, eb := range plan.Editions {
		ids = append(ids, eb.ID)
	}
	a.DB.AddPublication(store.Publication{WS: w.Cfg.Name, What: "editions", Version: version, Target: t.ID, At: time.Now(), By: who, Location: loc, Result: status})
	note := ""
	if plan.NeedsAck {
		note = " [PUBLIC with organisation data, confirmed by " + who + "]"
	}
	a.DB.Audit(w.Cfg.Name, who, "publish", fmt.Sprintf("editions %s (%s) -> %s: %s%s", version, strings.Join(ids, ", "), t.ID, status, note))
	if err != nil {
		return res, err
	}
	if ferr := a.freeze(w, rel, t.ID, who); ferr != nil {
		return res, fmt.Errorf("published, but the release record failed: %w", ferr)
	}
	return res, nil
}

// SaveEditions — набір редакцій простору (nil — повернути набір за замовчуванням).
func (a *App) SaveEditions(w *workspace.WS, es []workspace.Edition, who string) error {
	if es != nil {
		if err := workspace.CheckEditions(es); err != nil {
			return err
		}
	}
	for _, t := range w.Cfg.Targets {
		for _, id := range t.Editions {
			found := false
			for _, e := range es {
				found = found || e.ID == id
			}
			if es == nil {
				for _, e := range workspace.DefaultEditions() {
					found = found || e.ID == id
				}
			}
			if !found {
				return fmt.Errorf("target %s publishes edition %s - change the target first", t.ID, id)
			}
		}
	}
	w.Cfg.Editions = es
	if err := w.SaveConfig(); err != nil {
		return err
	}
	a.DB.Audit(w.Cfg.Name, who, "editions", fmt.Sprintf("%d edition(s)", len(w.Cfg.EditionList())))
	return a.commit(w, "editions", who)
}

func sortedKeys(m map[string][]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// editionAssets — файли пакетів редакцій для .lock (variants/<склад>/<ім'я>).
func editionAssets(rel *store.Release, eds []EditionBuild) map[string]string {
	out := map[string]string{}
	for _, e := range eds {
		if e.Dir == "" || e.Dir == rel.Dir {
			continue
		}
		for _, n := range []string{install.PackageName, install.ManifestName, install.SigName, install.BundleName} {
			out["variants/"+e.Variant+"/"+n] = filepath.Join(e.Dir, n)
		}
	}
	return out
}

// editionsVersion — найбільша версія пакета серед редакцій на цілі.
func editionsVersion(cur map[string]publish.EditionState) string {
	v := ""
	for _, c := range cur {
		if c.Version != "" && (v == "" || manifest.Compare(c.Version, v) > 0) {
			v = c.Version
		}
	}
	return v
}
