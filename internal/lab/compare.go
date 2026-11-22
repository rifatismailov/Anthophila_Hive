package lab

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Статуси пунктів звіту.
const (
	Green  = "green"
	Yellow = "yellow"
	Red    = "red"
)

// Accepted — перевірене людиною спрацювання (lab/accepted.yaml у git простору). Діє, доки тіло правила те саме.
type Accepted struct {
	Gate   string `yaml:"gate" json:"gate"`
	Rule   string `yaml:"rule,omitempty" json:"rule,omitempty"`
	Body   string `yaml:"body,omitempty" json:"body,omitempty"`
	SHA256 string `yaml:"sha256" json:"sha256"`
	Reason string `yaml:"reason" json:"reason"`
	By     string `yaml:"by" json:"by"`
	At     string `yaml:"at" json:"at"`
}

// Key — ключ прийняття.
func (a Accepted) Key() string { return a.Gate + "|" + a.Rule + "|" + a.Body + "|" + a.SHA256 }

// Thresholds — пороги швидкості (відсотки сповільнення відносно базового релізу).
type Thresholds struct {
	SlowerYellow int // за замовчуванням 30
	SlowerRed    int // за замовчуванням 100
	MinSeconds   float64
}

// Item — рядок пункту звіту.
type Item struct {
	Set      string `json:"set"`
	File     string `json:"file"`
	SHA      string `json:"sha,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Accepted string `json:"accepted,omitempty"` // причина, якщо прийнято
	Key      string `json:"key,omitempty"`      // для «прийняти»
}

// Gate — пункт звіту.
type Gate struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Items  []Item `json:"items,omitempty"`
	Total  int    `json:"total"`
}

// CatRow — критичні правила по категоріях на розміченому наборі.
type CatRow struct {
	Set, Category                    string
	Found, Missed, False             int
	BaseFound, BaseMissed, BaseFalse int
	HasBase                          bool
}

// TimeRow — швидкість на наборі.
type TimeRow struct {
	Set             string
	Files           int
	Cand, Base      float64
	HasBase, Cached bool
	Sandbox         string
}

// Report — звіт прогону.
type Report struct {
	Candidate, Baseline string
	CandSHA, BaseSHA    string
	Mode                string
	Gates               []Gate
	Categories          []CatRow
	Times               []TimeRow
	Result              string // green | yellow | red
}

const maxItems = 1000

func (g *Gate) add(it Item) {
	g.Total++
	if len(g.Items) < maxItems {
		g.Items = append(g.Items, it)
	}
}

// Compare — кандидат проти базового релізу (base може бути nil: першого релізу немає).
func Compare(c, b *PackageResult, sets []Set, accepted []Accepted, th Thresholds) *Report {
	if th.SlowerYellow == 0 {
		th.SlowerYellow = 30
	}
	if th.SlowerRed == 0 {
		th.SlowerRed = 100
	}
	if th.MinSeconds == 0 {
		th.MinSeconds = 2
	}
	acc := map[string]Accepted{}
	for _, a := range accepted {
		acc[a.Key()] = a
	}
	r := &Report{Candidate: c.Version, CandSHA: c.PkgSHA, Mode: c.Mode}
	if b != nil {
		r.Baseline, r.BaseSHA = b.Version, b.PkgSHA
	}
	detects := func(pr *PackageResult, rules []string) []string {
		var out []string
		for _, x := range rules {
			if ri, ok := pr.Rules[x]; ok && !ri.Info && !ri.Critical {
				out = append(out, x)
			}
		}
		return out
	}
	baseFile := func(set, rel string) *File {
		if b == nil || b.Sets[set] == nil {
			return nil
		}
		for i := range b.Sets[set].Files {
			if b.Sets[set].Files[i].Rel == rel {
				return &b.Sets[set].Files[i]
			}
		}
		return nil
	}
	mark := func(it *Item, gate string) bool {
		if a, ok := acc[gate+"|"+it.Rule+"|"+bodyOf(c, it.Rule)+"|"+it.SHA]; ok {
			it.Accepted = a.Reason + " (" + a.By + ")"
			return true
		}
		it.Key = gate + "|" + it.Rule + "|" + bodyOf(c, it.Rule) + "|" + it.SHA
		return false
	}

	// G1: нові попередження yarac (повільні рядки тощо)
	g1 := Gate{ID: "G1", Title: "компіляція: нові попередження yarac (повільні правила)", Status: Green}
	baseW := map[string]bool{}
	if b != nil {
		for _, w := range b.Warnings {
			baseW[w] = true
		}
	}
	for _, w := range c.Warnings {
		if !baseW[w] {
			g1.add(Item{Detail: w})
		}
	}
	if g1.Total > 0 {
		g1.Status, g1.Detail = Red, fmt.Sprintf("%d нових попереджень (у базовому — %d)", g1.Total, len(b0(b).Warnings))
		if b == nil {
			g1.Status = Yellow
		}
	} else {
		g1.Detail = fmt.Sprintf("попереджень: %d, нових немає", len(c.Warnings))
	}

	g2 := Gate{ID: "G2", Title: "хибні: нові спрацювання на чистих документах", Status: Green}
	g3 := Gate{ID: "G3", Title: "втрачені виявлення на ШПЗ", Status: Green}
	g4 := Gate{ID: "G4", Title: "критичні: tests/match у черзі, tests/no-match — ні", Status: Green}
	g6 := Gate{ID: "G6", Title: "помилки сканування (ворожі файли та інші)", Status: Green}
	g7 := Gate{ID: "G7", Title: "швидкість", Status: Green}
	var red2, red3, red4, red6 int
	cleanFiles, malFiles, malDet := 0, 0, 0
	for _, s := range sets {
		cs := c.Sets[s.ID]
		if cs == nil {
			continue
		}
		tr := TimeRow{Set: s.ID, Files: len(cs.Files), Cand: cs.Seconds, Cached: cs.Cached, Sandbox: cs.Sandbox}
		if b != nil && b.Sets[s.ID] != nil {
			tr.HasBase, tr.Base = true, b.Sets[s.ID].Seconds
		}
		r.Times = append(r.Times, tr)
		for _, e := range cs.Errors {
			it := Item{Set: s.ID, Detail: e}
			g6.add(it)
			if s.Kind == "hostile" {
				red6++
			}
		}
		for _, f := range cs.Files {
			bf := baseFile(s.ID, f.Rel)
			if f.Err != "" && (bf == nil || bf.Err == "") {
				it := Item{Set: s.ID, File: f.Rel, SHA: f.SHA, Detail: f.Err}
				if !mark(&it, "G6") && s.Kind == "hostile" {
					red6++
				}
				g6.add(it)
			}
			switch s.Kind {
			case "clean":
				cleanFiles++
				var old map[string]bool
				if bf != nil {
					old = map[string]bool{}
					for _, x := range bf.Rules {
						old[x] = true
					}
				}
				for _, x := range detects(c, f.Rules) {
					if old != nil && old[x] {
						continue
					}
					it := Item{Set: s.ID, File: f.Rel, SHA: f.SHA, Rule: x}
					if b == nil {
						it.Detail = "немає базового релізу"
					}
					if !mark(&it, "G2") && b != nil {
						red2++
					}
					g2.add(it)
				}
				if f.Queued && (bf == nil || !bf.Queued) {
					g2.add(Item{Set: s.ID, File: f.Rel, SHA: f.SHA, Rule: strings.Join(f.Crit, ","), Detail: "критичні правила: документ у черзі (перевірте, чи справді критичний)"})
				}
			case "malware":
				malFiles++
				now := detects(c, f.Rules)
				if len(now) > 0 {
					malDet++
				}
				if bf == nil {
					if b == nil && len(now) == 0 {
						g3.add(Item{Set: s.ID, File: f.Rel, SHA: f.SHA, Detail: "не виявлено (немає базового релізу для порівняння)"})
					}
					continue
				}
				was := detects(b, bf.Rules)
				if len(was) > 0 && len(now) == 0 {
					it := Item{Set: s.ID, File: f.Rel, SHA: f.SHA, Detail: "було: " + strings.Join(was, ", ")}
					if !mark(&it, "G3") {
						red3++
					}
					g3.add(it)
				} else if len(was) > 0 {
					nowSet := map[string]bool{}
					for _, x := range now {
						nowSet[x] = true
					}
					var lost []string
					for _, x := range was {
						if !nowSet[x] {
							lost = append(lost, x)
						}
					}
					if len(lost) > 0 {
						g3.add(Item{Set: s.ID, File: f.Rel, SHA: f.SHA, Detail: "файл і далі виявляється; не спрацювали: " + strings.Join(lost, ", ")})
					}
				}
			case "critical-match", "critical-no-match":
				want := s.Kind == "critical-match"
				if f.Queued != want {
					it := Item{Set: s.ID, File: f.Rel, SHA: f.SHA, Rule: strings.Join(f.Crit, ",")}
					if want {
						it.Detail = "NOT FOUND"
					} else {
						it.Detail = "FALSE ALARM"
					}
					if !mark(&it, "G4") {
						red4++
					}
					g4.add(it)
				}
			}
		}
		if s.Kind == "critical-labelled" {
			r.Categories = append(r.Categories, categories(s, cs, c, b)...)
		}
		if tr.HasBase && tr.Base >= th.MinSeconds && !tr.Cached {
			pct := int((tr.Cand/tr.Base - 1) * 100)
			switch {
			case pct > th.SlowerRed:
				g7.Status = Red
				g7.add(Item{Set: s.ID, Detail: fmt.Sprintf("%.1f с проти %.1f с (+%d%%)", tr.Cand, tr.Base, pct)})
			case pct > th.SlowerYellow:
				if g7.Status == Green {
					g7.Status = Yellow
				}
				g7.add(Item{Set: s.ID, Detail: fmt.Sprintf("%.1f с проти %.1f с (+%d%%)", tr.Cand, tr.Base, pct)})
			}
		}
	}
	status := func(g *Gate, red int, empty string) {
		switch {
		case red > 0:
			g.Status = Red
		case g.Total > 0:
			g.Status = Yellow
		}
		if g.Detail == "" {
			if g.Total == 0 {
				g.Detail = empty
			} else {
				g.Detail = fmt.Sprintf("%d (червоних %d)", g.Total, red)
			}
		}
	}
	status(&g2, red2, fmt.Sprintf("на %d чистих файлах нових спрацювань немає", cleanFiles))
	status(&g3, red3, fmt.Sprintf("виявлено %d з %d зразків, втрат немає", malDet, malFiles))
	if malFiles > 0 && g3.Detail != "" && g3.Total > 0 {
		g3.Detail = fmt.Sprintf("виявлено %d з %d зразків; %s", malDet, malFiles, g3.Detail)
	}
	status(&g4, red4, "усе як очікується")
	status(&g6, red6, "помилок немає")
	if g7.Total == 0 {
		g7.Detail = "у межах порогів (або без порівняння: кеш / коротко)"
	} else {
		g7.Detail = fmt.Sprintf("сповільнення: жовте > %d%%, червоне > %d%%", th.SlowerYellow, th.SlowerRed)
	}
	g5 := Gate{ID: "G5", Title: "критичні по категоріях (розмічені набори)", Status: Green, Detail: "немає розмічених наборів"}
	if len(r.Categories) > 0 {
		g5.Detail = "знайдено / пропущено / хибні — таблиця нижче"
		for _, cr := range r.Categories {
			if cr.HasBase && (cr.Missed > cr.BaseMissed || cr.False > cr.BaseFalse) {
				g5.Status = Yellow
				g5.add(Item{Set: cr.Set, Rule: cr.Category, Detail: fmt.Sprintf("пропущено %d (було %d), хибних %d (було %d)", cr.Missed, cr.BaseMissed, cr.False, cr.BaseFalse)})
			}
		}
	}
	r.Gates = []Gate{g1, g2, g3, g4, g5, g6, g7}
	r.Result = Green
	for _, g := range r.Gates {
		if g.Status == Red {
			r.Result = Red
			break
		}
		if g.Status == Yellow {
			r.Result = Yellow
		}
	}
	return r
}

func b0(b *PackageResult) *PackageResult {
	if b == nil {
		return &PackageResult{}
	}
	return b
}

func bodyOf(pr *PackageResult, rule string) string {
	if ri, ok := pr.Rules[rule]; ok {
		return ri.Body[:16]
	}
	return ""
}

// labels — expected.tsv розміченого набору: шлях (folder/file або file) -> категорії ("none" — жодної).
func labels(dir string) (map[string][]string, error) {
	f, err := os.Open(filepath.Join(dir, "expected.tsv"))
	if err != nil {
		return nil, fmt.Errorf("a labelled set needs expected.tsv: %w", err)
	}
	defer f.Close()
	rd := csv.NewReader(f)
	rd.Comma, rd.FieldsPerRecord, rd.LazyQuotes = '\t', -1, true
	rows, err := rd.ReadAll()
	if err != nil || len(rows) == 0 {
		return nil, fmt.Errorf("expected.tsv: %v", err)
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	fi, ok1 := col["file"]
	ei, ok2 := col["expected"]
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("expected.tsv: no file / expected columns")
	}
	out := map[string][]string{}
	for _, row := range rows[1:] {
		if len(row) <= ei || len(row) <= fi {
			continue
		}
		p := row[fi]
		if di, ok := col["folder"]; ok && di < len(row) && row[di] != "" {
			p = row[di] + "/" + row[fi]
		}
		var cats []string
		for _, c := range strings.Split(row[ei], ",") {
			if c = strings.TrimSpace(c); c != "" && c != "none" {
				cats = append(cats, c)
			}
		}
		out[p] = cats
	}
	return out, nil
}

func categories(s Set, cs *SetResult, c, b *PackageResult) []CatRow {
	lab, err := labels(s.Path)
	if err != nil {
		return []CatRow{{Set: s.ID, Category: "помилка: " + err.Error()}}
	}
	byBase := map[string][]string{}
	for p := range lab {
		byBase[filepath.Base(p)] = append(byBase[filepath.Base(p)], p)
	}
	count := func(pr *PackageResult, sr *SetResult) map[string]*CatRow {
		rows := map[string]*CatRow{}
		get := func(cat string) *CatRow {
			if rows[cat] == nil {
				rows[cat] = &CatRow{Set: s.ID, Category: cat}
			}
			return rows[cat]
		}
		for _, f := range sr.Files {
			want, ok := lab[f.Rel]
			if !ok {
				if ps := byBase[filepath.Base(f.Rel)]; len(ps) == 1 {
					want, ok = lab[ps[0]]
				}
			}
			if !ok {
				continue
			}
			got := map[string]bool{}
			for _, x := range f.Crit {
				if ri, ok := pr.Rules[x]; ok {
					got[ri.Category] = true
				}
			}
			wantSet := map[string]bool{}
			for _, w := range want {
				wantSet[w] = true
				if got[w] {
					get(w).Found++
				} else {
					get(w).Missed++
				}
			}
			for g := range got {
				if !wantSet[g] {
					get(g).False++
				}
			}
		}
		return rows
	}
	cr := count(c, cs)
	var br map[string]*CatRow
	if b != nil && b.Sets[s.ID] != nil {
		br = count(b, b.Sets[s.ID])
	}
	var out []CatRow
	for k, v := range cr {
		if br != nil {
			v.HasBase = true
			if x := br[k]; x != nil {
				v.BaseFound, v.BaseMissed, v.BaseFalse = x.Found, x.Missed, x.False
			}
		}
		out = append(out, *v)
	}
	for k, x := range br {
		if cr[k] == nil {
			out = append(out, CatRow{Set: s.ID, Category: k, HasBase: true, BaseFound: x.Found, BaseMissed: x.Missed, BaseFalse: x.False})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out
}
