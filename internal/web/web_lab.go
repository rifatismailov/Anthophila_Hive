package web

import (
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/rifatismailov/Anthophila_Hive/internal/contract"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/hive"
	"github.com/rifatismailov/Anthophila_Hive/internal/lab"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
)

func (s *Server) labRoutes() map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		"/lab": s.labPage, "/lab/set/add": s.labSetAdd, "/lab/set/remove": s.labSetRemove, "/lab/set/files": s.labSetFiles, "/lab/set/file/remove": s.labSetFileRemove, "/lab/config": s.labConfig,
		"/lab/run": s.labRun, "/lab/report": s.labReport, "/lab/accept": s.labAccept,
		"/dupes": s.dupesPage, "/dupes/keep": s.dupesKeep, "/dupes/drop-in": s.dupesDropIn,
		"/settings": s.settings, "/settings/floor": s.settingsFloor, "/target/delete": s.targetDelete,
		"/reproduce": s.reproduce, "/verify": s.verify,
	}
}

func (s *Server) postWS(w http.ResponseWriter, r *http.Request) *workspace.WS {
	ws, err := s.wsOf(r)
	if err != nil || !post(r) {
		s.fail(w, r, fmt.Errorf("POST with a workspace"))
		return nil
	}
	return ws
}

// ---------------------------------------------------------------- лабораторія

type labData struct {
	Sets     []store.LabSet
	Used     map[string]bool
	Cfg      workspace.Lab
	Runs     []store.LabRun
	Releases []store.Release
	Kinds    []string
	Sandbox  string
	Added    map[string][]hive.AddedFile
}

func (s *Server) labPage(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := labData{Used: map[string]bool{}, Cfg: ws.Cfg.Lab, Kinds: lab.Kinds}
	d.Sets, _ = s.app.DB.LabSets()
	d.Added = map[string][]hive.AddedFile{}
	for _, set := range d.Sets {
		d.Added[set.ID] = s.app.AddedFiles(set.ID)
	}
	for _, id := range ws.Cfg.Lab.Sets {
		d.Used[id] = true
	}
	d.Runs, _ = s.app.DB.LabRuns(ws.Cfg.Name)
	d.Releases, _ = s.app.DB.Releases(ws.Cfg.Name)
	d.Sandbox = sandboxName()
	s.render(w, r, "lab", "Лабораторія", d)
}

func (s *Server) labSetAdd(w http.ResponseWriter, r *http.Request) {
	if s.postWS(w, r) == nil {
		return
	}
	set, err := s.app.AddLabSet(r.FormValue("id"), r.FormValue("kind"), r.FormValue("path"), r.FormValue("copy") == "on", r.FormValue("confidential") == "on", who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lab", fmt.Sprintf("набір %s: %d файлів", set.ID, set.Files))
}

func (s *Server) labSetRemove(w http.ResponseWriter, r *http.Request) {
	if s.postWS(w, r) == nil {
		return
	}
	if err := s.app.RemoveLabSet(r.FormValue("id"), who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lab", "набір прибрано")
}

// labSetFiles — додати файли (кілька за раз) у наявний набір.
func (s *Server) labSetFiles(w http.ResponseWriter, r *http.Request) {
	if s.postWS(w, r) == nil {
		return
	}
	id := r.FormValue("id")
	var fhs []*multipart.FileHeader
	if r.MultipartForm != nil {
		fhs = r.MultipartForm.File["file"]
	}
	if len(fhs) == 0 {
		s.fail(w, r, fmt.Errorf("no files chosen"))
		return
	}
	var done []string
	for _, fh := range fhs {
		f, err := fh.Open()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		af, err := s.app.AddToLabSet(id, fh.Filename, f, who(r))
		f.Close()
		if err != nil {
			s.fail(w, r, fmt.Errorf("%v (added before the error: %d)", err, len(done)))
			return
		}
		done = append(done, af.Name)
	}
	s.back(w, r, "/lab", fmt.Sprintf("набір %s: додано %d — %s; запустіть прогін ще раз", id, len(done), strings.Join(done, ", ")))
}

func (s *Server) labSetFileRemove(w http.ResponseWriter, r *http.Request) {
	if s.postWS(w, r) == nil {
		return
	}
	if err := s.app.RemoveFromLabSet(r.FormValue("id"), r.FormValue("name"), who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lab", "файл прибрано з набору "+r.FormValue("id"))
}

func (s *Server) labConfig(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	cfg := workspace.Lab{Sets: r.Form["sets"], Mode: r.FormValue("mode")}
	fmt.Sscan(r.FormValue("slower_yellow"), &cfg.SlowerYellow)
	fmt.Sscan(r.FormValue("slower_red"), &cfg.SlowerRed)
	if err := s.app.SetLabConfig(ws, cfg, who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lab", "налаштування лабораторії збережено")
}

func (s *Server) labRun(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	lr, err := s.app.RunLab(ws, r.FormValue("candidate"), r.FormValue("baseline"), r.FormValue("mode"), who(r), nil)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lab/report", "", "id", fmt.Sprint(lr.Run.ID))
}

func (s *Server) labReport(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := hive.ParseRunID(r.FormValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	lr, err := s.app.LabReport(ws, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "labreport", fmt.Sprintf("Прогін #%d", id), lr)
}

func (s *Server) labAccept(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	id, err := hive.ParseRunID(r.FormValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	lr, err := s.app.Accept(ws, id, r.FormValue("key"), r.FormValue("reason"), who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/lab/report", "прийнято; прогін тепер "+lr.Report.Result, "id", fmt.Sprint(id))
}

// ---------------------------------------------------------------- дублікати

type dupesData struct {
	Groups []hive.DupGroup
	Count  map[string]int
	Level  string
	Plan   *dropPlan
}

type dropPlan struct {
	Pattern string
	N       int
	Lines   []string
}

func (s *Server) dupesPage(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := s.app.Dupes(ws)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := dupesData{Count: map[string]int{}, Level: r.FormValue("level")}
	for _, g := range all {
		d.Count[g.Level]++
		if g.Resolved() {
			d.Count["resolved"]++
			if r.FormValue("all") == "" {
				continue
			}
		}
		if (d.Level == "" || g.Level == d.Level) && len(d.Groups) < 300 {
			d.Groups = append(d.Groups, g)
		}
	}
	s.render(w, r, "dupes", "Дублікати", d)
}

func (s *Server) dupesKeep(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	n, skipped, err := s.app.KeepOne(ws, r.FormValue("level"), r.FormValue("key"), r.FormValue("keep"), who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/dupes", dropMsg(n, skipped), "level", r.FormValue("level"))
}

func (s *Server) dupesDropIn(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	pattern := r.FormValue("pattern")
	if r.FormValue("confirm") == "" {
		pn, plan, err := s.app.PlanDropDupesIn(ws, pattern)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		all, _ := s.app.Dupes(ws)
		d := dupesData{Count: map[string]int{}, Plan: &dropPlan{Pattern: pattern, N: pn, Lines: plan}}
		for _, g := range all {
			d.Count[g.Level]++
		}
		s.render(w, r, "dupes", "Дублікати", d)
		return
	}
	if r.FormValue("confirm") != r.FormValue("n") {
		s.fail(w, r, fmt.Errorf("type the number of rules to confirm"))
		return
	}
	n, skipped, err := s.app.DropDupesIn(ws, pattern, who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/dupes", dropMsg(n, skipped))
}

func dropMsg(n int, skipped []string) string {
	m := fmt.Sprintf("відкинуто дублікатів: %d", n)
	if len(skipped) > 0 {
		if len(skipped) > 10 {
			skipped = append(skipped[:10], "…")
		}
		m += "; лишено: " + strings.Join(skipped, "; ")
	}
	return m
}

// ---------------------------------------------------------------- налаштування

type settingsData struct {
	Reproduce *reproduceResult
	Verify    *contract.Report
	VerifyErr string
	Path      string
}

type reproduceResult struct {
	Version string
	Files   int
	Diff    []string
	Err     string
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	if _, err := s.wsOf(r); err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, "settings", "Налаштування", settingsData{})
}

func (s *Server) settingsFloor(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	if err := s.app.SetFloor(ws, strings.TrimSpace(r.FormValue("floor")), who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/settings", "збережено")
}

func (s *Server) targetDelete(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	if err := s.app.DeleteTarget(ws, r.FormValue("id"), who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/settings", "ціль прибрано")
}

func (s *Server) reproduce(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	v := r.FormValue("v")
	res := &reproduceResult{Version: v}
	n, diff, err := s.app.Reproduce(ws, v)
	res.Files, res.Diff = n, diff
	if err != nil {
		res.Err = err.Error()
	}
	s.render(w, r, "settings", "Налаштування", settingsData{Reproduce: res})
}

// verify — перевірка будь-якого пакета на диску чи за адресою (як hive verify): ключ простору + офіційний.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	path := strings.TrimSpace(r.FormValue("path"))
	o := contract.Options{Keys: append(append([]string{ws.Cfg.RulesKey.Public}, ws.Cfg.RulesKey.Previous...), manifest.OfficialKeys...), NewerThan: r.FormValue("newer")}
	if s.app.Tools.Configured() {
		o.Compiler = s.app.Tools
	}
	d := settingsData{Path: path}
	rep, err := contract.VerifyRules(path, o)
	if err != nil {
		d.VerifyErr = err.Error()
	}
	d.Verify = rep
	s.render(w, r, "settings", "Налаштування", d)
}
