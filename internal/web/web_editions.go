package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/rifatismailov/Anthophila_Hive/internal/hive"
	"github.com/rifatismailov/Anthophila_Hive/internal/workspace"
)

type editionsData struct {
	Editions []workspace.Edition
	Default  bool                // набір за замовчуванням (не збережений у hive.yaml)
	Targets  []workspace.Target  // цілі редакцій
	Used     map[string][]string // id редакції -> цілі, що її публікують
	Building bool                // збирання збирає редакції (є ціль редакцій)
}

func (s *Server) editionsPage(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := editionsData{Editions: ws.Cfg.EditionList(), Default: len(ws.Cfg.Editions) == 0, Used: map[string][]string{},
		Building: hive.HasEditionsTarget(ws.Cfg)}
	for _, t := range ws.Cfg.Targets {
		if !hive.IsEditionsTarget(t) {
			continue
		}
		d.Targets = append(d.Targets, t)
		es, _ := ws.Cfg.TargetEditions(t)
		for _, e := range es {
			d.Used[e.ID] = append(d.Used[e.ID], t.ID)
		}
	}
	s.render(w, r, "editions", "Редакції", d)
}

// editionsSave — зберегти набір (рядки e<i>_*; порожній id — рядок пропускається; del — прибрати) або повернути
// набір за замовчуванням (action=reset).
func (s *Server) editionsSave(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	if r.FormValue("action") == "reset" {
		if err := s.app.SaveEditions(ws, nil, who(r)); err != nil {
			s.fail(w, r, err)
			return
		}
		s.back(w, r, "/editions", "повернуто редакції за замовчуванням")
		return
	}
	n, _ := strconv.Atoi(r.FormValue("n"))
	if n < 0 || n > 64 {
		s.fail(w, r, fmt.Errorf("too many rows"))
		return
	}
	var es []workspace.Edition
	for i := 0; i < n; i++ {
		f := func(k string) string { return strings.TrimSpace(r.FormValue(fmt.Sprintf("e%d_%s", i, k))) }
		on := func(k string) bool { return f(k) == "on" }
		if f("id") == "" || on("del") {
			continue
		}
		es = append(es, workspace.Edition{ID: f("id"), Title: f("title"), Description: f("desc"),
			Rules: on("rules"), Own: on("own"), Critical: on("critical"), White: on("white"), Black: on("black")})
	}
	if len(es) == 0 {
		s.fail(w, r, fmt.Errorf("at least one edition is needed (or return the default set)"))
		return
	}
	if err := s.app.SaveEditions(ws, es, who(r)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/editions", fmt.Sprintf("збережено редакцій: %d; нові пакети — з наступного збирання", len(es)))
}
