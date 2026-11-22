package web

import (
	"fmt"
	"net/http"

	"github.com/rifatismailov/Anthophila_Hive/internal/hive"
	"github.com/rifatismailov/Anthophila_Hive/internal/vendor"
)

type vendorData struct {
	Cfg     *vendor.Config
	Files   int
	Report  string
	Update  *hive.VendorUpdate
	Changes map[string]int
}

func (s *Server) vendorRoutes() map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		"/vendor": s.vendorPage, "/vendor/import": s.vendorImport, "/vendor/update": s.vendorUpdate,
		"/vendor/pin": s.vendorPin, "/vendor/regenerate": s.vendorRegenerate, "/vendor/history": s.vendorHistory,
		"/vendor/fetch": s.vendorFetch,
	}
}

func (s *Server) vendorPage(w http.ResponseWriter, r *http.Request) {
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := vendorData{}
	var sel []vendor.Selection
	if d.Cfg, sel, err = ws.Vendor(); err != nil {
		s.fail(w, r, err)
		return
	}
	d.Files = len(sel)
	d.Report, _ = s.app.VendorReport(ws)
	if len(d.Report) > 200000 {
		d.Report = d.Report[:200000] + "\n… (повний звіт — vendor/report.md у git простору)"
	}
	s.render(w, r, "vendor", "Вендорні правила", d)
}

func (s *Server) vendorImport(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	rep, err := s.app.ImportVendor(ws, r.FormValue("script"), r.FormValue("selection"), r.FormValue("from"), who(r), nil)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/vendor", fmt.Sprintf("генератор: %d файлів, %d правил", rep.Files, rep.Rules))
}

func (s *Server) vendorUpdate(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	u, err := s.app.VendorUpdatePreview(ws, r.FormValue("source"), r.FormValue("ref"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := vendorData{Update: u, Changes: map[string]int{}}
	d.Cfg, _, _ = ws.Vendor()
	for _, c := range u.Changes {
		d.Changes[c.Status]++
	}
	s.render(w, r, "vendor", "Вендорні правила", d)
}

func (s *Server) vendorPin(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	rep, err := s.app.VendorPin(ws, r.FormValue("source"), r.FormValue("commit"), who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/vendor", fmt.Sprintf("закріплено; згенеровано %d правил", rep.Rules))
}

func (s *Server) vendorRegenerate(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	rep, err := s.app.VendorRegenerate(ws, "manual", who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/vendor", fmt.Sprintf("згенеровано: %d файлів, %d правил", rep.Files, rep.Rules))
}

func (s *Server) vendorHistory(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	n, err := s.app.ImportVendorHistory(ws, r.FormValue("repo"), r.FormValue("path"), who(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/vendor", fmt.Sprintf("імпортовано версій звіту: %d", n))
}

func (s *Server) vendorFetch(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	if err := s.app.FetchVendor(ws, r.FormValue("from"), nil); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/vendor", "джерела завантажено")
}
