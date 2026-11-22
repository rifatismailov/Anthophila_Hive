package web

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/auth"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/install"
)

// releaseFiles — файли пакета, які кладуться в теку-дзеркало (mirror.url) DocScanUpdater-а; маніфест — останнім.
var releaseFiles = []string{install.PackageName, install.BundleName, install.SigName, install.ManifestName}

// releaseDownload — завантажити зібраний пакет на свій ПК: file=all — один zip з усіма файлами (розпакувати в теку,
// на яку вказує mirror.url), або один файл. Лише publisher і вище (пакет поза Hive = ручна публікація), лише PASS.
func (s *Server) releaseDownload(w http.ResponseWriter, r *http.Request) {
	ss := sess(r)
	if ss == nil || ss.User.Role < auth.Publisher {
		w.WriteHeader(http.StatusForbidden)
		s.render(w, r, "error", "Немає прав", fmt.Errorf("downloading a package needs the role %s", auth.Publisher))
		return
	}
	ws, err := s.wsOf(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rel, err := s.app.DB.Release(ws.Cfg.Name, r.FormValue("v"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rel.Result != "PASS" {
		s.fail(w, r, fmt.Errorf("%s did not pass the checks (%s) - it cannot be downloaded", rel.Version, rel.Result))
		return
	}
	file := r.FormValue("file")
	if file == "all" {
		name := fmt.Sprintf("DocScan-rules-%s-%s.zip", ws.Cfg.Name, rel.Version)
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		zw := zip.NewWriter(w)
		for _, n := range releaseFiles {
			in, err := os.Open(filepath.Join(rel.Dir, n))
			if err != nil {
				zw.Close()
				return
			}
			fi, _ := in.Stat()
			h := &zip.FileHeader{Name: n, Method: zip.Store, Modified: fi.ModTime()}
			out, err := zw.CreateHeader(h)
			if err == nil {
				_, err = io.Copy(out, in)
			}
			in.Close()
			if err != nil {
				zw.Close()
				return
			}
		}
		zw.Close()
		s.app.DB.Audit(ws.Cfg.Name, ss.User.Name, "download", rel.Version+" (all files)")
		return
	}
	ok := false
	for _, n := range releaseFiles {
		ok = ok || n == file
	}
	if !ok {
		s.fail(w, r, fmt.Errorf("unknown file %q", file))
		return
	}
	in, err := os.Open(filepath.Join(rel.Dir, file))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer in.Close()
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	if filepath.Ext(file) == ".zip" {
		w.Header().Set("Content-Type", "application/zip")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	http.ServeContent(w, r, file, time.Time{}, in)
	s.app.DB.Audit(ws.Cfg.Name, ss.User.Name, "download", rel.Version+" "+file)
}
