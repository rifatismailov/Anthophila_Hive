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

// releaseFiles — файли релізу, які можна завантажити окремо.
var releaseFiles = []string{install.PackageName, install.BundleName, install.SigName, install.ManifestName}

// mirrorFiles — те, що читає DocScanUpdater з теки-дзеркала (rules.mirror.url). Bundle — ті самі три файли в одному
// zip для ручного встановлення (-InstallRules), тож у zip для теки його немає.
var mirrorFiles = []string{install.PackageName, install.SigName, install.ManifestName}

// releaseDownload — завантажити зібраний пакет на свій ПК: file=mirror — zip з трьома файлами для теки-дзеркала
// (розпакувати в теку, на яку вказує mirror.url), або один файл (напр. DocScan-rules-bundle.zip для -InstallRules).
// Лише publisher і вище (пакет поза Hive = ручна публікація), лише PASS.
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
	// редакція (пакет правил редакції; списки підписуються лише під час публікації)
	dir, label := rel.Dir, ws.Cfg.Name
	if id := r.FormValue("edition"); id != "" {
		dir = ""
		for _, e := range s.app.ReleaseEditions(rel) {
			if e.ID == id && e.Rules && e.Result == "PASS" {
				dir, label = e.Dir, ws.Cfg.Name+"-"+e.ID
			}
		}
		if dir == "" {
			s.fail(w, r, fmt.Errorf("%s has no rules package of edition %q", rel.Version, id))
			return
		}
	}
	file := r.FormValue("file")
	if file == "mirror" {
		name := fmt.Sprintf("DocScan-rules-%s-%s-mirror.zip", label, rel.Version)
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		zw := zip.NewWriter(w)
		for _, n := range mirrorFiles {
			in, err := os.Open(filepath.Join(dir, n))
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
		s.app.DB.Audit(ws.Cfg.Name, ss.User.Name, "download", rel.Version+" "+label+" (mirror folder files)")
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
	in, err := os.Open(filepath.Join(dir, file))
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
	s.app.DB.Audit(ws.Cfg.Name, ss.User.Name, "download", rel.Version+" "+label+" "+file)
}
