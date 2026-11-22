package hive

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Backup — резервна копія теки даних у tar.gz: hive.db (узгоджена копія VACUUM INTO), workspaces/ (git просторів),
// keys/ (зашифровані — пароль сховища в копію не потрапляє), lab/reports/, out/ (активи релізів), blobs/ (тестові
// документи й активи; конфіденційні — копію зберігати як дані організації). Кеш джерел не копіюється (завантажиться
// знову); копії наборів лабораторії (lab/sets — можуть містити ШПЗ) — лише з withSets.
func (a *App) Backup(dst string, withBlobs, withSets bool) (int, error) {
	tmp, err := os.MkdirTemp("", "hive-backup-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	dbCopy := filepath.Join(tmp, "hive.db")
	if _, err := a.DB.Exec(`VACUUM INTO ?`, dbCopy); err != nil {
		return 0, fmt.Errorf("database copy: %w", err)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	n := 0
	add := func(path, name string) error {
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return nil
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(name)
		if fi.IsDir() {
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			in, err := os.Open(path)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, in)
			in.Close()
			n++
			return err
		}
		return nil
	}
	if err := add(dbCopy, "hive.db"); err != nil {
		return n, err
	}
	dirs := []string{"workspaces", "keys", "lab/reports", "out"}
	if withBlobs {
		dirs = append(dirs, "blobs")
	}
	if withSets {
		dirs = append(dirs, "lab/sets")
	}
	for _, d := range dirs {
		root := filepath.Join(a.Data, d)
		if _, err := os.Stat(root); err != nil {
			continue
		}
		err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(a.Data, p)
			return add(p, rel)
		})
		if err != nil {
			return n, err
		}
	}
	if err := tw.Close(); err != nil {
		return n, err
	}
	return n, gz.Close()
}

// Restore — розгорнути резервну копію в порожню теку даних.
func Restore(src, data string) (int, error) {
	if ents, err := os.ReadDir(data); err == nil && len(ents) > 0 {
		return 0, fmt.Errorf("%s is not empty - restore into a new data folder", data)
	}
	f, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}
	tr := tar.NewReader(gz)
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
		name := filepath.Clean(filepath.FromSlash(h.Name))
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return n, fmt.Errorf("unsafe path in the backup: %q", h.Name)
		}
		p := filepath.Join(data, name)
		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(p, 0o700)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(p), 0o700)
			out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(h.Mode)&0o700|0o600)
			if err != nil {
				return n, err
			}
			_, err = io.Copy(out, tr)
			out.Close()
			if err != nil {
				return n, err
			}
			os.Chtimes(p, time.Now(), h.ModTime)
			n++
		}
	}
	return n, nil
}
