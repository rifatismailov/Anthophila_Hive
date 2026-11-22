// Package blobs — сховище файлів Hive поза git: тестові документи, зразки ШПЗ, активи релізів.
//
// Файл зберігається за sha256 вмісту (<root>/ab/<sha256>), без імені й без розширення, лише на читання (0400):
// зразок ШПЗ не відкриється подвійним кліком і не має прав на виконання. Ім'я файлу й вид набору — у метаданих
// (tests.yaml робочого простору), не тут.
package blobs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Store — сховище в теці Root.
type Store struct{ Root string }

func (s Store) path(sha string) string { return filepath.Join(s.Root, sha[:2], sha) }

// Put — зберегти вміст r; повертає sha256 і розмір. Той самий вміст — той самий файл.
func (s Store) Put(r io.Reader) (string, int64, error) {
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return "", 0, err
	}
	tmp, err := os.CreateTemp(s.Root, ".put-")
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	tmp.Close()
	if err != nil {
		return "", 0, err
	}
	sha := hex.EncodeToString(h.Sum(nil))
	dst := s.path(sha)
	if _, err := os.Stat(dst); err == nil {
		return sha, n, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", 0, err
	}
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", 0, err
	}
	return sha, n, nil
}

// PutFile — Put з файлу.
func (s Store) PutFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	return s.Put(f)
}

// Path — шлях до файлу sha256 (помилка — немає або неправильний хеш).
func (s Store) Path(sha string) (string, error) {
	if !shaRe.MatchString(sha) {
		return "", fmt.Errorf("blob %q: not a sha256", sha)
	}
	p := s.path(sha)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("blob %s: %w", sha[:12], err)
	}
	return p, nil
}

// Has — файл є.
func (s Store) Has(sha string) bool { _, err := s.Path(sha); return err == nil }

// Materialize — копія файлу sha256 під ім'ям name у теці dir (для сканування з --file-vars: правила бачать справжнє
// ім'я й розширення). Без прав на виконання.
func (s Store) Materialize(sha, dir, name string) (string, error) {
	src, err := s.Path(sha)
	if err != nil {
		return "", err
	}
	name = filepath.Base(name)
	if name == "." || name == "/" || name == "" {
		name = sha
	}
	dst := filepath.Join(dir, name)
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return dst, err
}
