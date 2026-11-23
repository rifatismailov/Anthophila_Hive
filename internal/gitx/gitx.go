// Package gitx — git через командний рядок (той самий git, що в людини: її налаштування, проксі, сертифікати).
//
// Токени ніколи не потрапляють в URL remote, у .git/config чи в аргументи: дочірньому git їх дає GIT_ASKPASS-помічник,
// що читає токен зі змінної середовища лише цього процесу (Auth).
package gitx

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Auth — доступ до закритого репозиторію: ім'я (для GitHub / Forgejo будь-яке) і токен.
type Auth struct {
	User  string
	Token string
}

// Repo — git-репозиторій (робоча копія або bare).
type Repo struct {
	Dir  string
	Bare bool
	Auth *Auth
}

// Error — помилка git з виводом (токен у виводі замінено на ***).
type Error struct {
	Args   []string
	Output string
	Err    error
}

func (e *Error) Error() string {
	return fmt.Sprintf("git %s: %v: %s", strings.Join(e.Args, " "), e.Err, strings.TrimSpace(e.Output))
}

var askpass = "#!/bin/sh\ncase \"$1\" in\n  Username*|username*) printf '%s\\n' \"$HIVE_GIT_USER\" ;;\n  *) printf '%s\\n' \"$HIVE_GIT_TOKEN\" ;;\nesac\n"

// Run — git з аргументами в теці репозиторію; повертає stdout.
func (r *Repo) Run(args ...string) (string, error) {
	return r.RunInput(nil, args...)
}

// RunInput — те саме зі stdin.
func (r *Repo) RunInput(stdin []byte, args ...string) (string, error) {
	full := args
	if r.Bare {
		full = append([]string{"--git-dir", r.Dir}, args...)
	} else if r.Dir != "" {
		full = append([]string{"-C", r.Dir}, args...)
	}
	// без збережених паролів і без запитів у терміналі
	full = append([]string{"-c", "credential.helper=", "-c", "core.autocrlf=false"}, full...)
	cmd := exec.Command("git", full...)
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var cleanup func()
	if r.Auth != nil && r.Auth.Token != "" {
		d, err := os.MkdirTemp("", "hive-askpass-")
		if err != nil {
			return "", err
		}
		p := filepath.Join(d, "askpass.sh")
		if err := os.WriteFile(p, []byte(askpass), 0o700); err != nil { // помічник без секрету: токен — лише в env
			os.RemoveAll(d)
			return "", err
		}
		cleanup = func() { os.RemoveAll(d) }
		user := r.Auth.User
		if user == "" {
			user = "hive"
		}
		env = append(env, "GIT_ASKPASS="+p, "HIVE_GIT_USER="+user, "HIVE_GIT_TOKEN="+r.Auth.Token)
	}
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if cleanup != nil {
		cleanup()
	}
	if err != nil {
		msg := errb.String()
		shown := append([]string(nil), args...)
		if r.Auth != nil && r.Auth.Token != "" {
			msg = strings.ReplaceAll(msg, r.Auth.Token, "***")
			for i := range shown {
				shown[i] = strings.ReplaceAll(shown[i], r.Auth.Token, "***")
			}
		}
		return out.String(), &Error{Args: shown, Output: msg, Err: err}
	}
	return out.String(), nil
}

// Line — Run з одним рядком результату.
func (r *Repo) Line(args ...string) (string, error) {
	s, err := r.Run(args...)
	return strings.TrimSpace(s), err
}

// Init — новий репозиторій (робоча копія) з гілкою main; файли зберігаються байт у байт (* -text).
func Init(dir string) (*Repo, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	r := &Repo{Dir: dir}
	if _, err := r.Run("init", "-q", "-b", "main"); err != nil {
		return nil, err
	}
	for _, kv := range [][2]string{{"user.name", "Anthophila_Hive"}, {"user.email", "hive@localhost"}, {"commit.gpgsign", "false"}, {"tag.gpgsign", "false"}} {
		if _, err := r.Run("config", kv[0], kv[1]); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("# rules and test lists are stored byte for byte\n* -text\n"), 0o644); err != nil {
		return nil, err
	}
	return r, nil
}

// CommitAll — git add -A і коміт (нічого не змінилося — повертає поточний HEAD без коміту).
func (r *Repo) CommitAll(msg, author string) (string, error) {
	if _, err := r.Run("add", "-A"); err != nil {
		return "", err
	}
	st, err := r.Line("status", "--porcelain")
	if err != nil {
		return "", err
	}
	if st == "" {
		return r.Line("rev-parse", "HEAD")
	}
	args := []string{"commit", "-q", "-m", msg}
	if author != "" {
		args = append(args, "--author", author+" <hive@localhost>")
	}
	if _, err := r.Run(args...); err != nil {
		return "", err
	}
	return r.Line("rev-parse", "HEAD")
}

// Mirror — bare-клон url у dir (або оновлення наявного): усі гілки й теги.
func Mirror(url, dir string, auth *Auth) (*Repo, error) {
	r := &Repo{Dir: dir, Bare: true, Auth: auth}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		os.MkdirAll(filepath.Dir(dir), 0o755)
		c := &Repo{Auth: auth}
		if _, err := c.Run("clone", "-q", "--mirror", url, dir); err != nil {
			return nil, err
		}
		return r, nil
	}
	if _, err := r.Run("remote", "set-url", "origin", url); err != nil {
		return nil, err
	}
	if _, err := r.Run("fetch", "-q", "--prune", "--tags", "origin", "+refs/heads/*:refs/heads/*"); err != nil {
		return nil, err
	}
	return r, nil
}

// Resolve — повний коміт для ref (гілка, тег, скорочений коміт).
func (r *Repo) Resolve(ref string) (string, error) {
	return r.Line("rev-parse", "--verify", "--quiet", ref+"^{commit}")
}

// Extract — дерево коміту в dst (git archive): лише файли, без .git; символьні посилання відкидаються.
func (r *Repo) Extract(commit, dst string) error {
	out, err := r.Run("archive", "--format=tar", commit)
	if err != nil {
		return err
	}
	tr := tar.NewReader(strings.NewReader(out))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(filepath.FromSlash(h.Name))
		if name == "." || strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return fmt.Errorf("unsafe path in %s: %q", commit, h.Name)
		}
		p := filepath.Join(dst, name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			f, err := os.Create(p)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return err
			}
		}
	}
}

// Show — вміст файлу path у коміті (nil, nil — файлу немає).
func (r *Repo) Show(commit, path string) ([]byte, error) {
	if _, err := r.Run("cat-file", "-e", commit+":"+path); err != nil {
		return nil, nil
	}
	s, err := r.Run("show", commit+":"+path)
	return []byte(s), err
}

// OrphanCommit — коміт без батьків з файлами files (ім'я в корені -> вміст). Повертає коміт.
func (r *Repo) OrphanCommit(files map[string][]byte, msg string) (string, error) {
	var tree strings.Builder
	for _, name := range sortedNames(files) {
		if strings.ContainsAny(name, "/\\\t\n") {
			return "", fmt.Errorf("orphan commit: %q is not a top-level name", name)
		}
		h, err := r.RunInput(files[name], "hash-object", "-w", "--stdin")
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&tree, "100644 blob %s\t%s\n", strings.TrimSpace(h), name)
	}
	t, err := r.RunInput([]byte(tree.String()), "mktree")
	if err != nil {
		return "", err
	}
	c, err := r.RunInput([]byte(msg+"\n"), "-c", "user.name=Anthophila_Hive", "-c", "user.email=hive@localhost", "commit-tree", strings.TrimSpace(t))
	return strings.TrimSpace(c), err
}

// ForcePushBranch — commit -> refs/heads/branch на url, лише якщо гілка там досі expected ("" — гілки ще немає):
// --force-with-lease, щоб не затерти чужу публікацію, що відбулася між читанням і записом.
func (r *Repo) ForcePushBranch(url, commit, branch, expected string) error {
	lease := "--force-with-lease=refs/heads/" + branch + ":" + expected
	_, err := r.Run("push", "-q", lease, url, commit+":refs/heads/"+branch)
	return err
}

// RemoteHead — коміт гілки на url ("" — гілки немає).
func (r *Repo) RemoteHead(url, branch string) (string, error) {
	s, err := r.Line("ls-remote", url, "refs/heads/"+branch)
	if err != nil || s == "" {
		return "", err
	}
	return strings.Fields(s)[0], nil
}

// FetchCommit — забрати коміт гілки з url у цей репозиторій (щоб прочитати його файли).
func (r *Repo) FetchBranch(url, branch string) (string, error) {
	if _, err := r.Run("fetch", "-q", url, "+refs/heads/"+branch+":refs/hive/remote/"+branch); err != nil {
		return "", err
	}
	return r.Line("rev-parse", "refs/hive/remote/"+branch)
}

func sortedNames(m map[string][]byte) []string {
	var n []string
	for k := range m {
		n = append(n, k)
	}
	for i := 1; i < len(n); i++ {
		for j := i; j > 0 && n[j] < n[j-1]; j-- {
			n[j], n[j-1] = n[j-1], n[j]
		}
	}
	return n
}

// OrphanTreeCommit — коміт без батьків з файлами files (шлях з "/" -> вміст), з підтеками. Повертає коміт.
func (r *Repo) OrphanTreeCommit(files map[string][]byte, msg string) (string, error) {
	var mk func(prefix string) (string, error)
	mk = func(prefix string) (string, error) {
		var tree strings.Builder
		dirs := map[string]bool{}
		var names []string
		for p := range files {
			if !strings.HasPrefix(p, prefix) {
				continue
			}
			rest := strings.TrimPrefix(p, prefix)
			if i := strings.Index(rest, "/"); i >= 0 {
				dirs[rest[:i]] = true
			} else {
				names = append(names, rest)
			}
		}
		type ent struct{ mode, kind, hash, name string }
		var ents []ent
		for _, n := range names {
			if n == "" || n == "." || n == ".." || strings.ContainsAny(n, "\\\t\n") {
				return "", fmt.Errorf("tree commit: bad name %q", prefix+n)
			}
			h, err := r.RunInput(files[prefix+n], "hash-object", "-w", "--stdin")
			if err != nil {
				return "", err
			}
			ents = append(ents, ent{"100644", "blob", strings.TrimSpace(h), n})
		}
		for d := range dirs {
			if d == "" || d == "." || d == ".." || strings.ContainsAny(d, "\\\t\n") {
				return "", fmt.Errorf("tree commit: bad folder %q", prefix+d)
			}
			h, err := mk(prefix + d + "/")
			if err != nil {
				return "", err
			}
			ents = append(ents, ent{"040000", "tree", h, d})
		}
		sort.Slice(ents, func(i, j int) bool { return ents[i].name < ents[j].name })
		for _, e := range ents {
			fmt.Fprintf(&tree, "%s %s %s\t%s\n", e.mode, e.kind, e.hash, e.name)
		}
		t, err := r.RunInput([]byte(tree.String()), "mktree")
		return strings.TrimSpace(t), err
	}
	t, err := mk("")
	if err != nil {
		return "", err
	}
	c, err := r.RunInput([]byte(msg+"\n"), "-c", "user.name=Anthophila_Hive", "-c", "user.email=hive@localhost", "commit-tree", t)
	return strings.TrimSpace(c), err
}

// Dirs — теки верхнього рівня коміту.
func (r *Repo) Dirs(commit string) ([]string, error) {
	s, err := r.Run("ls-tree", "-d", "--name-only", commit)
	if err != nil {
		return nil, err
	}
	return strings.Fields(s), nil
}
