// Package yaraexec — єдине місце, де Hive запускає DocScan yara / yarac.
//
// Правила:
//   - лише DocScan-збірка (модуль docscan, --critical-rules): Probe перевіряє це при старті; звичайна yara не
//     скомпілює docscan-policy.yar і не має третього проходу, тож перевірки нею нічого не варті;
//   - Hive лише сканує: прапори, що змінюють або пишуть файли (лікування, витяг VBA, бекапи) чи вимикають пісочницю,
//     заборонені тут, на рівні коду (checkArgs), — навіть помилка в іншому модулі не запустить лікування на наборі;
//   - кожен запуск з тайм-аутом.
//
// Команди компіляції — ТІ САМІ, що в docscan-updater (updater/rules.go: compileRules, compileCritical).
package yaraexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Externals — зовнішні змінні DocScan (THOR / LOKI), як їх задає watcher і updater перед компіляцією.
var Externals = []string{"filename", "filepath", "extension", "filetype", "owner"}

// forbidden — прапори, яких Hive ніколи не передає yara.
var forbidden = []string{
	"--docscan-disarm",     // лікує файл на місці
	"--docscan-extract",    // пише VBA у файл
	"--docscan-backup-dir", // бекапи / карантин
	"--docscan-worker",     // внутрішній режим
	"--docscan-no-sandbox", // діагностика без пісочниці
	"--docscan-confine-check",
}

// Tools — шляхи до DocScan yara і yarac.
type Tools struct {
	Yara    string
	Yarac   string
	Timeout time.Duration // 0 — 10 хвилин
	// Sandbox — тека, у яку yara може писати (черга, тимчасові файли); не порожня — запуск у пісочниці ОС без
	// мережі й без запису деінде (macOS sandbox-exec, Linux bwrap). Для сканування наборів лабораторії (ШПЗ).
	Sandbox string
}

// FromEnv — HIVE_YARA / HIVE_YARAC (порожні, якщо не задані).
func FromEnv() Tools {
	return Tools{Yara: os.Getenv("HIVE_YARA"), Yarac: os.Getenv("HIVE_YARAC")}
}

// Configured — обидва шляхи задані.
func (t Tools) Configured() bool { return t.Yara != "" && t.Yarac != "" }

// ErrForbidden — спроба передати заборонений прапор.
var ErrForbidden = errors.New("forbidden yara option")

func checkArgs(args []string) error {
	for _, a := range args {
		for _, f := range forbidden {
			if a == f || strings.HasPrefix(a, f+"=") {
				return fmt.Errorf("%w %s: Hive only scans, it never cures, extracts or disables the sandbox", ErrForbidden, f)
			}
		}
	}
	return nil
}

// Result — вивід і код завершення.
type Result struct {
	Output   string // stdout, потім stderr (цілими рядками)
	Stderr   string
	ExitCode int
}

func (t Tools) run(bin, dir string, args ...string) (Result, error) {
	if bin == "" {
		return Result{}, fmt.Errorf("the path to DocScan yara / yarac is not set (HIVE_YARA, HIVE_YARAC)")
	}
	if err := checkArgs(args); err != nil {
		return Result{}, err
	}
	to := t.Timeout
	if to == 0 {
		to = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	name, full := bin, args
	if t.Sandbox != "" {
		var err error
		if name, full, err = sandboxed(t.Sandbox, bin, args); err != nil {
			return Result{}, err
		}
	}
	cmd := exec.CommandContext(ctx, name, full...)
	cmd.Dir = dir
	// stdout і stderr — окремо: stdout yara буферизований блоками, stderr — ні; в одному буфері рядок stderr
	// вклинюється посеред рядка stdout на межі блоку, і рядок «правило шлях» губиться (знайдено на 4 539 файлах).
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := Result{Output: out.String(), Stderr: errb.String()}
	if r.Stderr != "" {
		if r.Output != "" && !strings.HasSuffix(r.Output, "\n") {
			r.Output += "\n"
		}
		r.Output += r.Stderr // для викликачів, що шукають «error» у всьому виводі
	}
	if ctx.Err() == context.DeadlineExceeded {
		return r, fmt.Errorf("%s: timed out after %s", filepath.Base(bin), to)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.ExitCode = ee.ExitCode()
		return r, nil
	}
	return r, err
}

// Yara / Yarac — запуск з перевіркою прапорів.
func (t Tools) RunYara(dir string, args ...string) (Result, error) {
	return t.run(t.Yara, dir, args...)
}
func (t Tools) RunYarac(dir string, args ...string) (Result, error) {
	return t.run(t.Yarac, dir, args...)
}

// Info — що знайдено при перевірці.
type Info struct {
	Version string // yara -v
}

// Probe — це справді DocScan yara: є --critical-rules / --file-vars, yarac компілює import "docscan".
func (t Tools) Probe() (Info, error) {
	var inf Info
	r, err := t.RunYara("", "-v")
	if err != nil {
		return inf, fmt.Errorf("yara: %w", err)
	}
	inf.Version = strings.TrimSpace(r.Output)
	r, err = t.RunYara("", "--help")
	if err != nil {
		return inf, fmt.Errorf("yara --help: %w", err)
	}
	for _, f := range []string{"--critical-rules", "--critical-out", "--file-vars", "--docscan-json"} {
		if !strings.Contains(r.Output, f) {
			return inf, fmt.Errorf("%s has no %s - not DocScan's yara (a stock yara cannot check DocScan rules)", t.Yara, f)
		}
	}
	tmp, err := os.MkdirTemp("", "hive-probe-")
	if err != nil {
		return inf, err
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(tmp, "probe.yar")
	os.WriteFile(src, []byte("import \"docscan\"\nrule hive_probe { condition: false }\n"), 0o644)
	r, err = t.RunYarac(tmp, "-w", src, filepath.Join(tmp, "probe.yarc"))
	if err != nil {
		return inf, fmt.Errorf("yarac: %w", err)
	}
	if r.ExitCode != 0 {
		return inf, fmt.Errorf("%s cannot compile import \"docscan\" - not DocScan's yarac: %s", t.Yarac, strings.TrimSpace(r.Output))
	}
	return inf, nil
}

// CompileIndex — пробна компіляція так, як її робить updater перед заміною правил:
//
//	yarac -w -d filename= -d filepath= -d extension= -d filetype= -d owner= <dir>/docscan-index.yar <out>   (cwd = dir)
//
// updater/rules.go: compileRules.
func (t Tools) CompileIndex(dir string) error {
	tmp, err := os.MkdirTemp("", "hive-compile-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "rules-test.yarc")
	args := []string{"-w"}
	for _, e := range Externals {
		args = append(args, "-d", e+"=")
	}
	args = append(args, filepath.Join(dir, "docscan-index.yar"), out)
	r, err := t.RunYarac(dir, args...)
	if err != nil {
		return err
	}
	if _, serr := os.Stat(out); r.ExitCode != 0 || serr != nil {
		return fmt.Errorf("yarac: exit %d %s", r.ExitCode, strings.TrimSpace(r.Output))
	}
	return nil
}

// CompileCritical — critical/*.yar компілюються разом так, як yara64 робить це на скануванні
// (--critical-rules=<тека>): основні правила — одне порожнє правило, файл — пробний; помилка — будь-який рядок
// виводу з "error". Немає .yar — нічого не перевіряється. updater/rules.go: compileCritical.
func (t Tools) CompileCritical(dir string) error {
	ents, _ := os.ReadDir(dir)
	n := 0
	for _, e := range ents {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".yar") {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	tmp, err := os.MkdirTemp("", "hive-critical-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	empty, probe := filepath.Join(tmp, "empty.yar"), filepath.Join(tmp, "probe.txt")
	os.WriteFile(empty, []byte("rule docscan_critical_probe { condition: false }\n"), 0o644)
	os.WriteFile(probe, []byte("probe\r\n"), 0o644)
	r, err := t.RunYara("", "-w", "--critical-rules="+dir, "--critical-out="+filepath.Join(tmp, "q.json"), empty, probe)
	if err != nil {
		return err
	}
	if errs := ErrorLines(r.Output); len(errs) > 0 {
		return fmt.Errorf("critical rules: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ErrorLines — рядки виводу з "error" (будь-який регістр), як у DocScan.
func ErrorLines(out string) []string {
	var errs []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToLower(l), "error") {
			errs = append(errs, strings.TrimSpace(l))
		}
	}
	return errs
}

var (
	sandboxOnce sync.Once
	sandboxName string
)

// SandboxKind — яка пісочниця ОС доступна і справді працює ("" — жодної). bwrap перевіряється пробним запуском:
// у Docker зі стандартним seccomp простори імен користувача заборонені — тоді bwrap є, але не запускається.
func SandboxKind() string {
	sandboxOnce.Do(func() {
		switch runtime.GOOS {
		case "darwin":
			if _, err := exec.LookPath("sandbox-exec"); err == nil {
				if exec.Command("sandbox-exec", "-p", "(version 1)(allow default)(deny network*)", "/usr/bin/true").Run() == nil {
					sandboxName = "sandbox-exec"
				}
			}
		case "linux":
			if _, err := exec.LookPath("bwrap"); err == nil {
				if exec.Command("bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-net", "--die-with-parent", "/bin/true").Run() == nil {
					sandboxName = "bwrap"
				}
			}
		}
	})
	return sandboxName
}

// sandboxed — команда в пісочниці: без мережі, запис лише в writable (і /dev/null).
func sandboxed(writable, bin string, args []string) (string, []string, error) {
	w, err := filepath.Abs(writable)
	if err != nil {
		return "", nil, err
	}
	if r, err := filepath.EvalSymlinks(w); err == nil {
		w = r
	}
	switch SandboxKind() {
	case "sandbox-exec":
		q := strings.ReplaceAll(w, `"`, `\"`)
		profile := `(version 1)(allow default)(deny network*)(deny file-write*)` +
			`(allow file-write* (subpath "` + q + `") (literal "/dev/null") (literal "/dev/dtracehelper"))`
		return "sandbox-exec", append([]string{"-p", profile, bin}, args...), nil
	case "bwrap":
		return "bwrap", append([]string{"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--bind", w, w,
			"--unshare-net", "--unshare-pid", "--die-with-parent", bin}, args...), nil
	}
	return "", nil, fmt.Errorf("no OS sandbox (sandbox-exec / bwrap) to run yara over the lab sets")
}

// CompileYarc — docscan-index.yar теки dir у .yarc out (зовнішні змінні DocScan) і попередження yarac (без -w:
// «may slow down scanning» тощо — для лабораторії).
func (t Tools) CompileYarc(dir, out string) ([]string, error) {
	args := []string{}
	for _, e := range Externals {
		args = append(args, "-d", e+"=")
	}
	args = append(args, filepath.Join(dir, "docscan-index.yar"), out)
	r, err := t.RunYarac(dir, args...)
	if err != nil {
		return nil, err
	}
	var warns []string
	for _, l := range strings.Split(r.Output, "\n") {
		if strings.HasPrefix(l, "warning:") {
			warns = append(warns, strings.TrimSpace(strings.TrimPrefix(l, "warning:")))
		}
	}
	if _, serr := os.Stat(out); r.ExitCode != 0 || serr != nil {
		return warns, fmt.Errorf("yarac: exit %d %s", r.ExitCode, strings.TrimSpace(r.Output))
	}
	return warns, nil
}
