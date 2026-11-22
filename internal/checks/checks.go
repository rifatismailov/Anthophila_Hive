// Package checks — перевірки правил до збирання: лінтер критичних правил (кириличні пастки з CRITICAL-RULES.md),
// компіляція одного файлу DocScan yarac / yara з номерами рядків, тести правила на файлах і прогін набору
// критичних правил на tests/match і tests/no-match (порт cirun/deploy/critical.go: CheckCritical).
package checks

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

// Finding — помилка (error: правило не можна брати) або зауваження (warn).
type Finding struct {
	Line  int    `json:"line"` // 0 — весь файл
	Level string `json:"level"`
	Text  string `json:"text"`
}

// HasErrors — є хоч одна помилка.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Level == "error" {
			return true
		}
	}
	return false
}

var (
	stringDefRe = regexp.MustCompile(`\$[A-Za-z0-9_]*\s*=\s*("(?:[^"\\\n]|\\.)*"|/(?:[^/\\\n]|\\.)+/[is]*)([^\n$]*)`)
	compileErr  = regexp.MustCompile(`\((\d+)\)\s*:\s*(.*)$`)
	critFileErr = regexp.MustCompile(`in --critical-rules file ([^\s;]+)`)
)

func lineAt(src string, off int) int { return 1 + strings.Count(src[:off], "\n") }

func isCyr(r rune) bool { return unicode.Is(unicode.Cyrillic, r) }

// LintCritical — пастки критичних правил (текст нормалізований: нижній регістр, один пробіл; кирилиця в YARA).
func LintCritical(src string) []Finding {
	var out []Finding
	add := func(line int, lvl, f string, a ...any) {
		out = append(out, Finding{Line: line, Level: lvl, Text: fmt.Sprintf(f, a...)})
	}
	m := yaraparse.Mask(src)
	if regexp.MustCompile(`(?m)^\s*import\s`).MatchString(m) {
		add(lineAt(m, regexp.MustCompile(`(?m)^\s*import\s`).FindStringIndex(m)[0]), "error", "критичні правила без import: працюють по тексту документа, модулів там немає")
	}
	if regexp.MustCompile(`(?m)^\s*include\s`).MatchString(m) {
		add(0, "error", "include не працює: кожен файл critical/ компілюється як окремий текст")
	}
	f := yaraparse.Parse(src)
	if len(f.Rules) == 0 {
		add(0, "error", "у файлі немає правил")
	}
	for _, r := range f.Rules {
		var miss []string
		for _, k := range []string{"description", "category", "owner"} {
			if r.MetaValue(k) == "" {
				miss = append(miss, k)
			}
		}
		if len(miss) > 0 {
			add(r.Line, "warn", "правило %s: немає meta %s (чек-лист CRITICAL-RULES.md)", r.Name, strings.Join(miss, ", "))
		}
		base := strings.Index(src[r.HeadStart:], r.Strings)
		if r.Strings == "" || base < 0 {
			continue
		}
		base += r.HeadStart
		for _, d := range stringDefRe.FindAllStringSubmatchIndex(r.Strings, -1) {
			lit := r.Strings[d[2]:d[3]]
			mods := r.Strings[d[4]:d[5]]
			line := lineAt(src, base+d[2])
			nocase := strings.Contains(mods, "nocase")
			if lit[0] == '"' {
				body := lit[1 : len(lit)-1]
				lintText(body, nocase, line, add)
			} else {
				end := strings.LastIndex(lit, "/")
				body, flags := lit[1:end], lit[end+1:]
				lintRegex(body, nocase || strings.Contains(flags, "i"), line, add)
			}
		}
	}
	// одне й те саме зауваження до одного рядка — один раз
	seen := map[string]bool{}
	uniq := out[:0]
	for _, f := range out {
		k := fmt.Sprintf("%d|%s|%s", f.Line, f.Level, f.Text)
		if !seen[k] {
			seen[k] = true
			uniq = append(uniq, f)
		}
	}
	out = uniq
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

func lintText(s string, nocase bool, line int, add func(int, string, string, ...any)) {
	if !nocase && hasUpper(s, false) {
		add(line, "warn", "%q: великі літери не знайдуться — текст документа нормалізований до нижнього регістру", s)
	}
	if strings.Contains(s, "  ") || strings.Contains(s, `\n`) || strings.Contains(s, `\r`) || strings.Contains(s, `\t`) {
		add(line, "warn", "%q: між словами в нормалізованому тексті рівно один пробіл, переносів і табуляцій немає", s)
	}
}

func hasUpper(s string, regex bool) bool {
	rs := []rune(s)
	for i, c := range rs {
		if regex && i > 0 && rs[i-1] == '\\' {
			continue // \S \W \D \B — класи, не літери
		}
		if unicode.IsUpper(c) {
			return true
		}
	}
	return false
}

func lintRegex(s string, nocase bool, line int, add func(int, string, string, ...any)) {
	rs := []rune(s)
	cyr := false
	for _, c := range rs {
		if isCyr(c) {
			cyr = true
		}
	}
	if !nocase && hasUpper(s, true) {
		add(line, "warn", "/%s/: великі літери не знайдуться — текст нормалізований до нижнього регістру", s)
	}
	inClass := false
	classHasNonASCII := false
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if c == '\\' {
			if i+1 < len(rs) {
				if !inClass && rs[i+1] == 'b' && cyr {
					add(line, "warn", "/%s/: \\b не працює з кирилицею — межу слова пишіть (^| ) … ( |$|[.,;:!?)])", s)
				}
				if !inClass && (rs[i+1] == 'n' || rs[i+1] == 'r') {
					add(line, "warn", "/%s/: у нормалізованому тексті немає переносів рядків", s)
				}
			}
			i++
			continue
		}
		switch {
		case c == '[' && !inClass:
			inClass, classHasNonASCII = true, false
		case c == ']' && inClass:
			inClass = false
			if classHasNonASCII {
				add(line, "error", "/%s/: кирилиця всередині [...] — правило не скомпілюється (non-ascii character); пишіть (д|d)", s)
			}
		case inClass:
			if c > 127 {
				classHasNonASCII = true
			}
		case c == '*' || c == '+':
			add(line, "warn", "/%s/: необмежений квантор (*, +, {n,}) — повільно; задайте межу {0,N}", s)
		case c == '{':
			j := strings.IndexRune(string(rs[i:]), '}')
			if j < 0 {
				continue
			}
			q := string(rs[i+1 : i+j])
			lo, hi, ok := strings.Cut(q, ",")
			if ok && strings.TrimSpace(hi) == "" {
				add(line, "warn", "/%s/: необмежений квантор (*, +, {n,}) — повільно; задайте межу {0,N}", s)
			}
			if !ok {
				hi = lo
			}
			n, err := strconv.Atoi(strings.TrimSpace(hi))
			if err == nil && cyr && n > 0 && n <= 6 && prevIsLetterPattern(rs, i) {
				add(line, "warn", "/%s/: {%s} рахує БАЙТИ, кирилична літера — 2 байти: {0,%d} — це до %d літер", s, q, n, n/2)
			}
			i += j
		}
	}
}

// prevIsLetterPattern — перед квантором стоїть клас на кшталт [^ ] або кирилична літера (а не цифри, \d тощо).
func prevIsLetterPattern(rs []rune, i int) bool {
	if i == 0 {
		return false
	}
	p := rs[i-1]
	if isCyr(p) {
		return true
	}
	if p == ']' {
		k := i - 1
		for k > 0 && rs[k] != '[' {
			k--
		}
		cls := string(rs[k:i])
		return cls == "[^ ]" || cls == "[^ ,.]" || strings.HasPrefix(cls, "[^")
	}
	return p == '.'
}

// CompileOwn — компіляція одного файлу так, як він піде в пакет:
//
//	kind "org": yarac -w -d <зовнішні DocScan> файл (окремо; повний пакет компілюється під час збирання);
//	kind "critical": yara --critical-rules=<тека з цим файлом і рештою critical/> (усі разом, як на ПК).
//
// Помилки — з номерами рядків цього файлу.
func CompileOwn(t yaraexec.Tools, kind, name, src string, otherCritical map[string]string) ([]Finding, error) {
	tmp, err := os.MkdirTemp("", "hive-own-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	var out string
	if kind == "critical" {
		dir := filepath.Join(tmp, "critical")
		os.MkdirAll(dir, 0o755)
		for n, s := range otherCritical {
			if n != name {
				os.WriteFile(filepath.Join(dir, n), []byte(s), 0o644)
			}
		}
		os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644)
		if err := t.CompileCritical(dir); err != nil {
			out = err.Error()
		}
		// у повідомленні yara рядок є, файл — окремим рядком: віднесемо до цього файлу лише його помилки
		if out != "" {
			var fs []Finding
			files := critFileErr.FindAllStringSubmatch(out, -1)
			for _, part := range strings.Split(out, "; ") {
				if mm := compileErr.FindStringSubmatch(part); mm != nil {
					ln, _ := strconv.Atoi(mm[1])
					fs = append(fs, Finding{Line: ln, Level: "error", Text: mm[2]})
				}
			}
			other := ""
			for _, fm := range files {
				if fm[1] != name {
					other = fm[1]
				}
			}
			if other != "" && len(files) == 1 {
				return []Finding{{Level: "error", Text: "помилка в іншому файлі critical/: " + other + ": " + out}}, nil
			}
			if len(fs) == 0 {
				fs = append(fs, Finding{Level: "error", Text: out})
			}
			return fs, nil
		}
		return nil, nil
	}
	p := filepath.Join(tmp, name)
	os.WriteFile(p, []byte(src), 0o644)
	args := []string{"-w"}
	for _, e := range yaraexec.Externals {
		args = append(args, "-d", e+"=")
	}
	r, err := t.RunYarac(tmp, append(args, p, filepath.Join(tmp, "out.yarc"))...)
	if err != nil {
		return nil, err
	}
	if r.ExitCode == 0 {
		return nil, nil
	}
	var fs []Finding
	for _, l := range strings.Split(r.Output, "\n") {
		if mm := compileErr.FindStringSubmatch(l); mm != nil {
			ln, _ := strconv.Atoi(mm[1])
			fs = append(fs, Finding{Line: ln, Level: "error", Text: mm[2]})
		} else if strings.TrimSpace(l) != "" {
			fs = append(fs, Finding{Level: "error", Text: strings.TrimSpace(l)})
		}
	}
	return fs, nil
}

// TestFile — файл тесту, уже розкладений на диску (blobs.Materialize) під своїм ім'ям.
type TestFile struct {
	Path   string
	Name   string
	Expect string // match | no-match
	Rule   string // для тесту одного правила
}

// TestResult — результат одного файлу.
type TestResult struct {
	TestFile
	Matched []string // правила, що спрацювали (виявлення) або потрапили в чергу (критичні)
	OK      bool
}

// RunRuleTests — тести одного файлу правил на файлах: kind "org" — yara --file-vars <файл правил> <файл>,
// kind "critical" — yara --critical-rules=<critical/> (рядок "docscan-critical: queued … rules=A,B").
func RunRuleTests(t yaraexec.Tools, kind, rulesPath string, files []TestFile) ([]TestResult, error) {
	tmp, err := os.MkdirTemp("", "hive-ruletest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	empty := filepath.Join(tmp, "empty.yar")
	os.WriteFile(empty, []byte("rule docscan_critical_probe { condition: false }\n"), 0o644)
	var out []TestResult
	for i, f := range files {
		var res yaraexec.Result
		if kind == "critical" {
			res, err = t.RunYara("", "-w", "--file-vars", "--critical-rules="+rulesPath, "--critical-out="+filepath.Join(tmp, fmt.Sprintf("q%d.json", i)), empty, f.Path)
		} else {
			res, err = t.RunYara("", "-w", "--file-vars", rulesPath, f.Path)
		}
		if err != nil {
			return nil, err
		}
		if errs := yaraexec.ErrorLines(res.Output); len(errs) > 0 {
			return nil, fmt.Errorf("%s: %s", f.Name, strings.Join(errs, "; "))
		}
		tr := TestResult{TestFile: f}
		for _, l := range strings.Split(res.Output, "\n") {
			if kind == "critical" {
				if i := strings.Index(l, "rules="); strings.HasPrefix(l, "docscan-critical: queued") && i > 0 {
					tr.Matched = strings.Split(strings.TrimSpace(l[i+6:]), ",")
				}
			} else if fs := strings.Fields(l); len(fs) >= 2 && strings.HasSuffix(l, f.Path) {
				tr.Matched = append(tr.Matched, fs[0])
			}
		}
		hit := false
		for _, m := range tr.Matched {
			if m == f.Rule || f.Rule == "" {
				hit = true
			}
		}
		tr.OK = hit == (f.Expect == "match")
		out = append(out, tr)
	}
	return out, nil
}

// SetResult — прогін набору критичних правил на tests/match і tests/no-match.
type SetResult struct {
	Match, NoMatch   int
	Missed, Unwanted []string // імена файлів
}

// CheckCriticalSet — порт cirun/deploy/critical.go: CheckCritical (прогін): один yara -r по кожній теці, у черзі —
// шлях кожного документа, що спрацював. index — docscan-index.yar пакета (основні правила, як на ПК); "" — порожнє
// правило. matchDir / noMatchDir — теки з документами (можуть бути порожні).
func CheckCriticalSet(t yaraexec.Tools, criticalDir, index, matchDir, noMatchDir string) (*SetResult, error) {
	tmp, err := os.MkdirTemp("", "hive-critset-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if index == "" {
		index = filepath.Join(tmp, "empty.yar")
		os.WriteFile(index, []byte("rule docscan_critical_probe { condition: false }\n"), 0o644)
	}
	r := &SetResult{}
	for _, x := range []struct {
		dir  string
		want bool
	}{{matchDir, true}, {noMatchDir, false}} {
		if x.dir == "" {
			continue
		}
		docs := map[string]string{}
		filepath.Walk(x.dir, func(p string, fi os.FileInfo, err error) error {
			if err == nil && fi.Mode().IsRegular() && !strings.HasPrefix(fi.Name(), ".") {
				rel, _ := filepath.Rel(x.dir, p)
				docs[realPath(p)] = rel
			}
			return nil
		})
		if len(docs) == 0 {
			continue
		}
		q := filepath.Join(tmp, fmt.Sprintf("q-%v.json", x.want))
		res, err := t.RunYara("", "-w", "-r", "--file-vars", "--critical-rules="+criticalDir, "--critical-out="+q, index, x.dir)
		if err != nil {
			return nil, err
		}
		if errs := yaraexec.ErrorLines(res.Output); len(errs) > 0 {
			return nil, fmt.Errorf("yara: %s", strings.Join(errs, "; "))
		}
		queued, err := queuedPaths(q)
		if err != nil {
			return nil, err
		}
		for p, rel := range docs {
			switch {
			case x.want && !queued[p]:
				r.Missed = append(r.Missed, rel)
			case !x.want && queued[p]:
				r.Unwanted = append(r.Unwanted, rel)
			}
		}
		if x.want {
			r.Match = len(docs)
		} else {
			r.NoMatch = len(docs)
		}
	}
	sort.Strings(r.Missed)
	sort.Strings(r.Unwanted)
	return r, nil
}

func queuedPaths(q string) (map[string]bool, error) {
	m := map[string]bool{}
	f, err := os.Open(q)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	for sc.Scan() {
		var rec struct {
			Document struct {
				Path string `json:"path"`
			} `json:"document"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("queue line is not JSON: %w", err)
		}
		m[realPath(rec.Document.Path)] = true
	}
	return m, sc.Err()
}

func realPath(p string) string {
	abs, _ := filepath.Abs(p)
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}
