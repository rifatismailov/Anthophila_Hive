// Package lab — тестова лабораторія (PLAN.md, розділ 5): прогін пакета правил на наборах файлів і порівняння
// кандидата з попереднім релізом на тих самих файлах.
//
// Набори: clean (чисті документи організації), malware (зразки ШПЗ — лише сканування), critical-match /
// critical-no-match (документи для критичних правил), critical-labelled (розмічений набір з expected.tsv, як у
// eval_sensitive.py), hostile (зламані / ворожі файли). Набір — тека за посиланням (ref) або копія у сховищі Hive
// (copy); у git нічого з наборів не потрапляє.
//
// Режими: fast — один yara -r -p N по теці (вивід «правило шлях», черга третього проходу); full — процес на файл з
// --docscan-json, як watcher (збіги другого проходу теж). Сканування — у пісочниці ОС (без мережі, запис лише в
// робочу теку), прапори лікування заборонені в yaraexec. Результати кешуються за (sha пакета, відбиток набору, режим,
// версія yara): базовий реліз на тих самих файлах вдруге не проганяється.
package lab

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/dupes"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

// Kinds — види наборів.
var Kinds = []string{"clean", "malware", "critical-match", "critical-no-match", "critical-labelled", "hostile"}

// ValidKind — вид набору відомий.
func ValidKind(k string) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// Set — набір файлів.
type Set struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Mode string `json:"mode"` // ref | copy
	Path string `json:"path"` // тека (ref — оригінал, copy — копія у сховищі Hive)
	// Extra — файли, додані в набір через веб (сховище Hive; оригінальна тека не змінюється); у звітах — «+added/…»
	Extra        string `json:"extra,omitempty"`
	Confidential bool   `json:"confidential"`
	Files        int    `json:"files"`
	Bytes        int64  `json:"bytes"`
	Added        string `json:"added"`
	By           string `json:"by"`
}

// File — результат одного файлу.
type File struct {
	Rel    string   `json:"rel"`
	SHA    string   `json:"sha"`
	Rules  []string `json:"rules,omitempty"`  // правила виявлення / політики, що спрацювали
	Queued bool     `json:"queued,omitempty"` // третій прохід: документ у черзі
	Crit   []string `json:"crit,omitempty"`   // критичні правила, що спрацювали
	Err    string   `json:"err,omitempty"`
}

// SetResult — прогін одного набору.
type SetResult struct {
	Set     string   `json:"set"`
	Kind    string   `json:"kind"`
	Files   []File   `json:"files"`
	Seconds float64  `json:"seconds"`
	Errors  []string `json:"errors,omitempty"` // помилки yara, що не прив'язані до файлу
	Sandbox string   `json:"sandbox"`
	Cached  bool     `json:"-"`
}

// RuleInfo — що відомо про правило пакета.
type RuleInfo struct {
	Info     bool   `json:"info,omitempty"`     // docscan_info / severity INFO: не підвищує вердикт
	Critical bool   `json:"critical,omitempty"` // з critical/
	Category string `json:"category,omitempty"` // критичні: meta category або ORG_<КОД>_
	Body     string `json:"body"`               // dupes.BodyHash
	File     string `json:"file"`
}

// PackageResult — прогін одного пакета на наборах.
type PackageResult struct {
	PkgSHA   string                `json:"pkg_sha"`
	Version  string                `json:"version"`
	Mode     string                `json:"mode"`
	Warnings []string              `json:"warnings,omitempty"` // попередження yarac (повільні рядки тощо)
	Rules    map[string]RuleInfo   `json:"rules"`
	Sets     map[string]*SetResult `json:"sets"`
}

// Runner — чим і де проганяти.
type Runner struct {
	Tools   yaraexec.Tools
	Cache   string // тека кешу результатів
	Work    string // тимчасова тека
	Threads int
	Say     func(string, ...any)
}

func (r Runner) say(f string, a ...any) {
	if r.Say != nil {
		r.Say(f, a...)
	}
}

// Inventory — кількість файлів і байтів теки.
func Inventory(dir string) (int, int64, error) {
	n, b := 0, int64(0)
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode().IsRegular() && !strings.HasPrefix(fi.Name(), ".") {
			n++
			b += fi.Size()
		}
		return nil
	})
	return n, b, err
}

// CopySet — копія теки src у dst (файли лише на читання, без прав на виконання).
func CopySet(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(t, 0o700)
		}
		if !fi.Mode().IsRegular() || strings.HasPrefix(fi.Name(), ".") {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(t, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	})
}

type entry struct {
	rel, abs string
	size     int64
	mtime    int64
}

func realPath(p string) string {
	abs, _ := filepath.Abs(p)
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}

// AddedPrefix — префікс шляхів доданих через веб файлів у звітах.
const AddedPrefix = "+added/"

// SetRoots — теки набору: основна і (якщо є) додані файли.
func SetRoots(s Set) []string {
	roots := []string{s.Path}
	if s.Extra != "" {
		if st, err := os.Stat(s.Extra); err == nil && st.IsDir() {
			roots = append(roots, s.Extra)
		}
	}
	return roots
}

// listFiles — файли тек набору (перша — основна, решта — додані: шляхи з префіксом +added/) і відбиток (для кешу).
func listFiles(dirs ...string) ([]entry, string, error) {
	var es []entry
	for i, dir := range dirs {
		root := realPath(dir)
		prefix := ""
		if i > 0 {
			prefix = AddedPrefix
		}
		err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.Mode().IsRegular() && !strings.HasPrefix(fi.Name(), ".") && fi.Name() != "expected.tsv" {
				rel, _ := filepath.Rel(root, p)
				es = append(es, entry{rel: prefix + filepath.ToSlash(rel), abs: p, size: fi.Size(), mtime: fi.ModTime().UnixNano()})
			}
			return nil
		})
		if err != nil {
			return nil, "", err
		}
	}
	sort.Slice(es, func(i, j int) bool { return es[i].rel < es[j].rel })
	h := sha256.New()
	for _, e := range es {
		fmt.Fprintf(h, "%s|%d|%d\n", e.rel, e.size, e.mtime)
	}
	return es, hex.EncodeToString(h.Sum(nil)), nil
}

func fileSHA(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

// codes — ORG_<КОД>_… → категорія (eval_sensitive.py: CODES).
var codes = map[string]string{"BANK": "bank", "PERS": "personal", "CRED": "credentials", "KEYS": "keys", "TOK": "tokens",
	"INFRA": "infra", "CLASS": "classified", "ORG": "org"}

// RulesOf — правила пакета (тека tree): інформаційні, критичні з категоріями, тіла.
func RulesOf(tree string) (map[string]RuleInfo, error) {
	out := map[string]RuleInfo{}
	err := filepath.Walk(tree, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() || !yaraparse.IsRulesFile(p) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(tree, p)
		rel = filepath.ToSlash(rel)
		crit := strings.HasPrefix(rel, "critical/")
		for _, r := range yaraparse.Parse(string(b)).Rules {
			ri := RuleInfo{Critical: crit, Body: dupes.BodyHash(r), File: rel}
			for _, t := range r.Tags {
				if t == "docscan_info" {
					ri.Info = true
				}
			}
			if strings.EqualFold(r.MetaValue("severity"), "INFO") {
				ri.Info = true
			}
			if crit {
				ri.Category = r.MetaValue("category")
				if ri.Category == "" {
					if p := strings.Split(r.Name, "_"); len(p) > 2 && codes[p[1]] != "" {
						ri.Category = codes[p[1]]
					}
				}
				if ri.Category == "" {
					ri.Category = "?"
				}
			}
			out[r.Name] = ri
		}
		return nil
	})
	return out, err
}

// Run — пакет (розпакована тека tree, sha пакета) на наборах.
func (r Runner) Run(tree, pkgSHA, version string, sets []Set, mode string) (*PackageResult, error) {
	if mode != "full" {
		mode = "fast"
	}
	if !r.Tools.Configured() {
		return nil, fmt.Errorf("DocScan yara / yarac are not set")
	}
	inf, err := r.Tools.Probe()
	if err != nil {
		return nil, err
	}
	pr := &PackageResult{PkgSHA: pkgSHA, Version: version, Mode: mode, Sets: map[string]*SetResult{}}
	if pr.Rules, err = RulesOf(tree); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(r.Work, "lab-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	yarc := filepath.Join(work, "rules.yarc")
	if pr.Warnings, err = r.Tools.CompileYarc(tree, yarc); err != nil {
		return nil, err
	}
	// шлях теки пакета з попереджень — інакше кожне попередження кандидата «нове» проти базового
	for i, w := range pr.Warnings {
		for _, p := range []string{realPath(tree), tree} {
			w = strings.ReplaceAll(w, p+string(filepath.Separator), "")
		}
		pr.Warnings[i] = w
	}
	critDir := filepath.Join(tree, "critical")
	if _, err := os.Stat(critDir); err != nil {
		critDir = ""
	}
	for _, s := range sets {
		files, fp, err := listFiles(SetRoots(s)...)
		if err != nil {
			return nil, fmt.Errorf("set %s: %w", s.ID, err)
		}
		key := fmt.Sprintf("%s-%s-%s-%s-%s.json", pkgSHA[:16], s.ID, fp[:16], mode, hash(inf.Version)[:8])
		cp := filepath.Join(r.Cache, key)
		if b, err := os.ReadFile(cp); err == nil {
			var sr SetResult
			if json.Unmarshal(b, &sr) == nil {
				sr.Cached = true
				pr.Sets[s.ID] = &sr
				r.say("%s %s: %s (cached)", version, s.ID, s.Kind)
				continue
			}
		}
		r.say("%s %s: %d files (%s)…", version, s.ID, len(files), mode)
		sr, err := r.runSet(s, files, yarc, critDir, work, mode)
		if err != nil {
			return nil, fmt.Errorf("set %s: %w", s.ID, err)
		}
		pr.Sets[s.ID] = sr
		if b, err := json.Marshal(sr); err == nil {
			os.MkdirAll(r.Cache, 0o700)
			os.WriteFile(cp, b, 0o600)
		}
	}
	return pr, nil
}

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func (r Runner) tools(work string) (yaraexec.Tools, string) {
	t := r.Tools
	t.Timeout = 2 * time.Hour
	kind := yaraexec.SandboxKind()
	if kind != "" {
		t.Sandbox = work
	} else {
		kind = "none"
	}
	return t, kind
}

func (r Runner) runSet(s Set, files []entry, yarc, critDir, work, mode string) (*SetResult, error) {
	sr := &SetResult{Set: s.ID, Kind: s.Kind}
	byAbs := map[string]*File{}
	res := make([]File, len(files))
	for i, e := range files {
		res[i] = File{Rel: e.rel, SHA: fileSHA(e.abs)}
		byAbs[e.abs] = &res[i]
	}
	threads := r.Threads
	if threads <= 0 {
		threads = 8
	}
	t, kind := r.tools(work)
	sr.Sandbox = kind
	start := time.Now()
	if mode == "fast" {
		for ri, root := range SetRoots(s) {
			q := filepath.Join(work, fmt.Sprintf("%s-q%d.json", s.ID, ri))
			os.Remove(q)
			args := []string{"-w", "--file-vars", "-r", "-p", fmt.Sprint(threads)}
			if critDir != "" {
				args = append(args, "--critical-rules="+critDir, "--critical-out="+q)
			}
			args = append(args, "-C", yarc, realPath(root))
			out, err := t.RunYara("", args...)
			if err != nil {
				return nil, err
			}
			for _, l := range strings.Split(out.Output, "\n") {
				switch {
				case l == "", strings.HasPrefix(l, "docscan-critical:"), strings.HasPrefix(l, "warning:"):
				case strings.HasPrefix(l, "error scanning "):
					p, msg, _ := strings.Cut(strings.TrimPrefix(l, "error scanning "), ": ")
					if f := byAbs[p]; f != nil {
						f.Err = msg
					} else {
						sr.Errors = append(sr.Errors, l)
					}
				case strings.HasPrefix(l, "error"):
					sr.Errors = append(sr.Errors, l)
				default:
					rule, p, ok := strings.Cut(l, " ")
					if f := byAbs[p]; ok && f != nil {
						f.Rules = append(f.Rules, rule)
					}
				}
			}
			if err := readQueue(q, byAbs); err != nil {
				return nil, err
			}
		}
	} else {
		var mu sync.Mutex
		jobs := make(chan entry)
		var wg sync.WaitGroup
		for w := 0; w < threads; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for e := range jobs {
					q := filepath.Join(work, fmt.Sprintf("%s-q%d.json", s.ID, w))
					os.Remove(q)
					args := []string{"-w", "--docscan-json"}
					if critDir != "" {
						args = append(args, "--critical-rules="+critDir, "--critical-out="+q)
					}
					args = append(args, "-C", yarc, e.abs)
					out, err := t.RunYara("", args...)
					mu.Lock()
					f := byAbs[e.abs]
					if err != nil {
						f.Err = err.Error()
					} else {
						f.Rules, f.Err = parseJSON(out.Output)
						readQueue(q, byAbs)
					}
					mu.Unlock()
				}
			}(w)
		}
		for _, e := range files {
			jobs <- e
		}
		close(jobs)
		wg.Wait()
	}
	sr.Seconds = time.Since(start).Seconds()
	for i := range res {
		sort.Strings(res[i].Rules)
		res[i].Rules = uniq(res[i].Rules)
		sort.Strings(res[i].Crit)
	}
	sr.Files = res
	return sr, nil
}

func uniq(s []string) []string {
	out := s[:0]
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// parseJSON — правила з рядка --docscan-json: усі *_matches і details[].rule.
func parseJSON(out string) ([]string, string) {
	var rules []string
	var errs []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "{") {
			if strings.HasPrefix(l, "error") {
				errs = append(errs, l)
			}
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			errs = append(errs, "bad JSON: "+err.Error())
			continue
		}
		for k, v := range m {
			if strings.HasPrefix(k, "yara_") && strings.HasSuffix(k, "_matches") || k == "yara_matches" {
				var arr []any
				json.Unmarshal(v, &arr)
				for _, x := range arr {
					switch y := x.(type) {
					case string:
						rules = append(rules, y)
					case map[string]any:
						if s, ok := y["rule"].(string); ok {
							rules = append(rules, s)
						}
					}
				}
			}
		}
		var d struct {
			Details []struct {
				Rule string `json:"rule"`
			} `json:"details"`
		}
		json.Unmarshal([]byte(l), &d)
		for _, x := range d.Details {
			if x.Rule != "" {
				rules = append(rules, x.Rule)
			}
		}
	}
	return rules, strings.Join(errs, "; ")
}

// readQueue — черга третього проходу: шлях документа і правила, що спрацювали (metadata.yara_matches).
func readQueue(q string, byAbs map[string]*File) error {
	f, err := os.Open(q)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	for sc.Scan() {
		var rec struct {
			Document struct {
				Path string `json:"path"`
			} `json:"document"`
			Metadata struct {
				YaraMatches []string `json:"yara_matches"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return fmt.Errorf("queue line is not JSON: %w", err)
		}
		if fl := byAbs[realPath(rec.Document.Path)]; fl != nil {
			fl.Queued = true
			fl.Crit = append(fl.Crit, rec.Metadata.YaraMatches...)
		}
	}
	return sc.Err()
}
