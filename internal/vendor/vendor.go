// Package vendor — генератор вендорних правил DocScan: порт yara-docscan-rules/tools/build_vendor_rules.py на Go.
//
// Результат має бути БАЙТ У БАЙТ таким самим, як у Python-генератора (тест TestParityWithPython): general/,
// maldoc/<джерело>/, file-index.yar, LICENSE-*, tools/vendor-report.md. Тому тут свідомо відтворено поведінку
// Python: універсальні переноси рядків при читанні (\r\n, \r → \n), заміна невалідного UTF-8 як у
// bytes.decode(errors="replace"), \s у регулярних виразах — набір пробільних символів Python.
//
// Налаштування (джерела з закріпленими комітами, DROP / INFO / RENAME, YARA-Forge) — дані в git простору
// (vendor/config.yaml, vendor/selection.txt), а не код.
package vendor

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Source — вендорне джерело: git-репозиторій на коміті або zip-реліз ("release:<тег>").
type Source struct {
	Name   string `yaml:"name" json:"name"`
	URL    string `yaml:"url" json:"url"`
	Pin    string `yaml:"pin" json:"pin"`                           // коміт або release:<тег>
	SHA256 string `yaml:"sha256,omitempty" json:"sha256,omitempty"` // zip-реліз: sha256 архіву
}

// IsRelease — джерело — zip-реліз.
func (s Source) IsRelease() bool { return strings.HasPrefix(s.Pin, "release:") }

// Drop — правило, відкинуте свідомо: за назвою (File == "") або (шлях у джерелі, назва).
type Drop struct {
	File   string `yaml:"file,omitempty" json:"file,omitempty"`
	Rule   string `yaml:"rule" json:"rule"`
	Reason string `yaml:"reason" json:"reason"`
}

// Rename — перейменування при конфлікті назв: (шлях у джерелі, назва) -> нова назва.
type Rename struct {
	File string `yaml:"file" json:"file"`
	Rule string `yaml:"rule" json:"rule"`
	To   string `yaml:"to" json:"to"`
}

// Config — vendor/config.yaml (константи build_vendor_rules.py).
type Config struct {
	Sources      []Source          `yaml:"sources" json:"sources"`
	ForgeSources map[string]string `yaml:"forge_sources" json:"forge_sources"` // repo -> SPDX
	SourceInfo   map[string]string `yaml:"source_info" json:"source_info"`     // джерело -> regex «інформаційне»
	Drop         []Drop            `yaml:"drop" json:"drop"`
	Rename       []Rename          `yaml:"rename,omitempty" json:"rename"`
	OldYear      int               `yaml:"old_year" json:"old_year"`
	Info         []string          `yaml:"info" json:"info"`
	InfoTag      string            `yaml:"info_tag" json:"info_tag"`
	DocTag       string            `yaml:"doc_tag" json:"doc_tag"`
	// порядок ліцензійних файлів (джерело, ім'я файлу) — як у генераторі
	Licenses [][2]string `yaml:"licenses" json:"licenses"`
}

func (c *Config) source(name string) (Source, bool) {
	for _, s := range c.Sources {
		if s.Name == name {
			return s, true
		}
	}
	return Source{}, false
}

// Selection — рядок vendor-selection.txt.
type Selection struct{ OutDir, Source, Path string }

// ParseSelection — vendor-selection.txt (коментарі після #).
func ParseSelection(text string) ([]Selection, error) {
	var out []Selection
	for _, line := range splitLines(universal(text)) {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("vendor-selection: %q: expected <out_dir> <source> <path>", line)
		}
		out = append(out, Selection{f[0], f[1], f[2]})
	}
	return out, nil
}

// ---------------------------------------------------------------- поведінка Python

// decodeReplace — bytes.decode("utf-8", errors="replace"): максимальна валідна частина невалідної послідовності
// замінюється одним U+FFFD.
func decodeReplace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || n > 1 {
			sb.WriteString(string(b[i : i+n]))
			i += n
			continue
		}
		c := b[i]
		need, lo, hi := 0, byte(0x80), byte(0xBF)
		switch {
		case c >= 0xC2 && c <= 0xDF:
			need = 1
		case c == 0xE0:
			need, lo = 2, 0xA0
		case c >= 0xE1 && c <= 0xEC, c == 0xEE, c == 0xEF:
			need = 2
		case c == 0xED:
			need, hi = 2, 0x9F
		case c == 0xF0:
			need, lo = 3, 0x90
		case c >= 0xF1 && c <= 0xF3:
			need = 3
		case c == 0xF4:
			need, hi = 3, 0x8F
		}
		j := i + 1
		for k := 0; k < need && j < len(b); k++ {
			l, h := byte(0x80), byte(0xBF)
			if k == 0 {
				l, h = lo, hi
			}
			if b[j] < l || b[j] > h {
				break
			}
			j++
		}
		sb.WriteRune(utf8.RuneError)
		i = j
	}
	return sb.String()
}

// universal — переноси рядків як у текстовому режимі Python: \r\n і \r → \n.
func universal(s string) string {
	if !strings.Contains(s, "\r") {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// readText — Path.read_text(encoding="utf-8", errors="replace").
func readText(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return universal(decodeReplace(b)), nil
}

// splitLines — str.splitlines() для тексту з \n (після universal): без порожнього останнього.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	ls := strings.Split(s, "\n")
	if ls[len(ls)-1] == "" {
		ls = ls[:len(ls)-1]
	}
	return ls
}

// pyS — \s Python (str): пробільні символи Unicode.
const pyS = `[\t\n\v\f\r \x1c-\x1f\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`

func re(p string) *regexp.Regexp { return regexp.MustCompile(strings.ReplaceAll(p, `\s`, pyS)) }

func pyRstrip(s string) string {
	return strings.TrimRightFunc(s, func(r rune) bool {
		return strings.ContainsRune("\t\n\v\f\r \x1c\x1d\x1e\x1f\u0085 ", r) || r >= 0x2000 && r <= 0x200a
	})
}

// ---------------------------------------------------------------- розбір (split_rules)

var (
	header   = regexp.MustCompile(`(?m)^[ \t]*((?:private|global)[ \t]+)*rule[ \t]+([A-Za-z0-9_]+)[ \t\r\n]*(:[^{]*)?\{`)
	headerAt = regexp.MustCompile(`\A[ \t]*((?:private|global)[ \t]+)*rule[ \t]+([A-Za-z0-9_]+)[ \t\r\n]*(:[^{]*)?\{`)
	condRe   = re(`(?s)\bcondition\s*:(.*)$`)
	strsRe   = re(`(?s)\bstrings\s*:(.*?)\bcondition\s*:`)
)

// mask — копія тієї самої довжини (у байтах), де коментарі й текстові рядки замінено пробілами.
func mask(text string) string {
	out := []byte(text)
	n := len(text)
	for i := 0; i < n; {
		c := text[i]
		if c == '"' {
			j := i + 1
			for j < n && text[j] != '"' && text[j] != '\n' {
				if text[j] == '\\' {
					j += 2
				} else {
					j++
				}
			}
			for k := i + 1; k < j && k < n; k++ {
				out[k] = ' '
			}
			i = j + 1
			continue
		}
		if strings.HasPrefix(text[i:], "//") {
			j := strings.IndexByte(text[i:], '\n')
			if j < 0 {
				j = n
			} else {
				j += i
			}
			for k := i; k < j; k++ {
				out[k] = ' '
			}
			i = j
			continue
		}
		if strings.HasPrefix(text[i:], "/*") {
			j := strings.Index(text[i+2:], "*/")
			if j < 0 {
				j = n
			} else {
				j += i + 2 + 2
			}
			for k := i; k < j; k++ {
				if out[k] != '\n' {
					out[k] = ' '
				}
			}
			i = j
			continue
		}
		i++
	}
	return string(out)
}

type rule struct {
	name    string
	private bool
	hstart  int
	hend    int
	end     int
	text    string // коментарі перед правилом + правило
	hoff    int
	cond    string // з маски
	strs    string // з оригіналу
	drop    string
}

func splitRules(text string) (pre string, rules []*rule, tail string) {
	m := mask(text)
	hs := header.FindAllStringSubmatchIndex(m, -1)
	if len(hs) == 0 {
		return text, nil, ""
	}
	for k, h := range hs {
		nxt := len(m)
		if k+1 < len(hs) {
			nxt = hs[k+1][0]
		}
		end := 0
		if from := h[1] - 1; from <= nxt {
			if idx := strings.LastIndexByte(m[from:nxt], '}'); idx >= 0 {
				end = from + idx + 1
			}
		}
		rules = append(rules, &rule{name: m[h[4]:h[5]], private: h[2] < h[3], hstart: h[0], hend: h[1], end: end})
	}
	pre = text[:rules[0].hstart]
	prev := rules[0].hstart
	for _, r := range rules {
		// як у Python: зріз з кінцем перед початком — порожній, prev = end (навіть 0)
		if prev <= r.end {
			r.text = text[prev:r.end]
		}
		r.hoff = r.hstart - prev
		body := ""
		if r.hend <= r.end {
			body = m[r.hend:r.end]
		}
		if cm := condRe.FindStringSubmatch(body); cm != nil {
			r.cond = cm[1]
		}
		if r.hend <= r.end {
			if sm := strsRe.FindStringSubmatch(text[r.hend:r.end]); sm != nil {
				r.strs = sm[1]
			}
		}
		prev = r.end
	}
	if prev > len(text) {
		prev = len(text)
	}
	return pre, rules, text[prev:]
}
