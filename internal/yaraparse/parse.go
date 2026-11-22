package yaraparse

import (
	"regexp"
	"strings"
)

// KV — одна пара meta (значення — як у тексті: рядок без лапок, число, true / false).
type KV struct{ Key, Value string }

// Rule — правило в тексті файлу.
type Rule struct {
	Name      string
	Private   bool
	Global    bool
	Tags      []string
	Meta      []KV
	Strings   string // текст розділу strings (без заголовка)
	Condition string // текст розділу condition
	Line      int    // рядок заголовка (з 1)
	Start     int    // початок разом з коментарями перед правилом (кінець попереднього правила)
	HeadStart int    // початок заголовка (private / global / rule)
	End       int    // одразу після закривної дужки
}

// File — розібраний файл правил.
type File struct {
	Imports []string
	Rules   []Rule
}

// Text — текст правила разом з коментарями перед ним.
func (r Rule) Text(src string) string { return src[r.Start:r.End] }

// MetaValue — значення ключа meta (перше) або "".
func (r Rule) MetaValue(key string) string {
	for _, kv := range r.Meta {
		if strings.EqualFold(kv.Key, key) {
			return kv.Value
		}
	}
	return ""
}

var (
	ruleHeadFull = regexp.MustCompile(`(?m)(?:^|[\s}])((?:(?:private|global)\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(:[^{]*)?\{`)
	importRe     = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+"([^"]+)"`)
	sectionRe    = regexp.MustCompile(`\b(meta|strings|condition)\s*:`)
	metaRe       = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*("(?:[^"\\\n]|\\.)*"|-?[0-9]+|true|false)`)
	identRe      = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
)

// Parse — правила файлу (як split_rules у build_vendor_rules.py: текст правила — від кінця попереднього до його
// закривної дужки, з коментарями перед ним). Синтаксис не перевіряється — це робить DocScan yarac.
func Parse(src string) File {
	m := Mask(src)
	var f File
	for _, x := range importRe.FindAllStringSubmatchIndex(src, -1) {
		if strings.TrimSpace(m[x[0]:x[1]]) != "" { // не в коментарі
			f.Imports = append(f.Imports, src[x[2]:x[3]])
		}
	}
	heads := ruleHeadFull.FindAllStringSubmatchIndex(m, -1)
	prev := 0
	for i, h := range heads {
		next := len(m)
		if i+1 < len(heads) {
			next = heads[i+1][2]
		}
		hend := h[1]
		end := strings.LastIndexByte(m[hend-1:next], '}')
		if end < 0 {
			end = next - (hend - 1)
		}
		end += hend - 1 + 1
		mods := m[h[2]:h[3]]
		r := Rule{
			Name:      m[h[4]:h[5]],
			Private:   strings.Contains(mods, "private"),
			Global:    strings.Contains(mods, "global"),
			HeadStart: h[2],
			Start:     prev,
			End:       end,
			Line:      1 + strings.Count(m[:h[4]], "\n"),
		}
		if h[6] >= 0 {
			r.Tags = strings.Fields(strings.TrimPrefix(m[h[6]:h[7]], ":"))
		}
		// розділи тіла (за маскою: слова в рядках і коментарях не плутають)
		body, bm := src[hend:end-1], m[hend:end-1]
		secs := sectionRe.FindAllStringSubmatchIndex(bm, -1)
		for k, s := range secs {
			to := len(bm)
			if k+1 < len(secs) {
				to = secs[k+1][0]
			}
			text := body[s[1]:to]
			switch bm[s[2]:s[3]] {
			case "meta":
				for _, kv := range metaRe.FindAllStringSubmatch(text, -1) {
					r.Meta = append(r.Meta, KV{Key: kv[1], Value: unquote(kv[2])})
				}
			case "strings":
				r.Strings = text
			case "condition":
				r.Condition = text
			}
		}
		f.Rules = append(f.Rules, r)
		prev = end
	}
	return f
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' {
		v = v[1 : len(v)-1]
		v = strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(v)
	}
	return v
}

// ConditionWords — ідентифікатори в умові правила (без рядків і регулярних виразів): назви інших правил, модулі,
// ключові слова. Для пошуку залежностей між правилами.
func ConditionWords(r Rule) []string {
	return identRe.FindAllString(Mask(r.Condition), -1)
}

// Remove — текст src без правил із назвами names (разом з коментарями перед кожним). Повертає новий текст і
// назви, яких у файлі не знайшлося.
func Remove(src string, names map[string]bool) (string, []string) {
	f := Parse(src)
	var b strings.Builder
	pos := 0
	found := map[string]bool{}
	for _, r := range f.Rules {
		if !names[r.Name] {
			continue
		}
		found[r.Name] = true
		b.WriteString(src[pos:r.Start])
		pos = r.End
	}
	b.WriteString(src[pos:])
	var missing []string
	for n := range names {
		if !found[n] {
			missing = append(missing, n)
		}
	}
	return b.String(), missing
}
