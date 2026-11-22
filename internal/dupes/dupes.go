// Package dupes — дублікати правил (PLAN.md, розділ 4): L0 однаковий текст, L1 те саме тіло (strings + condition)
// після нормалізації — інша назва, інший порядок рядків, інші $-ідентифікатори, інша meta; L4 однакова назва з
// різним тілом там, де правила компілюються разом. L2 (схожі) і L3 (варіанти) — етап 2.
package dupes

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"

	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

var (
	defRe    = regexp.MustCompile(`(?m)\$([A-Za-z0-9_]*)\s*=`)
	refRe    = regexp.MustCompile(`([$#@!])([A-Za-z0-9_]*)(\*?)`)
	wsRe     = regexp.MustCompile(`\s+`)
	punctRe  = regexp.MustCompile(`\s*([(),=<>!+\-*/%&|^~\[\]])\s*`)
	modsSpRe = regexp.MustCompile(`\s+`)
)

// TextHash — L0: текст правила без коментарів, пробіли згорнуті (назва входить: це «той самий текст»).
func TextHash(src string, r yaraparse.Rule) string {
	t := src[r.HeadStart:r.End]
	m := yaraparse.Mask(t)
	// коментарі прибираємо за маскою (рядки й регулярні вирази в масці теж порожні — беремо їх з оригіналу)
	var b strings.Builder
	inComment := false
	for i := 0; i < len(t); i++ {
		if strings.HasPrefix(t[i:], "//") && m[i] == ' ' {
			inComment = true
		}
		if strings.HasPrefix(t[i:], "/*") && m[i] == ' ' {
			j := strings.Index(t[i+2:], "*/")
			if j >= 0 {
				i += j + 3
				continue
			}
		}
		if inComment && t[i] == '\n' {
			inComment = false
		}
		if !inComment {
			b.WriteByte(t[i])
		}
	}
	return hash(wsRe.ReplaceAllString(strings.TrimSpace(b.String()), " "))
}

// BodyHash — L1: канонічне тіло. Рядки: вид | значення (hex — нижній регістр без пробілів) | модифікатори
// (відсортовані); ідентифікатор $x у рядках і в умові замінюється хешем його канонічної форми; оператори and / or
// верхнього рівня умови сортуються. Назва, теги і meta не входять.
func BodyHash(r yaraparse.Rule) string {
	defs, ids := canonStrings(r.Strings)
	cond := canonCondition(r.Condition, ids)
	sort.Strings(defs)
	return hash(strings.Join(defs, "\n") + "\n--\n" + cond)
}

func canonStrings(s string) ([]string, map[string]string) {
	m := yaraparse.Mask(s)
	locs := defRe.FindAllStringSubmatchIndex(m, -1)
	ids := map[string]string{}
	var defs []string
	for i, l := range locs {
		end := len(s)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		id := s[l[2]:l[3]]
		raw := strings.TrimSpace(stripComments(s[l[1]:end], m[l[1]:end]))
		c := canonValue(raw)
		h := hash(c)[:12]
		if id != "" {
			ids[id] = h
		}
		defs = append(defs, c)
	}
	return defs, ids
}

func stripComments(s, masked string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if masked[i] == ' ' && s[i] != ' ' && (strings.HasPrefix(s[i:], "//") || strings.HasPrefix(s[i:], "/*")) {
			// коментар: до кінця рядка або до */
			if strings.HasPrefix(s[i:], "//") {
				j := strings.IndexByte(s[i:], '\n')
				if j < 0 {
					break
				}
				i += j - 1
				continue
			}
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				break
			}
			i += j + 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// canonValue — значення рядка + модифікатори.
func canonValue(v string) string {
	switch {
	case strings.HasPrefix(v, "{"):
		j := strings.LastIndexByte(v, '}')
		if j < 0 {
			return "hex|" + v
		}
		hex := strings.ToLower(wsRe.ReplaceAllString(v[1:j], ""))
		return "hex|" + hex + "|" + mods(v[j+1:])
	case strings.HasPrefix(v, `"`):
		j := closing(v, '"')
		return "text|" + v[:j+1] + "|" + mods(v[j+1:])
	case strings.HasPrefix(v, "/"):
		j := closing(v, '/')
		// прапорці регулярного виразу (i, s) — частина значення
		k := j + 1
		for k < len(v) && (v[k] == 'i' || v[k] == 's') {
			k++
		}
		return "re|" + v[:k] + "|" + mods(v[k:])
	}
	return "?|" + wsRe.ReplaceAllString(v, " ")
}

func closing(v string, q byte) int {
	for i := 1; i < len(v); i++ {
		if v[i] == '\\' {
			i++
			continue
		}
		if v[i] == q {
			return i
		}
	}
	return len(v) - 1
}

func mods(s string) string {
	f := strings.Fields(modsSpRe.ReplaceAllString(strings.TrimSpace(s), " "))
	// xor(1-255), base64("…") — модифікатори з аргументами лишаються як є
	sort.Strings(f)
	return strings.Join(f, " ")
}

func canonCondition(c string, ids map[string]string) string {
	m := yaraparse.Mask(c)
	// посилання на рядки — лише поза рядками й коментарями (за маскою)
	var b strings.Builder
	last := 0
	for _, l := range refRe.FindAllStringSubmatchIndex(m, -1) {
		id := m[l[4]:l[5]]
		if l[6] < l[7] { // $a* — шаблон: лишається як є
			continue
		}
		h, ok := ids[id]
		if !ok {
			continue
		}
		b.WriteString(c[last:l[4]])
		b.WriteString("s" + h)
		last = l[5]
	}
	b.WriteString(c[last:])
	out := stripComments(b.String(), yaraparse.Mask(b.String()))
	out = wsRe.ReplaceAllString(strings.TrimSpace(out), " ")
	out = punctRe.ReplaceAllString(out, "$1")
	return sortTop(out)
}

// sortTop — операнди and (або or) верхнього рівня — у відсортованому порядку (лише якщо на верхньому рівні один вид).
func sortTop(c string) string {
	for _, op := range []string{" and ", " or "} {
		parts, ok := splitTop(c, op)
		other := " or "
		if op == " or " {
			other = " and "
		}
		if !ok || len(parts) < 2 {
			continue
		}
		mixed := false
		for _, p := range parts {
			if q, _ := splitTop(p, other); len(q) > 1 {
				mixed = true
			}
		}
		if mixed {
			return c
		}
		sort.Strings(parts)
		return strings.Join(parts, op)
	}
	return c
}

func splitTop(c, op string) ([]string, bool) {
	depth, last := 0, 0
	var parts []string
	inStr := false
	for i := 0; i < len(c); i++ {
		switch {
		case c[i] == '"' && (i == 0 || c[i-1] != '\\'):
			inStr = !inStr
		case inStr:
		case c[i] == '(':
			depth++
		case c[i] == ')':
			depth--
		case depth == 0 && strings.HasPrefix(c[i:], op):
			parts = append(parts, strings.TrimSpace(c[last:i]))
			last = i + len(op)
			i += len(op) - 1
		}
	}
	parts = append(parts, strings.TrimSpace(c[last:]))
	return parts, len(parts) > 1
}

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// Member — правило в групі.
type Member struct {
	Origin, File, Name, Kind string
	Private                  bool
	TextHash, BodyHash       string
}

// Group — група дублікатів або конфлікт назв.
type Group struct {
	Level   string // L0 | L1 | L4
	Key     string
	Members []Member
}

// Groups — L0 (однаковий текст), L1 (те саме тіло, якщо не вся група вже L0) і L4 (однакова назва, різне тіло, у
// межах того, що компілюється разом: виявлення окремо, критичні окремо). private / global правила не беруться
// в L0 / L1: на них посилаються інші, генератор їх завжди лишає.
func Groups(ms []Member) []Group {
	by := func(key func(Member) string, skipPrivate bool) map[string][]Member {
		g := map[string][]Member{}
		for _, m := range ms {
			if skipPrivate && m.Private {
				continue
			}
			// без хешів (старий індекс) правило ні з чим не групується: порожній ключ злив би всю бібліотеку
			if m.TextHash == "" || m.BodyHash == "" {
				continue
			}
			g[key(m)] = append(g[key(m)], m)
		}
		return g
	}
	var out []Group
	l0 := by(func(m Member) string { return m.Kind + "|" + m.TextHash }, true)
	for k, g := range l0 {
		if len(g) > 1 {
			out = append(out, Group{Level: "L0", Key: k, Members: g})
		}
	}
	for k, g := range by(func(m Member) string { return m.Kind + "|" + m.BodyHash }, true) {
		if len(g) < 2 {
			continue
		}
		same := true
		for _, m := range g[1:] {
			if m.TextHash != g[0].TextHash {
				same = false
			}
		}
		if !same {
			out = append(out, Group{Level: "L1", Key: k, Members: g})
		}
	}
	for k, g := range by(func(m Member) string {
		d := "detection"
		if m.Kind == "critical" {
			d = "critical"
		}
		return d + "|" + m.Name
	}, false) {
		bodies := map[string]bool{}
		for _, m := range g {
			bodies[m.BodyHash] = true
		}
		if len(g) > 1 && len(bodies) > 1 {
			out = append(out, Group{Level: "L4", Key: k, Members: g})
		}
	}
	for i := range out {
		sort.Slice(out[i].Members, func(a, b int) bool {
			x, y := out[i].Members[a], out[i].Members[b]
			return x.Origin+x.File+x.Name < y.Origin+y.File+y.Name
		})
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Level != out[b].Level {
			return out[a].Level < out[b].Level
		}
		return out[a].Members[0].Name < out[b].Members[0].Name
	})
	return out
}

// Signature — канонічні рядки правила (короткі хеші, відсортовані) і канонічна умова: для L2 / L3.
func Signature(r yaraparse.Rule) ([]string, string) {
	defs, ids := canonStrings(r.Strings)
	var hs []string
	for _, d := range defs {
		hs = append(hs, hash(d)[:12])
	}
	sort.Strings(hs)
	return hs, canonCondition(r.Condition, ids)
}

// AndParts — операнди and верхнього рівня канонічної умови.
func AndParts(cond string) []string {
	p, _ := splitTop(cond, " and ")
	return p
}
