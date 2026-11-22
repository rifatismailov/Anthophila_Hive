// Package yaraparse — розбір тексту правил YARA для Hive. Етап 0: лише назви правил (унікальність назв критичних
// правил у всіх файлах critical/ — у записі для Wazuh і в черзі стоїть лише назва). Остаточний суддя синтаксису —
// завжди DocScan yarac.
package yaraparse

import (
	"regexp"
	"strings"
)

// Mask — копія тексту тієї самої довжини, де коментарі, текстові рядки "…" і регулярні вирази /…/ замінено
// пробілами (переноси рядків збережено — номери рядків не зсуваються).
func Mask(src string) string {
	b := []byte(src)
	n := len(b)
	blank := func(from, to int) {
		for k := from; k < to && k < n; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	prevSig := byte(0) // останній значущий символ поза маскою
	prevWord := ""
	word := []byte{}
	for i := 0; i < n; {
		c := b[i]
		switch {
		case c == '/' && i+1 < n && b[i+1] == '/':
			j := i
			for j < n && b[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
			continue
		case c == '/' && i+1 < n && b[i+1] == '*':
			j := i + 2
			for j+1 < n && !(b[j] == '*' && b[j+1] == '/') {
				j++
			}
			j += 2
			if j > n {
				j = n
			}
			blank(i, j)
			i = j
			continue
		case c == '"':
			j := i + 1
			for j < n && b[j] != '"' && b[j] != '\n' {
				if b[j] == '\\' {
					j++
				}
				j++
			}
			blank(i+1, j)
			prevSig = '"'
			i = j + 1
			continue
		case c == '/' && (prevSig == '=' || prevWord == "matches"):
			j := i + 1
			for j < n && b[j] != '/' && b[j] != '\n' {
				if b[j] == '\\' {
					j++
				}
				j++
			}
			blank(i+1, j)
			prevSig = '/'
			prevWord = ""
			i = j + 1
			continue
		}
		if isWord(c) {
			word = append(word, c)
		} else if len(word) > 0 {
			prevWord = string(word)
			word = word[:0]
		}
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			prevSig = c
			if !isWord(c) {
				prevWord = ""
			}
		}
		i++
	}
	return string(b)
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

var ruleHead = regexp.MustCompile(`(?m)(?:^|[\s}])((?:(?:private|global)\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^{]*)?\{`)

// RuleName — назва правила і рядок (з 1), де воно оголошене.
type RuleName struct {
	Name string
	Line int
}

// RuleNames — усі правила тексту в порядку появи.
func RuleNames(src string) []RuleName {
	m := Mask(src)
	var out []RuleName
	for _, loc := range ruleHead.FindAllStringSubmatchIndex(m, -1) {
		name := m[loc[4]:loc[5]]
		line := 1
		for _, c := range m[:loc[4]] {
			if c == '\n' {
				line++
			}
		}
		out = append(out, RuleName{Name: name, Line: line})
	}
	return out
}

// IsRulesFile — файл правил YARA за розширенням: .yar, .yara і .rule (InQuest постачає правила у файлах .rule —
// 18 правил офіційного набору; без них бібліотека й лабораторія їх не бачили).
func IsRulesFile(p string) bool {
	i := strings.LastIndexByte(p, '.')
	if i < 0 {
		return false
	}
	switch strings.ToLower(p[i:]) {
	case ".yar", ".yara", ".rule":
		return true
	}
	return false
}
