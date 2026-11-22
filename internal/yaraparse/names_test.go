package yaraparse

import (
	"os"
	"reflect"
	"testing"
)

func TestRuleNames(t *testing.T) {
	src := `import "pe"
// rule CommentedOut { condition: true }
/* rule BlockComment {
   condition: true } */
rule A { condition: true }
private rule B : tag1 tag2
{
    meta:
        description = "rule NotARule { x }"
    strings:
        $a = /rule NotARegexRule \{/
        $b = "x/y" // rule AfterString {
    condition:
        $a and $b and filename matches /rule Matches \{/
}
global private rule C{condition:B}
rule D_1 :t{condition:A}rule E { condition: true }
`
	var got []string
	for _, r := range RuleNames(src) {
		got = append(got, r.Name)
	}
	want := []string{"A", "B", "C", "D_1", "E"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if l := RuleNames(src)[1].Line; l != 6 {
		t.Errorf("rule B on line %d, want 6", l)
	}
}

func TestRuleNamesCyrillic(t *testing.T) {
	src := "rule crit_markings\n{\n strings:\n  $m1 = /службов[^ ]{0,12} користуванн[^ ]{0,8}/\n condition:\n  any of them\n}\n"
	r := RuleNames(src)
	if len(r) != 1 || r[0].Name != "crit_markings" {
		t.Fatalf("got %v", r)
	}
}

// Справжні файли критичних правил з context/ (кількість правил звірено з grep "^rule").
func TestRuleNamesContext(t *testing.T) {
	for f, n := range map[string]int{
		"../../context/docscan-critical/critical/zsu.yar":      2,
		"../../context/docscan-critical/org-rules-example.yar": 27,
		"../../context/yara-docscan-rules/docscan-policy.yar":  45,
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Skipf("%v", err)
		}
		got := len(RuleNames(string(b)))
		if n >= 0 && got != n {
			t.Errorf("%s: %d rules, want %d", f, got, n)
		}
		t.Logf("%s: %d rules", f, got)
	}
}

func TestIsRulesFile(t *testing.T) {
	for p, want := range map[string]bool{"a.yar": true, "b.YARA": true, "maldoc/inquest/IQY_File.rule": true, "x.yarc": false, "LICENSE": false, "a.yar.txt": false} {
		if IsRulesFile(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}
