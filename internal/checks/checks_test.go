package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func texts(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, f.Level+" "+f.Text)
	}
	return strings.Join(s, "\n")
}

func TestLintTraps(t *testing.T) {
	src := `rule crit_bad
{
    meta:
        description = "x"
        category = "classified"
        owner = "sb"
    strings:
        $a = /[дd]ск/
        $b = /службов[^ ]{0,4} користуванн/
        $c = /\bтаємн/
        $d = "Для Службового"
        $e = /пароль.*:/
        $f = "два  пробіли"
        $g = "Upper" nocase
        $h = /\d{10}/
    condition:
        any of them
}
rule crit_nometa { strings: $a = "x" condition: $a }
`
	fs := LintCritical(src)
	s := texts(fs)
	for _, want := range []string{
		"error /[дd]ск/: кирилиця всередині",
		"{0,4} рахує БАЙТИ",
		`\b не працює з кирилицею`,
		`"Для Службового": великі літери`,
		"необмежений квантор",
		"рівно один пробіл",
		"crit_nometa: немає meta description",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in:\n%s", want, s)
		}
	}
	for _, not := range []string{`"Upper"`, `\d{10}`} {
		if strings.Contains(s, not) {
			t.Errorf("false alarm on %s:\n%s", not, s)
		}
	}
	if !HasErrors(fs) {
		t.Fatal("no errors")
	}
	if fs[0].Line != 1 && fs[0].Line != 8 {
		t.Logf("first finding on line %d", fs[0].Line)
	}
	for _, f := range fs {
		if strings.Contains(f.Text, "[дd]ск") && f.Line != 8 {
			t.Errorf("line %d, want 8", f.Line)
		}
	}
}

func TestLintImport(t *testing.T) {
	if !HasErrors(LintCritical("import \"pe\"\nrule a { condition: true }")) {
		t.Fatal("import accepted")
	}
}

// Правила, написані за CRITICAL-RULES.md, не мають давати помилок лінтера.
func TestLintContextRules(t *testing.T) {
	for _, p := range []string{"../../context/docscan-critical/critical/zsu.yar", "../../context/docscan-critical/org-rules-example.yar"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Skip(err)
		}
		fs := LintCritical(string(b))
		if HasErrors(fs) {
			t.Errorf("%s:\n%s", p, texts(fs))
		}
		t.Logf("%s: %d warnings\n%s", filepath.Base(p), len(fs), texts(fs))
	}
}

func real(t *testing.T) yaraexec.Tools {
	tl := yaraexec.FromEnv()
	if !tl.Configured() {
		t.Skip("HIVE_YARA / HIVE_YARAC are not set")
	}
	return tl
}

func TestCompileOwnReal(t *testing.T) {
	tl := real(t)
	fs, err := CompileOwn(tl, "org", "x.yar", "import \"pe\"\nrule X {\n condition:\n  nosuch and filename == \"a\"\n}\n", nil)
	if err != nil || len(fs) != 1 || fs[0].Line != 4 || !strings.Contains(fs[0].Text, "nosuch") {
		t.Fatalf("%+v %v", fs, err)
	}
	if fs, _ := CompileOwn(tl, "org", "x.yar", "rule X { condition: filename == \"a\" }", nil); len(fs) != 0 {
		t.Fatalf("good rule: %+v", fs)
	}
	other := map[string]string{"zsu.yar": "rule crit_a { strings: $a = \"x\" condition: $a }\n"}
	fs, err = CompileOwn(tl, "critical", "bank.yar", "rule crit_b {\n strings: $a = /[дd]ск/\n condition: $a }\n", other)
	if err != nil || len(fs) == 0 || fs[0].Line != 2 {
		t.Fatalf("%+v %v", fs, err)
	}
	if fs, _ := CompileOwn(tl, "critical", "bank.yar", "rule crit_b { strings: $a = /(д|d)ск/ condition: $a }\n", other); len(fs) != 0 {
		t.Fatalf("good critical: %+v", fs)
	}
}

func TestRuleTestsReal(t *testing.T) {
	tl := real(t)
	d := t.TempDir()
	w := func(n, s string) string { p := filepath.Join(d, n); os.WriteFile(p, []byte(s), 0o644); return p }
	rules := w("own.yar", "rule Mal_X { strings: $a = \"evil-marker\" condition: $a and extension == \".bin\" }\n")
	bad := w("sample.bin", "xx evil-marker xx")
	good := w("clean.bin", "nothing here")
	renamed := w("sample.txt", "xx evil-marker xx") // --file-vars: ім'я має значення
	res, err := RunRuleTests(tl, "org", rules, []TestFile{
		{Path: bad, Name: "sample.bin", Expect: "match", Rule: "Mal_X"},
		{Path: good, Name: "clean.bin", Expect: "no-match", Rule: "Mal_X"},
		{Path: renamed, Name: "sample.txt", Expect: "no-match", Rule: "Mal_X"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if !r.OK {
			t.Errorf("%s: matched %v, expected %s", r.Name, r.Matched, r.Expect)
		}
	}
	cd := filepath.Join(d, "critical")
	os.MkdirAll(cd, 0o755)
	os.WriteFile(filepath.Join(cd, "zsu.yar"), []byte("rule crit_markings { strings: $a = /службов[^ ]{0,12} користуванн/ condition: $a }\n"), 0o644)
	doc := w("doc.txt", "Документ ДЛЯ СЛУЖБОВОГО\n  КОРИСТУВАННЯ")
	res, err = RunRuleTests(tl, "critical", cd, []TestFile{{Path: doc, Name: "doc.txt", Expect: "match", Rule: "crit_markings"}})
	if err != nil || !res[0].OK {
		t.Fatalf("%+v %v", res, err)
	}
	md, nd := filepath.Join(d, "m"), filepath.Join(d, "n")
	os.MkdirAll(md, 0o755)
	os.MkdirAll(nd, 0o755)
	os.WriteFile(filepath.Join(md, "1.txt"), []byte("для службового користування"), 0o644)
	os.WriteFile(filepath.Join(md, "2.txt"), []byte("звичайний текст"), 0o644)
	os.WriteFile(filepath.Join(nd, "3.txt"), []byte("службове користування"), 0o644)
	sr, err := CheckCriticalSet(tl, cd, "", md, nd)
	if err != nil {
		t.Fatal(err)
	}
	if sr.Match != 2 || sr.NoMatch != 1 || len(sr.Missed) != 1 || sr.Missed[0] != "2.txt" || len(sr.Unwanted) != 1 {
		t.Fatalf("%+v", sr)
	}
}
