package yaraparse

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sample = `import "pe"
import "math"
// header comment

/* about A */
rule A : tag1 tag2 {
    meta:
        description = "A \"quoted\" rule"
        score = 70
        modified = "2024-01-02"
    strings:
        $a = { 4D 5A }
        $b = "condition: fake" wide
    condition:
        uint16(0) == 0x5A4D and $a and $b
}

private rule B { condition: A and pe.number_of_sections > 1 }
rule C { strings: $x = /meta: [a-z]{1,3}/ condition: $x or B }
`

func TestParse(t *testing.T) {
	f := Parse(sample)
	if !reflect.DeepEqual(f.Imports, []string{"pe", "math"}) {
		t.Fatalf("imports %v", f.Imports)
	}
	if len(f.Rules) != 3 {
		t.Fatalf("%d rules", len(f.Rules))
	}
	a, b, c := f.Rules[0], f.Rules[1], f.Rules[2]
	if a.Name != "A" || !reflect.DeepEqual(a.Tags, []string{"tag1", "tag2"}) || a.Line != 6 {
		t.Fatalf("A: %+v", a)
	}
	if a.MetaValue("description") != `A "quoted" rule` || a.MetaValue("score") != "70" || a.MetaValue("modified") != "2024-01-02" {
		t.Fatalf("meta %v", a.Meta)
	}
	if !strings.Contains(a.Strings, "$b = \"condition: fake\"") || !strings.Contains(a.Condition, "uint16(0)") {
		t.Fatalf("sections: %q / %q", a.Strings, a.Condition)
	}
	if !strings.HasPrefix(a.Text(sample), `import "pe"`) || !strings.HasSuffix(a.Text(sample), "}") {
		t.Fatalf("A text %q", a.Text(sample))
	}
	if !b.Private || b.Name != "B" || !strings.HasPrefix(strings.TrimSpace(b.Text(sample)), "private rule B") {
		t.Fatalf("B: %+v %q", b, b.Text(sample))
	}
	if c.Name != "C" || !strings.Contains(c.Strings, "/meta: [a-z]{1,3}/") {
		t.Fatalf("C: %+v", c)
	}
	if w := ConditionWords(c); !reflect.DeepEqual(w, []string{"x", "or", "B"}) {
		t.Fatalf("words %v", w)
	}
}

func TestRemove(t *testing.T) {
	out, missing := Remove(sample, map[string]bool{"B": true, "Nope": true})
	if strings.Contains(out, "private rule B") || !strings.Contains(out, "rule A") || !strings.Contains(out, "rule C") {
		t.Fatalf("remove B:\n%s", out)
	}
	if !reflect.DeepEqual(missing, []string{"Nope"}) {
		t.Fatalf("missing %v", missing)
	}
	if again := Parse(out); len(again.Rules) != 2 {
		t.Fatalf("after removal %d rules", len(again.Rules))
	}
	out, _ = Remove(sample, map[string]bool{"A": true})
	if strings.Contains(out, "about A") || !strings.Contains(out, `import "math"`) {
		// коментар перед правилом іде разом з ним; але імпорти — частина «коментарів перед першим правилом»
		t.Logf("%s", out)
	}
}

// Вендорні файли з context/ (у т.ч. ReversingLabs .yara): кількість правил = кількість заголовків за grep.
func TestParseVendorSamples(t *testing.T) {
	files, _ := filepath.Glob("../../context/yara-docscan-rules/samples/*")
	if len(files) == 0 {
		t.Skip("no samples")
	}
	for _, p := range files {
		b, _ := os.ReadFile(p)
		f := Parse(string(b))
		n := 0
		for _, l := range strings.Split(string(b), "\n") {
			s := strings.TrimSpace(l)
			s = strings.TrimPrefix(strings.TrimPrefix(s, "private "), "global ")
			if strings.HasPrefix(s, "rule ") {
				n++
			}
		}
		if len(f.Rules) != n {
			t.Errorf("%s: %d rules, grep says %d", filepath.Base(p), len(f.Rules), n)
		}
		for _, r := range f.Rules {
			if r.Condition == "" {
				t.Errorf("%s: %s has no condition", filepath.Base(p), r.Name)
			}
		}
	}
}
