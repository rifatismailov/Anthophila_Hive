package vendor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func TestDecodeReplaceLikePython(t *testing.T) {
	// python3: b.decode("utf-8", errors="replace")
	for in, want := range map[string]string{
		"ok":                 "ok",
		"a\xffb":             "a\ufffdb",
		"a\xe2\x82b":         "a\ufffdb",       // усічена 3-байтова — один символ заміни
		"a\xe2\x82\xe2\x82b": "a\ufffd\ufffdb", // дві усічені
		"\xc0\x80":           "\ufffd\ufffd",   // C0 — недопустимий початок
		"\xed\xa0\x80":       "\ufffd\ufffd\ufffd",
		"\xf0\x9f\x98":       "\ufffd",
		"\xf0\x9f\x98\x80":   "\U0001F600",
	} {
		if got := decodeReplace([]byte(in)); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestSplitRulesAndTags(t *testing.T) {
	src := "import \"pe\"\n// c\nrule A : x {\n condition: true\n}\n/* about B */\nprivate rule B { strings: $a = \"condition: no\" condition: $a }\n"
	pre, rules, tail := splitRules(src)
	if pre != "import \"pe\"\n// c\n" || len(rules) != 2 || tail != "\n" {
		t.Fatalf("pre %q rules %d tail %q", pre, len(rules), tail)
	}
	if !rules[1].private || !strings.HasPrefix(rules[1].text, "\n/* about B */") || strings.TrimSpace(rules[1].cond) != "$a }" && !strings.Contains(rules[1].cond, "$a") {
		t.Fatalf("%+v", rules[1])
	}
	if got := addTag(rules[0].text, rules[0].hoff, "docscan_info"); !strings.HasPrefix(got, "rule A : x docscan_info {") {
		t.Fatalf("add tag to tagged: %q", got)
	}
	r := "rule C\n{\n condition: true\n}"
	if got := addTag(r, 0, "docscan_doc"); !strings.HasPrefix(got, "rule C : docscan_doc {") {
		t.Fatalf("add tag: %q", got)
	}
}

// Паритет з Python-генератором: з тих самих закріплених джерел — ті самі файли байт у байт, що в yara-docscan-rules.
// HIVE_VENDOR_DIR — теки джерел (як vendor-sources генератора); HIVE_RULES_REPO — чекаут yara-docscan-rules.
func TestParityWithPython(t *testing.T) {
	vdir, repo := os.Getenv("HIVE_VENDOR_DIR"), os.Getenv("HIVE_RULES_REPO")
	if vdir == "" || repo == "" {
		t.Skip("HIVE_VENDOR_DIR / HIVE_RULES_REPO are not set")
	}
	c, err := ImportPython(filepath.Join(repo, "tools", "build_vendor_rules.py"))
	if err != nil {
		t.Fatal(err)
	}
	selText, _ := os.ReadFile(filepath.Join(repo, "tools", "vendor-selection.txt"))
	sel, err := ParseSelection(string(selText))
	if err != nil {
		t.Fatal(err)
	}
	in := Inputs{Sources: map[string]string{}, VBAPlaintext: filepath.Join(repo, "maldoc", "vba_plaintext.yar")}
	for _, s := range c.Sources {
		in.Sources[s.Name] = filepath.Join(vdir, s.Name)
	}
	out := t.TempDir()
	rep, err := Build(c, sel, in, out, yaraexec.FromEnv())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("files %d, rules %d, dropped %d, duplicates %d, info %d, doc %d", rep.Files, rep.Rules, len(rep.Dropped), len(rep.Duplicates), len(rep.Info), len(rep.Doc))
	// усе, що згенеровано, — байт у байт як у репозиторії
	n, diff := 0, 0
	filepath.Walk(out, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(out, p)
		want, err := os.ReadFile(filepath.Join(repo, rel))
		got, _ := os.ReadFile(p)
		n++
		if err != nil {
			diff++
			t.Errorf("extra %s", rel)
		} else if !bytes.Equal(got, want) {
			diff++
			if diff <= 5 {
				i := 0
				for i < len(got) && i < len(want) && got[i] == want[i] {
					i++
				}
				lo := i - 80
				if lo < 0 {
					lo = 0
				}
				t.Errorf("%s differs at byte %d:\n got  %q\n want %q", rel, i, got[lo:min(len(got), i+80)], want[lo:min(len(want), i+80)])
			}
		}
		return nil
	})
	// і нічого не пропущено з того, що генерує Python
	for _, d := range append([]string{"general", "maldoc"}, "file-index.yar", "tools/vendor-report.md") {
		filepath.Walk(filepath.Join(repo, d), func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(repo, p)
			if _, err := os.Stat(filepath.Join(out, rel)); err != nil {
				diff++
				t.Errorf("missing %s", rel)
			}
			return nil
		})
	}
	if diff > 0 {
		t.Fatalf("%d of %d files differ", diff, n)
	}
	t.Logf("%d files identical to %s", n, repo)
}

func TestParseReport(t *testing.T) {
	text := "# Vendor rules — build report\n\nFiles: 3, rules kept: 10, dropped: 2, duplicates skipped: 1, renamed: 1, info: 1, doc: 1\n\n" +
		"## Dropped (cannot fire on a Windows workstation / DROP list) (2)\n\n- sb/yara/a.yar: A — old: last change 2015\n- sb/yara/a.yar: B — ELF only\n\n" +
		"## Duplicates skipped (identical rule already taken from another file) (1)\n\n- c/x.yar: D — same as sb/yara/d.yar\n\n" +
		"## Files with no rule left (1)\n\n- sb/yara/e.yar — no rule left\n\n" +
		"## Renamed (identifier clashes) (1)\n\n- c/y.yar: R -> R_2\n\n" +
		"## Tagged `docscan_info` (indicators, do not raise the verdict) (1)\n\n- bb/i.yar: I (source: informational)\n\n" +
		"## Tagged `docscan_doc` (document rules: indicators only on non-documents) (1)\n\n- sb/m.yar: M\n"
	pr := ParseReport(text)
	if pr.Counts["rules kept"] != 10 || pr.Counts["doc"] != 1 || len(pr.Entries) != 6 {
		t.Fatalf("%+v", pr)
	}
	want := []ReportEntry{{"dropped", "sb/yara/a.yar", "A", "old: last change 2015"}, {"dropped", "sb/yara/a.yar", "B", "ELF only"},
		{"duplicate", "c/x.yar", "D", "same as sb/yara/d.yar"}, {"renamed", "c/y.yar", "R", "R_2"}, {"info", "bb/i.yar", "I", "source: informational"}, {"doc", "sb/m.yar", "M", ""}}
	for i, w := range want {
		if pr.Entries[i] != w {
			t.Errorf("%d: %+v, want %+v", i, pr.Entries[i], w)
		}
	}
}
