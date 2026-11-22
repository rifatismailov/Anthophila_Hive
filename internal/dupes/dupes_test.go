package dupes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/yaraparse"
)

func rules(t *testing.T, src string) ([]yaraparse.Rule, string) {
	t.Helper()
	return yaraparse.Parse(src).Rules, src
}

func TestBodyHash(t *testing.T) {
	src := `
rule A : t1 {
  meta: author = "x"
  strings:
    $a = "evil" wide ascii
    $b = { 4D 5A 90 00 }   // header
  condition:
    uint16(0) == 0x5A4D and $a and #b > 1
}
rule B {
  meta: author = "someone else"
  strings:
    $hdr = {4d5a9000}
    $s1  = "evil" ascii wide
  condition:
    $s1 and #hdr>1 and uint16(0)==0x5A4D
}
rule C { strings: $a = "evil" wide ascii $b = { 4D 5A 90 00 } condition: uint16(0) == 0x5A4D and $a or #b > 1 }
rule D { strings: $a = "Evil" wide ascii $b = { 4D 5A 90 00 } condition: uint16(0) == 0x5A4D and $a and #b > 1 }
rule E { strings: $a = "evil" wide $b = { 4D 5A 90 00 } condition: uint16(0) == 0x5A4D and $a and #b > 1 }
`
	rs, _ := rules(t, src)
	h := map[string]string{}
	for _, r := range rs {
		h[r.Name] = BodyHash(r)
	}
	if h["A"] != h["B"] {
		t.Error("A and B are the same rule (other names, order, ids, spacing, hex case, modifier order, meta)")
	}
	for _, n := range []string{"C", "D", "E"} {
		if h[n] == h["A"] {
			t.Errorf("%s differs from A (or / case / modifier) but has the same hash", n)
		}
	}
}

func TestTextHashIgnoresComments(t *testing.T) {
	a, sa := rules(t, "rule X { // one\n condition: true }\n")
	b, sb := rules(t, "rule X {\n  /* two */ condition:   true\n}\n")
	c, sc := rules(t, "rule Y { condition: true }\n")
	if TextHash(sa, a[0]) != TextHash(sb, b[0]) {
		t.Error("comments / spacing change the text hash")
	}
	if TextHash(sa, a[0]) == TextHash(sc, c[0]) {
		t.Error("another name, same text hash")
	}
}

func TestGroups(t *testing.T) {
	mk := func(origin, file, name, kind, body, text string) Member {
		return Member{Origin: origin, File: file, Name: name, Kind: kind, BodyHash: body, TextHash: text}
	}
	g := Groups([]Member{
		mk("s", "a.yar", "X", "detection", "b1", "t1"),
		mk("s", "b.yar", "X", "detection", "b1", "t1"), // L0
		mk("s", "c.yar", "Y", "detection", "b1", "t2"), // L1 з X
		mk("org", "org/z.yar", "Z", "detection", "b9", "t9"),
		mk("s", "d.yar", "Z", "detection", "b8", "t8"),            // L4
		mk("crit", "critical/z.yar", "Z", "critical", "b7", "t7"), // критичне — інший простір назв
	})
	levels := map[string]int{}
	for _, x := range g {
		levels[x.Level]++
	}
	if levels["L0"] != 1 || levels["L1"] != 1 || levels["L4"] != 1 {
		t.Fatalf("%+v", g)
	}
}

// На справжньому дереві правил генератор уже прибрав точні дублікати; групи L1 / L4 мають бути поодинокі.
func TestRealTree(t *testing.T) {
	root := os.Getenv("HIVE_RULES_REPO")
	if root == "" {
		t.Skip("HIVE_RULES_REPO is not set")
	}
	var ms []Member
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() && fi.Name() == ".git" {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(p, ".yar") && !strings.HasSuffix(p, ".yara") {
			return nil
		}
		b, _ := os.ReadFile(p)
		src := string(b)
		rel, _ := filepath.Rel(root, p)
		for _, r := range yaraparse.Parse(src).Rules {
			ms = append(ms, Member{Origin: "s", File: rel, Name: r.Name, Kind: "detection", Private: r.Private, TextHash: TextHash(src, r), BodyHash: BodyHash(r)})
		}
		return nil
	})
	g := Groups(ms)
	n := map[string]int{}
	for _, x := range g {
		n[x.Level]++
		if n[x.Level] <= 3 {
			var names []string
			for _, m := range x.Members {
				names = append(names, m.File+":"+m.Name)
			}
			t.Logf("%s %s", x.Level, strings.Join(names, " | "))
		}
	}
	t.Logf("%d rules: L0 %d, L1 %d, L4 %d groups", len(ms), n["L0"], n["L1"], n["L4"])
}

// Регресія: індекс без хешів (старий формат) не має зливати бібліотеку в одну «групу дублікатів».
func TestEmptyHashesNeverGroup(t *testing.T) {
	var ms []Member
	for i := 0; i < 100; i++ {
		ms = append(ms, Member{Origin: "s", File: "f.yar", Name: "R" + string(rune('A'+i%26)) + string(rune('a'+i/26)), Kind: "detection"})
	}
	if g := Groups(ms); len(g) != 0 {
		t.Fatalf("%d groups from rules without hashes", len(g))
	}
}

func sim(t *testing.T, src string) []SimMember {
	t.Helper()
	var out []SimMember
	for _, r := range yaraparse.Parse(src).Rules {
		s, c := Signature(r)
		out = append(out, SimMember{Member: Member{Origin: "s", File: "f.yar", Name: r.Name, Kind: "detection", TextHash: TextHash(src, r), BodyHash: BodyHash(r)}, Strings: s, Cond: c})
	}
	return out
}

func TestSimilar(t *testing.T) {
	src := `
rule Base { strings: $a = "one" $b = "two" $c = "three" $d = "four" $e = "five" condition: 3 of them }
rule Near { strings: $a = "one" $b = "two" $c = "three" $d = "four" $e = "five" $f = "six" condition: 3 of them }
rule Far  { strings: $a = "one" $b = "x" $c = "y" $d = "z" condition: 3 of them }
rule PAExec { strings: $a = "pa1" $b = "pa2" $c = "pa3" condition: uint16(0) == 0x5A4D and all of them }
rule PAExec_Cloaked { strings: $x = "pa3" $y = "pa1" $z = "pa2" condition: uint16(0) == 0x5A4D and all of them and not filename iequals "paexec.exe" }
`
	g := Similar(sim(t, src))
	var l2, l3 []string
	for _, x := range g {
		var n []string
		for _, m := range x.Members {
			n = append(n, m.Name)
		}
		if x.Level == "L2" {
			l2 = append(l2, strings.Join(n, ","))
		} else {
			l3 = append(l3, strings.Join(n, ","))
		}
	}
	if len(l2) != 1 || l2[0] != "Base,Near" {
		t.Errorf("L2 %v", l2)
	}
	if len(l3) != 1 || l3[0] != "PAExec,PAExec_Cloaked" {
		t.Errorf("L3 %v", l3)
	}
}

func TestSimilarRealTree(t *testing.T) {
	root := os.Getenv("HIVE_RULES_REPO")
	if root == "" {
		t.Skip("HIVE_RULES_REPO is not set")
	}
	var ms []SimMember
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() && fi.Name() == ".git" {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(p, ".yar") && !strings.HasSuffix(p, ".yara") {
			return nil
		}
		b, _ := os.ReadFile(p)
		src := string(b)
		rel, _ := filepath.Rel(root, p)
		for _, r := range yaraparse.Parse(src).Rules {
			s, c := Signature(r)
			ms = append(ms, SimMember{Member: Member{Origin: "s", File: rel, Name: r.Name, Kind: "detection", Private: r.Private, TextHash: TextHash(src, r), BodyHash: BodyHash(r)}, Strings: s, Cond: c})
		}
		return nil
	})
	g := Similar(ms)
	n := map[string]int{}
	for _, x := range g {
		n[x.Level]++
		if n[x.Level] <= 3 {
			var names []string
			for _, m := range x.Members {
				names = append(names, m.File+":"+m.Name)
			}
			t.Logf("%s %s", x.Level, strings.Join(names, " | "))
		}
	}
	t.Logf("%d rules: L2 %d groups, L3 %d pairs", len(ms), n["L2"], n["L3"])
}
