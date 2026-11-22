package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rifatismailov/Anthophila_Hive/internal/yaraexec"
)

func put(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for n, s := range files {
		p := filepath.Join(root, filepath.FromSlash(n))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func gate(r *Report, id string) Gate {
	for _, g := range r.Gates {
		if g.ID == id {
			return g
		}
	}
	return Gate{}
}

func TestLab(t *testing.T) {
	tools := yaraexec.FromEnv()
	if !tools.Configured() {
		t.Skip("HIVE_YARA / HIVE_YARAC are not set")
	}
	d := t.TempDir()
	crit := "rule ORG_CLASS_GRIF { meta: category = \"classified\" strings: $a = /службов[^ ]{0,12} користуванн/ condition: $a }\n" +
		"rule ORG_BANK_IBAN { strings: $a = /ua[0-9]{27}/ condition: $a }\n"
	base := filepath.Join(d, "base")
	put(t, base, map[string]string{
		"docscan-index.yar":  "include \"docscan-policy.yar\"\ninclude \"r.yar\"\n",
		"docscan-policy.yar": "import \"docscan\"\nrule DS_P { meta: severity = \"HIGH\" condition: false }\n",
		"r.yar": "rule Mal_A { strings: $a = \"evil-a\" condition: $a }\n" +
			"rule Mal_B { strings: $a = \"evil-b\" condition: $a }\n" +
			"rule Info_X : docscan_info { strings: $a = \"report\" condition: $a }\n",
		"critical/c.yar": crit,
	})
	cand := filepath.Join(d, "cand")
	put(t, cand, map[string]string{
		"docscan-index.yar":  "include \"docscan-policy.yar\"\ninclude \"r.yar\"\n",
		"docscan-policy.yar": "import \"docscan\"\nrule DS_P { meta: severity = \"HIGH\" condition: false }\n",
		// Mal_B прибрано (втрата виявлення), Mal_New — хибне на чистому, Slow — повільне
		"r.yar": "rule Mal_A { strings: $a = \"evil-a\" condition: $a }\n" +
			"rule Mal_New { strings: $a = \"invoice\" condition: $a }\n" +
			"rule Info_X : docscan_info { strings: $a = \"report\" condition: $a }\n" +
			"rule Slow { strings: $a = /zz.*qq/ condition: $a }\n",
		"critical/c.yar": "rule ORG_CLASS_GRIF { meta: category = \"classified\" strings: $a = /службов[^ ]{0,12} користуванн/ condition: $a }\n",
	})
	sets := []Set{
		{ID: "clean", Kind: "clean", Path: filepath.Join(d, "sets", "clean")},
		{ID: "mal", Kind: "malware", Path: filepath.Join(d, "sets", "mal")},
		{ID: "cm", Kind: "critical-match", Path: filepath.Join(d, "sets", "cm")},
		{ID: "cn", Kind: "critical-no-match", Path: filepath.Join(d, "sets", "cn")},
		{ID: "lab", Kind: "critical-labelled", Path: filepath.Join(d, "sets", "lab")},
	}
	put(t, sets[0].Path, map[string]string{"a.txt": "invoice for March", "b.txt": "annual report", "c.txt": "plain"})
	put(t, sets[1].Path, map[string]string{"s1.bin": "xx evil-a xx", "s2.bin": "xx evil-b xx", "s3.bin": "nothing"})
	put(t, sets[2].Path, map[string]string{"d1.txt": "для службового користування", "d2.txt": "рахунок ua123456789012345678901234567"})
	put(t, sets[3].Path, map[string]string{"n1.txt": "звичайний лист"})
	put(t, sets[4].Path, map[string]string{
		"expected.tsv":      "file\tfolder\texpected\ng1.txt\tclassified\tclassified\nb1.txt\tbank\tbank\nn1.txt\tclean\tnone\n",
		"classified/g1.txt": "для службового користування", "bank/b1.txt": "iban ua123456789012345678901234567", "clean/n1.txt": "текст",
	})
	rn := Runner{Tools: tools, Cache: filepath.Join(d, "cache"), Work: d, Threads: 4}
	for _, mode := range []string{"fast", "full"} {
		bpr, err := rn.Run(base, strings.Repeat("b", 64), "v1.0.0", sets, mode)
		if err != nil {
			t.Fatal(err)
		}
		cpr, err := rn.Run(cand, strings.Repeat("c", 64), "v1.0.1", sets, mode)
		if err != nil {
			t.Fatal(err)
		}
		r := Compare(cpr, bpr, sets, nil, Thresholds{})
		dump := func() {
			for _, g := range r.Gates {
				t.Logf("%s %s %s %s", g.ID, g.Status, g.Title, g.Detail)
				for _, it := range g.Items {
					t.Logf("    %+v", it)
				}
			}
			for _, c := range r.Categories {
				t.Logf("  cat %+v", c)
			}
		}
		want := map[string]string{"G1": Red, "G2": Red, "G3": Red, "G4": Red}
		for id, st := range want {
			if g := gate(r, id); g.Status != st {
				dump()
				t.Fatalf("%s: %s %s, want %s", mode, id, g.Status, st)
			}
		}
		if g := gate(r, "G2"); g.Total != 1 || g.Items[0].Rule != "Mal_New" || g.Items[0].File != "a.txt" {
			dump()
			t.Fatalf("%s: G2 items %+v (Info_X must not count)", mode, g.Items)
		}
		if g := gate(r, "G3"); g.Items[0].File != "s2.bin" {
			t.Fatalf("%s: G3 %+v", mode, g.Items)
		}
		if g := gate(r, "G4"); g.Total != 1 || g.Items[0].File != "d2.txt" || g.Items[0].Detail != "NOT FOUND" {
			t.Fatalf("%s: G4 %+v", mode, g.Items)
		}
		bank := false
		for _, c := range r.Categories {
			if c.Category == "bank" && c.Missed == 1 && c.BaseFound == 1 {
				bank = true
			}
		}
		if !bank || gate(r, "G5").Status != Yellow {
			dump()
			t.Fatalf("%s: categories", mode)
		}
		if r.Result != Red {
			t.Fatal("result not red")
		}
		// прийняти хибне — G2 зеленіє
		acc := []Accepted{{Gate: "G2", Rule: "Mal_New", Body: bodyOf(cpr, "Mal_New"), SHA256: gate(r, "G2").Items[0].SHA, Reason: "checked: invoices mention it", By: "t"}}
		if k := gate(r, "G2").Items[0].Key; k != acc[0].Key() {
			t.Fatalf("key %q vs %q", k, acc[0].Key())
		}
		r2 := Compare(cpr, bpr, sets, acc, Thresholds{})
		if g := gate(r2, "G2"); g.Status != Yellow || g.Items[0].Accepted == "" {
			t.Fatalf("%s: accepted G2 %+v", mode, g)
		}
		// без базового — немає червоних G2 / G3
		r3 := Compare(cpr, nil, sets, nil, Thresholds{})
		if gate(r3, "G2").Status == Red || gate(r3, "G3").Status == Red {
			t.Fatalf("%s: no baseline gives red", mode)
		}
		t.Logf("%s: candidate %.2fs on %d sets, sandbox %s", mode, cpr.Sets["mal"].Seconds, len(sets), cpr.Sets["mal"].Sandbox)
	}
	// повторний прогін — з кешу
	pr, _ := rn.Run(base, strings.Repeat("b", 64), "v1.0.0", sets, "fast")
	if !pr.Sets["clean"].Cached {
		t.Fatal("not cached")
	}
}

// Правила у файлах .rule (InQuest) — теж правила пакета: інакше їхні спрацювання лабораторія не враховує.
func TestRulesOfIncludesDotRule(t *testing.T) {
	d := t.TempDir()
	put(t, d, map[string]string{"maldoc/inquest/IQY_File.rule": "rule IQY_File { condition: false }\n", "general/a.yar": "rule A { condition: false }\n"})
	rs, err := RulesOf(d)
	if err != nil || len(rs) != 2 {
		t.Fatalf("%v %v", rs, err)
	}
}
