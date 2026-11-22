package yaraexec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForbiddenOptions(t *testing.T) {
	tl := Tools{Yara: "/bin/echo", Yarac: "/bin/echo"}
	for _, a := range [][]string{
		{"--docscan-disarm", "x.yar", "f"},
		{"--docscan-extract=/tmp/vba", "x.yar", "f"},
		{"-w", "--docscan-backup-dir=/tmp", "x.yar", "f"},
		{"--docscan-no-sandbox"},
	} {
		if _, err := tl.RunYara("", a...); !errors.Is(err, ErrForbidden) {
			t.Errorf("%v: expected ErrForbidden, got %v", a, err)
		}
	}
	if _, err := tl.RunYara("", "-w", "--docscan-json", "--critical-rules=x"); err != nil {
		t.Errorf("allowed options refused: %v", err)
	}
}

// Перевірки справжнім DocScan: HIVE_YARA / HIVE_YARAC.
func realTools(t *testing.T) Tools {
	tl := FromEnv()
	if !tl.Configured() {
		t.Skip("HIVE_YARA / HIVE_YARAC are not set")
	}
	return tl
}

func TestProbeRealDocScan(t *testing.T) {
	tl := realTools(t)
	inf, err := tl.Probe()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DocScan yara %s", inf.Version)
}

func TestCompileRealDocScan(t *testing.T) {
	tl := realTools(t)
	d := t.TempDir()
	write := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(d, p)), 0o755)
		os.WriteFile(filepath.Join(d, p), []byte(s), 0o644)
	}
	write("docscan-index.yar", "include \"a.yar\"\n")
	write("a.yar", "import \"docscan\"\nrule A { condition: filename == \"x\" }\n")
	if err := tl.CompileIndex(d); err != nil {
		t.Fatalf("good rules: %v", err)
	}
	write("a.yar", "rule A { condition: nosuch }\n")
	if err := tl.CompileIndex(d); err == nil {
		t.Fatal("broken rules compiled")
	}
	write("critical/ok.yar", "rule CRIT_OK { strings: $a = /службов[^ ]{0,12} користуванн/ condition: $a }\n")
	if err := tl.CompileCritical(filepath.Join(d, "critical")); err != nil {
		t.Fatalf("good critical rules: %v", err)
	}
	// кирилиця всередині [...] — пастка №2 з CRITICAL-RULES.md: не компілюється
	write("critical/bad.yar", "rule CRIT_BAD { strings: $a = /[дd]ск/ condition: $a }\n")
	if err := tl.CompileCritical(filepath.Join(d, "critical")); err == nil {
		t.Fatal("cyrillic inside [...] compiled")
	}
}

func TestSandboxReal(t *testing.T) {
	tl := realTools(t)
	if SandboxKind() == "" {
		t.Skip("no OS sandbox")
	}
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "r.yar"), []byte("rule T { strings: $a = \"x\" condition: $a }\n"), 0o644)
	os.WriteFile(filepath.Join(d, "f.txt"), []byte("x"), 0o644)
	tl.Sandbox = d
	r, err := tl.RunYara(d, "-w", filepath.Join(d, "r.yar"), filepath.Join(d, "f.txt"))
	if err != nil || !strings.Contains(r.Output, "T ") {
		t.Fatalf("%+v %v", r, err)
	}
	warns, err := tl.CompileYarc(d, filepath.Join(d, "x.yarc"))
	if err == nil {
		t.Fatalf("no docscan-index.yar compiled: %v", warns)
	}
	os.WriteFile(filepath.Join(d, "docscan-index.yar"), []byte("rule S { strings: $a = /a.*b/ condition: $a }\n"), 0o644)
	warns, err = tl.CompileYarc(d, filepath.Join(d, "x.yarc"))
	if err != nil || len(warns) == 0 {
		t.Fatalf("warnings %v %v", warns, err)
	}
}
