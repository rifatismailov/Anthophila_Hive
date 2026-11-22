package lists

import (
	"strings"
	"testing"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/manifest"
	"github.com/rifatismailov/Anthophila_Hive/internal/docscan/orglists"
)

func TestSignLikeDocScan(t *testing.T) {
	seed, pub, _ := manifest.NewSeed()
	l := &orglists.List{Schema: 1, Serial: 5, Entries: []orglists.Entry{
		{SHA256: "  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ", Comment: "x"},
		{LnkTarget: `\\srv\share`, Path: `C:\Users\*\Desktop\App*.lnk`, Comment: "app"},
	}}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	s, err := Sign(l, "white", seed, pub, 20261122120000, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Serial != 20261122120001 {
		t.Fatalf("serial %d (must exceed the published one)", s.Serial)
	}
	// підписано нормалізовані байти
	if !strings.Contains(string(s.Data), strings.Repeat("a", 64)) || !strings.Contains(string(s.Data), `\\\\srv\\share\\`) {
		t.Fatalf("not normalized:\n%s", s.Data)
	}
	if _, _, err := VerifySigned(s.Data, s.Sig, "white", []string{pub}, 20261122120000); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifySigned(s.Data, s.Sig, "white", []string{pub}, s.Serial); err == nil {
		t.Fatal("same serial accepted")
	}
	tampered := []byte(strings.Replace(string(s.Data), "app", "evil", 1))
	if _, _, err := VerifySigned(tampered, s.Sig, "white", []string{pub}, 0); err == nil {
		t.Fatal("tampered list accepted")
	}
	_, other, _ := manifest.NewSeed()
	if _, err := Sign(l, "white", seed, other, 0, now); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestCanonicalRejectsWhatPCsReject(t *testing.T) {
	bad := &orglists.List{Schema: 1, Entries: []orglists.Entry{{Path: `C:\Users\*\Downloads\*`}}}
	if _, _, err := Canonical(bad, "white"); err == nil || !strings.Contains(err.Error(), "every file of a folder") {
		t.Fatalf("got %v", err)
	}
	if _, _, err := Canonical(bad, "black"); err != nil {
		t.Fatalf("black list: %v", err)
	}
}

func TestWarnings(t *testing.T) {
	white := &orglists.List{Schema: 1, Entries: []orglists.Entry{
		{Path: `C:\Users\*\Desktop\App*.lnk`, LnkTarget: `\\fileserver\BIN\App\Bin\App.exe`, Comment: "app"}, // F5
		{Path: `C:\Tools\setup.exe`, Comment: "setup"},
		{SHA256: strings.Repeat("1", 64)},
	}}
	black := &orglists.List{Schema: 1, Entries: []orglists.Entry{{SHA256: strings.Repeat("1", 64), Comment: "bad"}}}
	ws := Warnings(white, black)
	var all []string
	for _, w := range ws {
		all = append(all, w.Text)
	}
	s := strings.Join(all, "\n")
	for _, want := range []string{"схожий на файл", "БУДЬ-ЯКИЙ файл", "немає comment", "чорний за sha256"} {
		if !strings.Contains(s, want) {
			t.Errorf("no warning %q in:\n%s", want, s)
		}
	}
}

func TestNextSerial(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if s := NextSerial(now); s != 20260102030405 {
		t.Fatal(s)
	}
	if s := NextSerial(now, 20270000000000); s != 20270000000001 {
		t.Fatal(s)
	}
}
