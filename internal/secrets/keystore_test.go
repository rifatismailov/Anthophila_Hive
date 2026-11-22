package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeystore(t *testing.T) {
	k := Keystore{Dir: filepath.Join(t.TempDir(), "keys")}
	pass := []byte("a keystore passphrase")
	if err := k.Put("rules", "ed25519-seed", "", []byte("x"), pass, "t", false); err == nil {
		t.Fatal("put before init")
	}
	if err := k.Init([]byte("short")); err == nil {
		t.Fatal("short passphrase")
	}
	if err := k.Init(pass); err != nil {
		t.Fatal(err)
	}
	if err := k.Put("rules", "ed25519-seed", "ed25519:PUB", []byte("SEED-VALUE"), []byte("wrong passphrase!!"), "t", false); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if err := k.Put("rules", "ed25519-seed", "ed25519:PUB", []byte("SEED-VALUE"), pass, "t", false); err != nil {
		t.Fatal(err)
	}
	if err := k.Put("rules", "ed25519-seed", "", []byte("other"), pass, "t", false); err == nil {
		t.Fatal("overwrite without replace")
	}
	b, _ := os.ReadFile(filepath.Join(k.Dir, "rules.json"))
	if strings.Contains(string(b), "SEED-VALUE") {
		t.Fatal("plaintext on disk")
	}
	if fi, _ := os.Stat(filepath.Join(k.Dir, "rules.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	v, err := k.Open("rules", pass)
	if err != nil || string(v) != "SEED-VALUE" {
		t.Fatalf("%q %v", v, err)
	}
	if l := k.List(); len(l) != 1 || l[0].Public != "ed25519:PUB" || l[0].By != "t" {
		t.Fatalf("%+v", l)
	}
	// посилання hive: через Get
	UseKeystore(&k)
	defer UseKeystore(nil)
	if _, err := Get("hive:rules", nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("no unlock: %v", err)
	}
	got, err := Get("hive:rules", func(string) ([]byte, error) { return []byte("a keystore passphrase"), nil })
	if err != nil || string(got) != "SEED-VALUE" {
		t.Fatalf("%q %v", got, err)
	}
	// новий пароль
	nw := []byte("a brand new passphrase")
	if err := k.Rekey(pass, nw); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open("rules", pass); err == nil {
		t.Fatal("old passphrase still works")
	}
	if v, _ := k.Open("rules", nw); string(v) != "SEED-VALUE" {
		t.Fatal("rekey lost the value")
	}
}
