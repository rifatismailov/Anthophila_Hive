package docscan

// Копії пакетів DocScan мають лишатися ДОСЛІВНИМИ: Hive вирішує так само, як ПК, лише поки код той самий.
//
// Тест перевіряє дві речі:
//  1. копія в Hive має sha256, записаний у vendored (хтось змінив копію — червоно);
//  2. якщо поруч є оригінал (context/docscan-go або чекаут yara-docscan у HIVE_DOCSCAN_GO), він збігається з копією
//     (DocScan оновив свій код, а копію — ні — червоно: скопіювати заново і оновити sha256 тут і у VENDORED.md).

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// vendored — шлях копії (від цієї теки) -> шлях оригіналу (від кореня docscan-go) і sha256.
var vendored = []struct{ copy, orig, sha string }{
	{"manifest/manifest.go", "manifest/manifest.go", "0050afd63f4877de54c831e316803e5ef6ef10e3a36d94226f27530569be6b5a"},
	{"orglists/orglists.go", "orglists/orglists.go", "5a08e23c431d40590c1332d0e630870c5cc278fe8ba2f1cf8d99d853e530f60d"},
	{"orglists/orglists_test.go", "orglists/orglists_test.go", "c88fc959efbd715dd1b50592a41ea61e468480a1c693469d96bcea58a4ac72b0"},
}

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestVendoredCopiesUnchanged(t *testing.T) {
	for _, v := range vendored {
		if got := fileSHA(t, v.copy); got != v.sha {
			t.Errorf("%s: sha256 %s, expected %s - the copy of DocScan code must stay verbatim", v.copy, got, v.sha)
		}
	}
}

func TestVendoredCopiesMatchDocScan(t *testing.T) {
	root := os.Getenv("HIVE_DOCSCAN_GO")
	if root == "" {
		root = filepath.Join("..", "..", "context", "docscan-go")
	}
	if _, err := os.Stat(root); err != nil {
		t.Skipf("no DocScan sources at %s (set HIVE_DOCSCAN_GO)", root)
	}
	for _, v := range vendored {
		o := filepath.Join(root, v.orig)
		if _, err := os.Stat(o); err != nil {
			t.Errorf("%s: %v", o, err)
			continue
		}
		if got := fileSHA(t, o); got != v.sha {
			t.Errorf("%s changed in DocScan (sha256 %s): copy it to internal/docscan/%s and update the sha256", o, got, v.copy)
		}
	}
}
