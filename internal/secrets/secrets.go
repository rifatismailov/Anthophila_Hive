// Package secrets — ключі підпису й токени лише із захищеного сховища, ніколи з файлу на диску.
//
// Посилання на секрет (ref) у налаштуваннях простору:
//
//	env:NAME                          змінна середовища процесу Hive
//	keychain:SERVICE/ACCOUNT          системне сховище ключів (macOS Keychain, утиліта security)
//	keepassxc:/шлях/db.kdbx#Група/Запис   KeePassXC (keepassxc-cli show -s -a Password); пароль бази — Unlock
//	hive:<назва>                      сховище ключів Hive на сервері (keystore.go); пароль сховища — Unlock("hive")
//
// Значення секрету повертається як []byte: після використання — Wipe.
package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Ref — розібране посилання.
type Ref struct {
	Kind  string // env | keychain | keepassxc
	Name  string // env: змінна; keychain: сервіс; keepassxc: шлях до бази
	Entry string // keychain: обліковий запис; keepassxc: запис
}

// Parse — розбір посилання.
func Parse(s string) (Ref, error) {
	kind, rest, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || rest == "" {
		return Ref{}, fmt.Errorf("secret ref %q: expected env:NAME, keychain:SERVICE/ACCOUNT or keepassxc:DB#ENTRY", s)
	}
	switch kind {
	case "env":
		return Ref{Kind: kind, Name: rest}, nil
	case "keychain":
		svc, acct, ok := strings.Cut(rest, "/")
		if !ok || svc == "" || acct == "" {
			return Ref{}, fmt.Errorf("secret ref %q: expected keychain:SERVICE/ACCOUNT", s)
		}
		return Ref{Kind: kind, Name: svc, Entry: acct}, nil
	case "hive":
		if !ksName.MatchString(rest) {
			return Ref{}, fmt.Errorf("secret ref %q: expected hive:<name>", s)
		}
		return Ref{Kind: kind, Name: rest}, nil
	case "keepassxc":
		db, entry, ok := strings.Cut(rest, "#")
		if !ok || db == "" || entry == "" {
			return Ref{}, fmt.Errorf("secret ref %q: expected keepassxc:/path/db.kdbx#Group/Entry", s)
		}
		return Ref{Kind: kind, Name: db, Entry: entry}, nil
	}
	return Ref{}, fmt.Errorf("secret ref %q: unknown kind %q", s, kind)
}

func (r Ref) String() string {
	switch r.Kind {
	case "env":
		return "env:" + r.Name
	case "keychain":
		return "keychain:" + r.Name + "/" + r.Entry
	case "hive":
		return "hive:" + r.Name
	}
	return "keepassxc:" + r.Name + "#" + r.Entry
}

// ErrLocked — потрібен пароль (сховища ключів Hive або бази KeePassXC) — Unlock.
var ErrLocked = errors.New("the keystore passphrase is needed")

// Unlock — пароль бази KeePassXC (лише в пам'яті; для веб-інтерфейсу — введений людиною на час однієї дії).
type Unlock func(db string) ([]byte, error)

// Get — значення секрету.
func Get(ref string, unlock Unlock) ([]byte, error) {
	r, err := Parse(ref)
	if err != nil {
		return nil, err
	}
	switch r.Kind {
	case "env":
		v := strings.TrimSpace(os.Getenv(r.Name))
		if v == "" {
			return nil, fmt.Errorf("secret %s: the variable is empty", r)
		}
		return []byte(v), nil
	case "hive":
		if hiveStore == nil {
			return nil, fmt.Errorf("secret %s: no Hive keystore", r)
		}
		if unlock == nil {
			return nil, fmt.Errorf("secret %s: %w", r, ErrLocked)
		}
		pass, err := unlock("hive")
		if err != nil {
			return nil, err
		}
		defer Wipe(pass)
		return hiveStore.Open(r.Name, pass)
	case "keychain":
		if runtime.GOOS != "darwin" {
			return nil, fmt.Errorf("secret %s: keychain is supported on macOS only (use env: or keepassxc:)", r)
		}
		out, err := exec.Command("security", "find-generic-password", "-s", r.Name, "-a", r.Entry, "-w").Output()
		if err != nil {
			return nil, fmt.Errorf("secret %s: not found in the keychain", r)
		}
		return bytes.TrimSpace(out), nil
	default:
		if unlock == nil {
			return nil, fmt.Errorf("secret %s: %w", r, ErrLocked)
		}
		pw, err := unlock(r.Name)
		if err != nil {
			return nil, err
		}
		defer Wipe(pw)
		cmd := exec.Command("keepassxc-cli", "show", "-q", "-s", "-a", "Password", r.Name, r.Entry)
		cmd.Stdin = bytes.NewReader(append(append([]byte(nil), pw...), '\n'))
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("secret %s: keepassxc-cli failed (wrong password or no entry)", r)
		}
		return bytes.TrimSpace(out), nil
	}
}

// StoreKeychain — записати секрет у macOS Keychain. Значення йде через stdin утиліти security (security -i), а не
// в аргументах (аргументи видно в списку процесів).
func StoreKeychain(service, account string, value []byte) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("keychain is supported on macOS only")
	}
	if strings.ContainsAny(service+account, "\" \n") || bytes.ContainsAny(value, "\" \n") {
		return fmt.Errorf("keychain: service, account and value must not contain spaces, quotes or newlines")
	}
	cmd := exec.Command("security", "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -s \"%s\" -a \"%s\" -w \"%s\"\n", service, account, value))
	if out, err := cmd.CombinedOutput(); err != nil || strings.Contains(strings.ToLower(string(out)), "error") {
		return fmt.Errorf("keychain: cannot store %s/%s: %v %s", service, account, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DeleteKeychain — прибрати секрет (для тестів і заміни ключа).
func DeleteKeychain(service, account string) {
	exec.Command("security", "delete-generic-password", "-s", service, "-a", account).Run()
}

// Wipe — затерти значення в пам'яті.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Redactor — замінює відомі секрети в тексті (журнал, помилки) на ***.
type Redactor struct{ values [][]byte }

// Add — запам'ятати значення (копія; коротші за 6 символів не маскуються — забагато хибних замін).
func (r *Redactor) Add(v []byte) {
	if len(bytes.TrimSpace(v)) >= 6 {
		r.values = append(r.values, append([]byte(nil), bytes.TrimSpace(v)...))
	}
}

// Clean — текст без секретів.
func (r *Redactor) Clean(s string) string {
	for _, v := range r.values {
		s = strings.ReplaceAll(s, string(v), "***")
	}
	return s
}
