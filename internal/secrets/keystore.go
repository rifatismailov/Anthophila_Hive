package secrets

// Сховище ключів Hive на сервері (PLAN.md, розділ 11): ключ підпису правил, ключ списків, токени — у теці даних,
// кожен зашифрований паролем сховища (scrypt → AES-256-GCM). Пароль знає людина (публікатор / адміністратор) і
// вводить його у веб на час однієї дії; відкритим секрет на диску не лежить ніколи, у пам'яті — лише на час дії.
// Посилання на секрет у налаштуваннях простору: hive:<назва>.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Keystore — тека з зашифрованими секретами.
type Keystore struct{ Dir string }

type sealed struct {
	V       int    `json:"v"`
	KDF     string `json:"kdf"`
	N       int    `json:"n"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	Salt    string `json:"salt"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
	Kind    string `json:"kind,omitempty"`   // ed25519-seed | token
	Public  string `json:"public,omitempty"` // для ключів — публічна частина (не секрет)
	Created string `json:"created,omitempty"`
	By      string `json:"by,omitempty"`
}

// Entry — секрет у сховищі (без значення).
type Entry struct {
	Name, Kind, Public, Created, By string
}

const (
	scryptN = 1 << 16
	scryptR = 8
	scryptP = 1
	check   = ".passphrase-check" // перевірка пароля сховища: відоме значення, зашифроване ним
)

var ksName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrWrongPassphrase — неправильний пароль сховища.
var ErrWrongPassphrase = errors.New("wrong keystore passphrase")

func seal(plain, pass []byte) (*sealed, error) {
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	rand.Read(salt)
	rand.Read(nonce)
	key, err := scrypt.Key(pass, salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	e := base64.StdEncoding
	return &sealed{V: 1, KDF: "scrypt", N: scryptN, R: scryptR, P: scryptP, Salt: e.EncodeToString(salt), Nonce: e.EncodeToString(nonce),
		Data: e.EncodeToString(gcm.Seal(nil, nonce, plain, nil))}, nil
}

func (s *sealed) open(pass []byte) ([]byte, error) {
	e := base64.StdEncoding
	salt, err1 := e.DecodeString(s.Salt)
	nonce, err2 := e.DecodeString(s.Nonce)
	data, err3 := e.DecodeString(s.Data)
	if err1 != nil || err2 != nil || err3 != nil || s.KDF != "scrypt" {
		return nil, fmt.Errorf("keystore entry is damaged")
	}
	key, err := scrypt.Key(pass, salt, s.N, s.R, s.P, 32)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	blk, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCM(blk)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("keystore entry is damaged")
	}
	out, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return out, nil
}

func (k Keystore) path(name string) string { return filepath.Join(k.Dir, name+".json") }

func (k Keystore) read(name string) (*sealed, error) {
	b, err := os.ReadFile(k.path(name))
	if err != nil {
		return nil, fmt.Errorf("no secret hive:%s", name)
	}
	var s sealed
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("hive:%s is damaged", name)
	}
	return &s, nil
}

func (k Keystore) write(name string, s *sealed) error {
	if err := os.MkdirAll(k.Dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := k.path(name) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, k.path(name))
}

// Initialized — пароль сховища вже задано.
func (k Keystore) Initialized() bool {
	_, err := os.Stat(k.path(check))
	return err == nil
}

// Init — задати пароль сховища (один раз).
func (k Keystore) Init(pass []byte) error {
	if k.Initialized() {
		return fmt.Errorf("the keystore already has a passphrase")
	}
	if len([]rune(string(pass))) < 16 {
		return fmt.Errorf("the keystore passphrase needs at least 16 characters")
	}
	s, err := seal([]byte("anthophila-hive-keystore"), pass)
	if err != nil {
		return err
	}
	return k.write(check, s)
}

// Verify — пароль сховища правильний.
func (k Keystore) Verify(pass []byte) error {
	s, err := k.read(check)
	if err != nil {
		return fmt.Errorf("the keystore has no passphrase yet (admin: set it first)")
	}
	v, err := s.open(pass)
	if err != nil {
		return err
	}
	Wipe(v)
	return nil
}

// Put — зашифрувати й записати секрет (перезапис наявного — лише з replace).
func (k Keystore) Put(name, kind, public string, value, pass []byte, by string, replace bool) error {
	if !ksName.MatchString(name) || name == check {
		return fmt.Errorf("secret name %q: a-z 0-9 . _ -", name)
	}
	if err := k.Verify(pass); err != nil {
		return err
	}
	if _, err := os.Stat(k.path(name)); err == nil && !replace {
		return fmt.Errorf("hive:%s already exists", name)
	}
	s, err := seal(value, pass)
	if err != nil {
		return err
	}
	s.Kind, s.Public, s.Created, s.By = kind, public, time.Now().UTC().Format(time.RFC3339), by
	return k.write(name, s)
}

// Open — розшифрований секрет (викликач затирає Wipe).
func (k Keystore) Open(name string, pass []byte) ([]byte, error) {
	s, err := k.read(name)
	if err != nil {
		return nil, err
	}
	return s.open(pass)
}

// List — секрети (без значень).
func (k Keystore) List() []Entry {
	ps, _ := filepath.Glob(filepath.Join(k.Dir, "*.json"))
	var out []Entry
	for _, p := range ps {
		n := filepath.Base(p)
		n = n[:len(n)-len(".json")]
		if n == check {
			continue
		}
		if s, err := k.read(n); err == nil {
			out = append(out, Entry{Name: n, Kind: s.Kind, Public: s.Public, Created: s.Created, By: s.By})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Delete — прибрати секрет.
func (k Keystore) Delete(name string) error {
	if !ksName.MatchString(name) || name == check {
		return fmt.Errorf("secret name %q", name)
	}
	return os.Remove(k.path(name))
}

// Rekey — новий пароль сховища: кожен секрет розшифровується старим і шифрується новим.
func (k Keystore) Rekey(old, nw []byte) error {
	if err := k.Verify(old); err != nil {
		return err
	}
	if len([]rune(string(nw))) < 16 {
		return fmt.Errorf("the keystore passphrase needs at least 16 characters")
	}
	names := []string{check}
	for _, e := range k.List() {
		names = append(names, e.Name)
	}
	resealed := map[string]*sealed{}
	for _, n := range names {
		s, err := k.read(n)
		if err != nil {
			return err
		}
		v, err := s.open(old)
		if err != nil {
			return fmt.Errorf("hive:%s: %w", n, err)
		}
		ns, err := seal(v, nw)
		Wipe(v)
		if err != nil {
			return err
		}
		ns.Kind, ns.Public, ns.Created, ns.By = s.Kind, s.Public, s.Created, s.By
		resealed[n] = ns
	}
	for n, s := range resealed {
		if err := k.write(n, s); err != nil {
			return err
		}
	}
	return nil
}

// hiveStore — сховище, з якого Get бере посилання hive:<назва> (задає застосунок).
var hiveStore *Keystore

// UseKeystore — посилання hive:<назва> розв'язувати з k.
func UseKeystore(k *Keystore) { hiveStore = k }
