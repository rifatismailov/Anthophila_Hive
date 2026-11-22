// Package auth — користувачі веб-інтерфейсу Hive: локальні облікові записи (пароль argon2id + TOTP за бажанням),
// ролі, сесії, обмеження спроб входу (PLAN.md, розділ 11).
//
// Ролі — за зростанням прав (кожна вміє все, що попередні):
//
//	viewer     переглядає все
//	editor     змінює правила, рішення, списки, джерела, тести; збирає кандидатів; проганяє лабораторію
//	reviewer   схвалює релізи до публікації, приймає перевірені спрацювання лабораторії
//	publisher  розблоковує ключі, підписує й публікує (не той, хто зібрав реліз, — «чотири ока»)
//	admin      користувачі, цілі, ключі, набори лабораторії, налаштування
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Role — роль користувача.
type Role int

const (
	Viewer Role = iota + 1
	Editor
	Reviewer
	Publisher
	Admin
)

var roleNames = map[Role]string{Viewer: "viewer", Editor: "editor", Reviewer: "reviewer", Publisher: "publisher", Admin: "admin"}

func (r Role) String() string { return roleNames[r] }

// ParseRole — роль з назви.
func ParseRole(s string) (Role, error) {
	for r, n := range roleNames {
		if n == s {
			return r, nil
		}
	}
	return 0, fmt.Errorf("role %q: viewer | editor | reviewer | publisher | admin", s)
}

// Roles — усі ролі за зростанням.
func Roles() []Role { return []Role{Viewer, Editor, Reviewer, Publisher, Admin} }

// User — обліковий запис.
type User struct {
	Name      string
	Role      Role
	TOTP      bool
	Disabled  bool
	Created   time.Time
	LastLogin time.Time
}

// Store — користувачі й сесії в SQLite Hive.
type Store struct{ DB *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS users (
  name TEXT PRIMARY KEY, hash TEXT NOT NULL, role INTEGER NOT NULL, totp TEXT NOT NULL DEFAULT '',
  totp_last INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL,
  last_login TEXT NOT NULL DEFAULT '', failed INTEGER NOT NULL DEFAULT 0, locked_until TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, name TEXT NOT NULL, csrf TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL, ip TEXT NOT NULL
);
`

// Open — таблиці в базі Hive.
func Open(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Store{DB: db}, nil
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,31}$`)

// Помилки входу (людині — одне повідомлення, щоб не підказувати, чого саме бракує).
var (
	ErrBadLogin = errors.New("wrong user name, password or code")
	ErrLocked   = errors.New("too many failed attempts - try again later")
	ErrNeedTOTP = errors.New("the one-time code is needed")
)

// MinPassword — мінімальна довжина пароля.
const MinPassword = 12

func checkPassword(p string) error {
	if len([]rune(p)) < MinPassword {
		return fmt.Errorf("the password needs at least %d characters", MinPassword)
	}
	return nil
}

// ---------------------------------------------------------------- argon2id

const (
	argTime, argMem, argThreads, argLen = 3, 64 * 1024, 2, 32
)

// HashPassword — "$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>".
func HashPassword(p string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(p), salt, argTime, argMem, argThreads, argLen)
	e := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argMem, argTime, argThreads, e.EncodeToString(salt), e.EncodeToString(h)), nil
}

// VerifyPassword — пароль відповідає хешу.
func VerifyPassword(p, encoded string) bool {
	f := strings.Split(encoded, "$")
	if len(f) != 6 || f[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var th uint8
	if _, err := fmt.Sscanf(f[3], "m=%d,t=%d,p=%d", &m, &t, &th); err != nil {
		return false
	}
	e := base64.RawStdEncoding
	salt, err1 := e.DecodeString(f[4])
	want, err2 := e.DecodeString(f[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(p), salt, t, m, th, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---------------------------------------------------------------- TOTP (RFC 6238, SHA-1, 6 цифр, 30 с)

// NewTOTPSecret — новий секрет (base32 без «=»).
func NewTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
}

// TOTPCode — код для кроку counter.
func TOTPCode(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(padBase32(strings.ToUpper(strings.ReplaceAll(secret, " ", ""))))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	s := m.Sum(nil)
	off := s[len(s)-1] & 0x0f
	v := binary.BigEndian.Uint32(s[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

func padBase32(s string) string {
	if n := len(s) % 8; n != 0 {
		s += strings.Repeat("=", 8-n)
	}
	return s
}

// TOTPURI — otpauth:// для застосунку-автентифікатора.
func TOTPURI(issuer, user, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&period=30&digits=6", issuer, user, secret, issuer)
}

// checkTOTP — код для поточного кроку ±1, не використаний раніше (last — останній прийнятий крок).
func checkTOTP(secret, code string, now time.Time, last int64) (int64, bool) {
	c := now.Unix() / 30
	for _, d := range []int64{0, -1, 1} {
		if c+d <= last {
			continue
		}
		want, err := TOTPCode(secret, c+d)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(strings.TrimSpace(code))) == 1 {
			return c + d, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------- користувачі

// Add — новий користувач.
func (s *Store) Add(name string, role Role, password string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("user name %q: 2-32 of a-z 0-9 . _ -, starting with a letter", name)
	}
	if role < Viewer || role > Admin {
		return fmt.Errorf("bad role")
	}
	if err := checkPassword(password); err != nil {
		return err
	}
	h, err := HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO users (name,hash,role,created) VALUES (?,?,?,?)`, name, h, int(role), now())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("user %s already exists", name)
	}
	return err
}

// Count — кількість користувачів.
func (s *Store) Count() int {
	var n int
	s.DB.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n
}

// Get — користувач.
func (s *Store) Get(name string) (*User, error) {
	var u User
	var role, dis int
	var totp, created, last string
	err := s.DB.QueryRow(`SELECT name,role,totp,disabled,created,last_login FROM users WHERE name=?`, name).Scan(&u.Name, &role, &totp, &dis, &created, &last)
	if err != nil {
		return nil, fmt.Errorf("no user %s", name)
	}
	u.Role, u.TOTP, u.Disabled = Role(role), totp != "", dis != 0
	u.Created, _ = time.Parse(time.RFC3339, created)
	u.LastLogin, _ = time.Parse(time.RFC3339, last)
	return &u, nil
}

// List — усі користувачі.
func (s *Store) List() ([]User, error) {
	rows, err := s.DB.Query(`SELECT name FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		names = append(names, n)
	}
	rows.Close()
	var out []User
	for _, n := range names {
		if u, err := s.Get(n); err == nil {
			out = append(out, *u)
		}
	}
	return out, nil
}

// SetRole — змінити роль (останнього активного адміністратора не понизити).
func (s *Store) SetRole(name string, role Role) error {
	u, err := s.Get(name)
	if err != nil {
		return err
	}
	if u.Role == Admin && role != Admin && s.activeAdmins() <= 1 {
		return fmt.Errorf("%s is the last admin", name)
	}
	_, err = s.DB.Exec(`UPDATE users SET role=? WHERE name=?`, int(role), name)
	return err
}

// SetDisabled — вимкнути / увімкнути (сесії вимкненого — завершуються).
func (s *Store) SetDisabled(name string, disabled bool) error {
	u, err := s.Get(name)
	if err != nil {
		return err
	}
	if disabled && u.Role == Admin && !u.Disabled && s.activeAdmins() <= 1 {
		return fmt.Errorf("%s is the last admin", name)
	}
	if _, err := s.DB.Exec(`UPDATE users SET disabled=? WHERE name=?`, disabled, name); err != nil {
		return err
	}
	if disabled {
		s.DB.Exec(`DELETE FROM sessions WHERE name=?`, name)
	}
	return nil
}

func (s *Store) activeAdmins() int {
	var n int
	s.DB.QueryRow(`SELECT count(*) FROM users WHERE role=? AND disabled=0`, int(Admin)).Scan(&n)
	return n
}

// SetPassword — новий пароль (усі сесії користувача завершуються).
func (s *Store) SetPassword(name, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	h, err := HashPassword(password)
	if err != nil {
		return err
	}
	res, err := s.DB.Exec(`UPDATE users SET hash=?, failed=0, locked_until='' WHERE name=?`, h, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no user %s", name)
	}
	s.DB.Exec(`DELETE FROM sessions WHERE name=?`, name)
	return nil
}

// CheckPassword — поточний пароль (для зміни пароля / TOTP).
func (s *Store) CheckPassword(name, password string) bool {
	var h string
	if s.DB.QueryRow(`SELECT hash FROM users WHERE name=?`, name).Scan(&h) != nil {
		return false
	}
	return VerifyPassword(password, h)
}

// SetTOTP — увімкнути TOTP (секрет перевіряється кодом) або вимкнути (secret "").
func (s *Store) SetTOTP(name, secret, code string) error {
	if secret != "" {
		if _, ok := checkTOTP(secret, code, time.Now(), 0); !ok {
			return fmt.Errorf("the code does not match - check the time on the phone and try again")
		}
	}
	_, err := s.DB.Exec(`UPDATE users SET totp=?, totp_last=0 WHERE name=?`, secret, name)
	return err
}

const (
	maxFailed = 5
	lockFor   = 15 * time.Minute
)

// Login — перевірка пароля (і коду TOTP, якщо увімкнено); після 5 невдалих спроб — блокування на 15 хвилин.
func (s *Store) Login(name, password, code string, at time.Time) (*User, error) {
	var hash, totp, locked string
	var last int64
	var failed, dis, role int
	err := s.DB.QueryRow(`SELECT hash,totp,totp_last,failed,locked_until,disabled,role FROM users WHERE name=?`, name).
		Scan(&hash, &totp, &last, &failed, &locked, &dis, &role)
	if err != nil {
		VerifyPassword(password, "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") // той самий час
		return nil, ErrBadLogin
	}
	if t, err := time.Parse(time.RFC3339, locked); err == nil && at.Before(t) {
		return nil, ErrLocked
	}
	fail := func(e error) (*User, error) {
		failed++
		lock := ""
		if failed >= maxFailed {
			lock, failed = at.Add(lockFor).UTC().Format(time.RFC3339), 0
		}
		s.DB.Exec(`UPDATE users SET failed=?, locked_until=? WHERE name=?`, failed, lock, name)
		return nil, e
	}
	if !VerifyPassword(password, hash) || dis != 0 {
		return fail(ErrBadLogin)
	}
	if totp != "" {
		if strings.TrimSpace(code) == "" {
			return nil, ErrNeedTOTP
		}
		step, ok := checkTOTP(totp, code, at, last)
		if !ok {
			return fail(ErrBadLogin)
		}
		last = step
	}
	s.DB.Exec(`UPDATE users SET failed=0, locked_until='', totp_last=?, last_login=? WHERE name=?`, last, at.UTC().Format(time.RFC3339), name)
	return s.Get(name)
}

// ---------------------------------------------------------------- сесії

// Session — сесія веб-інтерфейсу.
type Session struct {
	User    *User
	CSRF    string
	Expires time.Time
}

// SessionTTL — тривалість сесії.
const SessionTTL = 12 * time.Hour

func tokenHash(t string) string { h := sha256.Sum256([]byte(t)); return hex.EncodeToString(h[:]) }

func random(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewSession — сесія для користувача; токен — у cookie (у базі лише його sha256).
func (s *Store) NewSession(name, ip string, at time.Time) (token string, err error) {
	token = random(32)
	_, err = s.DB.Exec(`INSERT INTO sessions VALUES (?,?,?,?,?,?)`, tokenHash(token), name, random(24), at.UTC().Format(time.RFC3339),
		at.Add(SessionTTL).UTC().Format(time.RFC3339), ip)
	s.DB.Exec(`DELETE FROM sessions WHERE expires < ?`, at.UTC().Format(time.RFC3339))
	return token, err
}

// Session — сесія за токеном (нема / прострочена / користувач вимкнений — помилка).
func (s *Store) Session(token string, at time.Time) (*Session, error) {
	if token == "" {
		return nil, errors.New("no session")
	}
	var name, csrf, exp string
	if err := s.DB.QueryRow(`SELECT name,csrf,expires FROM sessions WHERE token=?`, tokenHash(token)).Scan(&name, &csrf, &exp); err != nil {
		return nil, errors.New("no session")
	}
	t, _ := time.Parse(time.RFC3339, exp)
	if at.After(t) {
		s.DB.Exec(`DELETE FROM sessions WHERE token=?`, tokenHash(token))
		return nil, errors.New("session expired")
	}
	u, err := s.Get(name)
	if err != nil || u.Disabled {
		return nil, errors.New("no session")
	}
	return &Session{User: u, CSRF: csrf, Expires: t}, nil
}

// EndSession — вихід.
func (s *Store) EndSession(token string) {
	s.DB.Exec(`DELETE FROM sessions WHERE token=?`, tokenHash(token))
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }
