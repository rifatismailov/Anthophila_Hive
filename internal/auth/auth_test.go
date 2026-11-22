package auth

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func open(t *testing.T) *Store {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	s, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTOTPRFC6238(t *testing.T) {
	// RFC 6238, додаток B: секрет "12345678901234567890" (SHA-1), час 59 → 94287082 (8 цифр) → 287082 (6)
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, err := TOTPCode(secret, ts/30)
		if err != nil || got != want {
			t.Errorf("t=%d: %s, want %s (%v)", ts, got, want, err)
		}
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery", h) || VerifyPassword("wrong", h) {
		t.Fatal("verify")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("no salt")
	}
}

func TestUsersLoginLockTOTPSessions(t *testing.T) {
	s := open(t)
	if err := s.Add("admin", Admin, "short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := s.Add("Admin!", Admin, "a long enough password"); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := s.Add("admin", Admin, "a long enough password"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole("admin", Editor); err == nil {
		t.Fatal("last admin demoted")
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	if _, err := s.Login("admin", "a long enough password", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login("nobody", "x", "", now); err != ErrBadLogin {
		t.Fatalf("unknown user: %v", err)
	}
	// блокування після 5 невдалих
	for i := 0; i < 5; i++ {
		s.Login("admin", "wrong password!!", "", now)
	}
	if _, err := s.Login("admin", "a long enough password", "", now); err != ErrLocked {
		t.Fatalf("not locked: %v", err)
	}
	if _, err := s.Login("admin", "a long enough password", "", now.Add(16*time.Minute)); err != nil {
		t.Fatalf("still locked: %v", err)
	}
	// TOTP
	sec := NewTOTPSecret()
	code, _ := TOTPCode(sec, time.Now().Unix()/30)
	if err := s.SetTOTP("admin", sec, "000000"); err == nil && code != "000000" {
		t.Fatal("wrong code enabled TOTP")
	}
	if err := s.SetTOTP("admin", sec, code); err != nil {
		t.Fatal(err)
	}
	at := now.Add(time.Hour)
	if _, err := s.Login("admin", "a long enough password", "", at); err != ErrNeedTOTP {
		t.Fatalf("no TOTP asked: %v", err)
	}
	c, _ := TOTPCode(sec, at.Unix()/30)
	if _, err := s.Login("admin", "a long enough password", c, at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login("admin", "a long enough password", c, at); err == nil {
		t.Fatal("the same code accepted twice")
	}
	// сесії
	tok, _ := s.NewSession("admin", "127.0.0.1", now)
	if ss, err := s.Session(tok, now.Add(time.Hour)); err != nil || ss.User.Name != "admin" || ss.CSRF == "" {
		t.Fatalf("%+v %v", ss, err)
	}
	if _, err := s.Session(tok, now.Add(SessionTTL+time.Minute)); err == nil {
		t.Fatal("expired session accepted")
	}
	tok, _ = s.NewSession("admin", "", now)
	s.Add("ed", Editor, "another long password")
	s.Add("root2", Admin, "another long password")
	s.SetDisabled("admin", true)
	if _, err := s.Session(tok, now); err == nil {
		t.Fatal("session of a disabled user")
	}
	if err := s.SetDisabled("root2", true); err == nil {
		t.Fatal("last active admin disabled")
	}
	tok, _ = s.NewSession("ed", "", now)
	s.SetPassword("ed", "a new long password")
	if _, err := s.Session(tok, now); err == nil {
		t.Fatal("session survived a password change")
	}
}
