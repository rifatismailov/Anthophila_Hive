package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rifatismailov/Anthophila_Hive/internal/auth"
	"github.com/rifatismailov/Anthophila_Hive/internal/secrets"
	"github.com/rifatismailov/Anthophila_Hive/internal/store"
)

// limiter — спроби входу з однієї адреси: не більше 20 за 15 хвилин (поверх блокування облікового запису).
type limiter struct {
	mu sync.Mutex
	m  map[string]*attempt
}

type attempt struct {
	n     int
	since time.Time
}

func (l *limiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[ip]
	if a == nil || now.Sub(a.since) > 15*time.Minute {
		a = &attempt{since: now}
		l.m[ip] = a
	}
	a.n++
	return a.n <= 20
}

const preCookie = "hive_login"

func randomToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

type loginData struct {
	Next, Name, Pre string
	NeedTOTP        bool
}

// login — GET: форма; POST: пароль (+ TOTP). Токен форми — у cookie до входу (подвійна відправка).
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	render := func(d loginData, e error) {
		// один токен на браузер: якщо cookie вже є — та сама форма в усіх вкладках (інакше кожне відкриття
		// сторінки входу перезаписувало cookie, і форма з іншої вкладки «застарівала»; знайдено у Firefox)
		if c, err := r.Cookie(preCookie); d.Pre == "" && err == nil && len(c.Value) >= 32 {
			d.Pre = c.Value
		}
		if d.Pre == "" {
			d.Pre = randomToken()
			http.SetCookie(w, &http.Cookie{Name: preCookie, Value: d.Pre, Path: "/login", HttpOnly: true, Secure: s.secure(r), SameSite: http.SameSiteStrictMode, MaxAge: 900})
		}
		if e != nil {
			w.WriteHeader(http.StatusUnauthorized)
		}
		s.render(w, r, "login", "Вхід", loginPage{loginData: d, Err: errText(e)})
	}
	if r.Method != http.MethodPost {
		render(loginData{Next: next}, nil)
		return
	}
	r.ParseForm()
	c, err := r.Cookie(preCookie)
	if err != nil || c.Value == "" || c.Value != r.FormValue("pre") {
		log.Printf("login: form token mismatch from %s (cookie present: %v, form token present: %v, user agent %q)",
			s.clientIP(r), err == nil, r.FormValue("pre") != "", r.UserAgent())
		render(loginData{Next: next}, errors.New("the form expired - try again"))
		return
	}
	if !s.lim.allow(s.clientIP(r), time.Now()) {
		render(loginData{Next: next}, auth.ErrLocked)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	u, err := s.app.Auth.Login(name, r.FormValue("password"), r.FormValue("totp"), time.Now())
	if errors.Is(err, auth.ErrNeedTOTP) {
		// пароль правильний — просимо код (пароль передається знову з формою, на сервері не зберігається)
		render(loginData{Next: next, Name: name, Pre: c.Value, NeedTOTP: true}, nil)
		return
	}
	if err != nil {
		log.Printf("login: %s from %s: %v", name, s.clientIP(r), err)
		s.app.DB.Audit("*", name, "login-failed", s.clientIP(r))
		render(loginData{Next: next, Name: name}, err)
		return
	}
	tok, err := s.app.Auth.NewSession(u.Name, s.clientIP(r), time.Now())
	if err != nil {
		render(loginData{Next: next}, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: preCookie, Value: "", Path: "/login", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: s.secure(r),
		SameSite: http.SameSiteStrictMode, MaxAge: int(auth.SessionTTL / time.Second)})
	s.app.DB.Audit("*", u.Name, "login", s.clientIP(r))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

type loginPage struct {
	loginData
	Err string
}

func errText(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.app.Auth.EndSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) accountRoutes() map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		"/users": s.users, "/users/add": s.usersAdd, "/users/role": s.usersRole, "/users/disable": s.usersDisable,
		"/users/password": s.usersPassword,
		"/profile":        s.profile, "/profile/password": s.profilePassword, "/profile/totp": s.profileTOTP,
		"/keys": s.keys, "/keys/init": s.keysInit, "/keys/token": s.keysToken, "/keys/rekey": s.keysRekey, "/keys/delete": s.keysDelete,
	}
}

// ---------------------------------------------------------------- користувачі (адміністратор)

type usersData struct {
	Users []auth.User
	Roles []auth.Role
	Audit []store.AuditEntry
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	if sess(r).User.Role < auth.Admin {
		s.fail(w, r, fmt.Errorf("only an admin manages users"))
		return
	}
	d := usersData{Roles: auth.Roles()}
	d.Users, _ = s.app.Auth.List()
	d.Audit, _ = s.app.DB.AuditLog("*", 40)
	s.render(w, r, "users", "Користувачі", d)
}

func (s *Server) usersAdd(w http.ResponseWriter, r *http.Request) {
	role, err := auth.ParseRole(r.FormValue("role"))
	if err == nil {
		err = s.app.Auth.Add(strings.TrimSpace(r.FormValue("name")), role, r.FormValue("password"))
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.app.DB.Audit("*", who(r), "user", "add "+r.FormValue("name")+" "+role.String())
	s.back(w, r, "/users", "користувача додано: тимчасовий пароль передайте особисто, він змінить його в профілі")
}

func (s *Server) usersRole(w http.ResponseWriter, r *http.Request) {
	role, err := auth.ParseRole(r.FormValue("role"))
	if err == nil {
		err = s.app.Auth.SetRole(r.FormValue("name"), role)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.app.DB.Audit("*", who(r), "user", "role "+r.FormValue("name")+" "+role.String())
	s.back(w, r, "/users", "роль змінено")
}

func (s *Server) usersDisable(w http.ResponseWriter, r *http.Request) {
	name, off := r.FormValue("name"), r.FormValue("disabled") == "1"
	if name == who(r) && off {
		s.fail(w, r, fmt.Errorf("you cannot disable yourself"))
		return
	}
	if err := s.app.Auth.SetDisabled(name, off); err != nil {
		s.fail(w, r, err)
		return
	}
	s.app.DB.Audit("*", who(r), "user", fmt.Sprintf("%s disabled=%v", name, off))
	s.back(w, r, "/users", "збережено")
}

func (s *Server) usersPassword(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Auth.SetPassword(r.FormValue("name"), r.FormValue("password")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.app.DB.Audit("*", who(r), "user", "reset password of "+r.FormValue("name"))
	s.back(w, r, "/users", "пароль скинуто, сесії користувача завершено")
}

// ---------------------------------------------------------------- профіль

type profileData struct {
	TOTPSecret, TOTPURI string
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	d := profileData{}
	if !sess(r).User.TOTP {
		d.TOTPSecret = auth.NewTOTPSecret()
		d.TOTPURI = auth.TOTPURI("Anthophila_Hive", who(r), d.TOTPSecret)
	}
	s.render(w, r, "profile", "Профіль", d)
}

func (s *Server) profilePassword(w http.ResponseWriter, r *http.Request) {
	if !s.app.Auth.CheckPassword(who(r), r.FormValue("current")) {
		s.fail(w, r, fmt.Errorf("the current password is wrong"))
		return
	}
	if r.FormValue("password") != r.FormValue("password2") {
		s.fail(w, r, fmt.Errorf("the new passwords differ"))
		return
	}
	if err := s.app.Auth.SetPassword(who(r), r.FormValue("password")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.app.DB.Audit("*", who(r), "user", "changed own password")
	http.Redirect(w, r, "/login?next=/profile", http.StatusSeeOther)
}

func (s *Server) profileTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.app.Auth.CheckPassword(who(r), r.FormValue("current")) {
		s.fail(w, r, fmt.Errorf("the current password is wrong"))
		return
	}
	secret := r.FormValue("secret")
	if r.FormValue("off") == "1" {
		secret = ""
	}
	if err := s.app.Auth.SetTOTP(who(r), secret, r.FormValue("code")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.app.DB.Audit("*", who(r), "user", fmt.Sprintf("TOTP %v", secret != ""))
	s.back(w, r, "/profile", map[bool]string{true: "одноразові коди ввімкнено", false: "одноразові коди вимкнено"}[secret != ""])
}

// ---------------------------------------------------------------- сховище ключів

type keysData struct {
	Initialized bool
	Entries     []secrets.Entry
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "keys", "Ключі", keysData{Initialized: s.app.Keys.Initialized(), Entries: s.app.Keys.List()})
}

func (s *Server) keysInit(w http.ResponseWriter, r *http.Request) {
	p1, p2 := r.FormValue("passphrase"), r.FormValue("passphrase2")
	if p1 != p2 {
		s.fail(w, r, fmt.Errorf("the passphrases differ"))
		return
	}
	if err := s.app.Keys.Init([]byte(p1)); err != nil {
		s.fail(w, r, err)
		return
	}
	s.app.DB.Audit("*", who(r), "keystore", "passphrase set")
	s.back(w, r, "/keys", "пароль сховища задано: запишіть його в сейф організації — без нього ключі не розшифрувати")
}

func (s *Server) keysToken(w http.ResponseWriter, r *http.Request) {
	v := strings.TrimSpace(r.FormValue("value"))
	if v == "" {
		s.fail(w, r, fmt.Errorf("the token is empty"))
		return
	}
	if err := s.app.PutToken(r.FormValue("name"), []byte(v), who(r), r.FormValue("replace") == "on"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/keys", "токен збережено як hive:"+r.FormValue("name"))
}

func (s *Server) keysRekey(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("new") != r.FormValue("new2") {
		s.fail(w, r, fmt.Errorf("the new passphrases differ"))
		return
	}
	if err := s.app.Keys.Rekey([]byte(r.FormValue("keystore_password")), []byte(r.FormValue("new"))); err != nil {
		s.fail(w, r, err)
		return
	}
	s.app.DB.Audit("*", who(r), "keystore", "passphrase changed")
	s.back(w, r, "/keys", "пароль сховища змінено")
}

func (s *Server) keysDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Keys.Verify([]byte(r.FormValue("keystore_password"))); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.app.Keys.Delete(r.FormValue("name")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.app.DB.Audit("*", who(r), "keystore", "delete hive:"+r.FormValue("name"))
	s.back(w, r, "/keys", "секрет прибрано")
}

// ---------------------------------------------------------------- схвалення релізу

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	ws := s.postWS(w, r)
	if ws == nil {
		return
	}
	v := r.FormValue("v")
	if err := s.app.Approve(ws, v, who(r), strings.TrimSpace(r.FormValue("note"))); err != nil {
		s.fail(w, r, err)
		return
	}
	s.back(w, r, "/release", "реліз схвалено", "v", v)
}
