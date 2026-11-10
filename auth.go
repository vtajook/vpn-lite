package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const cookieName = "vpn-ui"

func hashPass(salt, pass string) string {
	h := sha256.Sum256([]byte(salt + ":" + pass))
	return salt + "$" + base64.RawStdEncoding.EncodeToString(h[:])
}

func (s *Store) SetAdmin(user, pass string) {
	s.mu.Lock()
	s.st.Admin = Admin{User: user, Hash: hashPass(randHex(8), pass)}
	s.touch()
	s.mu.Unlock()
}

func (s *Store) CheckAdmin(user, pass string) bool {
	s.mu.RLock()
	a := s.st.Admin
	s.mu.RUnlock()
	if a.User == "" {
		return false
	}
	i := strings.IndexByte(a.Hash, '$')
	if i < 0 {
		return false
	}
	want := hashPass(a.Hash[:i], pass)
	okU := subtle.ConstantTimeCompare([]byte(user), []byte(a.User)) == 1
	okP := subtle.ConstantTimeCompare([]byte(want), []byte(a.Hash)) == 1
	return okU && okP
}

func (s *Store) sign(exp int64) string {
	msg := strconv.FormatInt(exp, 10)
	m := hmac.New(sha256.New, []byte(s.st.Secret))
	m.Write([]byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Store) verify(tok string) bool {
	i := strings.IndexByte(tok, '.')
	if i < 0 {
		return false
	}
	exp, err := strconv.ParseInt(tok[:i], 10, 64)
	if err != nil || exp < time.Now().Unix() {
		return false
	}
	s.mu.RLock()
	want := s.signLocked(exp)
	s.mu.RUnlock()
	return hmac.Equal([]byte(want), []byte(tok))
}

func (s *Store) signLocked(exp int64) string { return s.sign(exp) }

func (s *Store) issue(w http.ResponseWriter, secure bool) {
	s.mu.RLock()
	mins := s.st.Global.SessionMinutes
	base := s.st.Global.BasePath
	s.mu.RUnlock()
	exp := time.Now().Add(time.Duration(mins) * time.Minute)
	s.mu.RLock()
	tok := s.sign(exp.Unix())
	s.mu.RUnlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: base, Expires: exp,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

func (s *Store) loggedIn(r *http.Request) bool {
	id, ok := s.who(r)
	return ok && id == 0
}

// Reseller sessions use their own token form, "A.<id>.<ver>.<exp>.<sig>", signed with the same
// panel secret. The version is the agent's TokenVer, so a password change or a ban ends them.
func (s *Store) signAgent(id, ver int, exp int64) string {
	msg := "A." + strconv.Itoa(id) + "." + strconv.Itoa(ver) + "." + strconv.FormatInt(exp, 10)
	s.mu.RLock()
	m := hmac.New(sha256.New, []byte(s.st.Secret))
	s.mu.RUnlock()
	m.Write([]byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Store) issueAgent(w http.ResponseWriter, id, ver int, secure bool) {
	s.mu.RLock()
	mins := s.st.Global.SessionMinutes
	base := s.st.Global.BasePath
	s.mu.RUnlock()
	exp := time.Now().Add(time.Duration(mins) * time.Minute)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.signAgent(id, ver, exp.Unix()), Path: base, Expires: exp,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

// who reports the caller of a request: (0, true) the admin, (id, true) a reseller agent whose
// session is still valid, (_, false) nobody.
func (s *Store) who(r *http.Request) (int, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return 0, false
	}
	tok := c.Value
	if !strings.HasPrefix(tok, "A.") {
		return 0, s.verify(tok)
	}
	f := strings.Split(tok, ".")
	if len(f) != 5 {
		return 0, false
	}
	id, e1 := strconv.Atoi(f[1])
	ver, e2 := strconv.Atoi(f[2])
	exp, e3 := strconv.ParseInt(f[3], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || id <= 0 || exp < time.Now().Unix() {
		return 0, false
	}
	if !hmac.Equal([]byte(s.signAgent(id, ver, exp)), []byte(tok)) {
		return 0, false
	}
	if Ag == nil || !Ag.SessionOK(id, ver) {
		return 0, false
	}
	return id, true
}
