package main

import (
	"crypto/subtle"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------- sessions

type Session struct {
	ID        string
	Email     string
	InboundID int
	Proto     string
	SrcIP     string // the client's address as the server sees it
	VIP       string // tunnel address handed to the client
	Dev       string // network device carrying it (resolved lazily)

	Start    int64  // unix ms
	Kill     func() // engine-specific disconnect; must not block on the caller's locks
	Up, Down int64  // last absolute counters seen (client->server, server->client)
	LastSeen int64  // unix ms of the last event for this session
	dying    bool   // evicted/kicked: no longer counts toward the cap, removed on its Stop event
}

type SessionTable struct {
	mu   sync.Mutex
	byID map[string]*Session
}

var Sessions = &SessionTable{byID: map[string]*Session{}}

func (t *SessionTable) liveOf(email string) []*Session {
	var out []*Session
	for _, s := range t.byID {
		if !s.dying && strings.EqualFold(s.Email, email) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

func (t *SessionTable) Add(s *Session) { t.mu.Lock(); t.byID[s.ID] = s; t.mu.Unlock() }
func (t *SessionTable) Remove(id string) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.byID[id]
	delete(t.byID, id)
	return s
}
func (t *SessionTable) Get(id string) *Session { t.mu.Lock(); defer t.mu.Unlock(); return t.byID[id] }

func (t *SessionTable) IPsOf(email string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var ips []string
	for _, s := range t.liveOf(email) {
		ips = append(ips, s.SrcIP)
	}
	return ips
}

func (t *SessionTable) Snapshot() []Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Session, 0, len(t.byID))
	for _, s := range t.byID {
		if s.dying {
			continue
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start > out[j].Start })
	return out
}

func (t *SessionTable) KickEmail(email string) int {
	t.mu.Lock()
	live := t.liveOf(email)
	for _, s := range live {
		s.dying = true
	}
	t.mu.Unlock()
	for _, s := range live {
		if s.Kill != nil {
			s.Kill()
		}
	}
	return len(live)
}

// ---------------------------------------------------------------- authorization

type AuthResult struct {
	OK      bool
	Reason  string
	Account *Account
	Email   string // copied under the store lock
	Family  string // protocol family of the inbound: openvpn, l2tp, openconnect
	Single  bool   // the account may use only one protocol at a time
}

func intSetting(m map[string]any, k string, def int) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return def
}
func strSetting(m map[string]any, k, def string) string {
	if v, ok := m[k].(string); ok && v != "" {
		return v
	}
	return def
}

// Authorize decides whether (user, pass) may start a session on an inbound.
// If sess != nil and the login is accepted, the session is reserved in the table
// inside the same critical section as the device-cap check, so two simultaneous
// logins can never both slip under the cap.
func (s *Store) Authorize(inboundID int, user, pass string, sess *Session) AuthResult {
	return s.AuthorizeFn(inboundID, user, func(stored string) bool {
		return subtle.ConstantTimeCompare([]byte(stored), []byte(pass)) == 1
	}, sess)
}

// checkAccount validates credentials and account state (no device-cap logic).
// It returns the account's effective device limit alongside the result.
func (s *Store) checkAccount(inboundID int, user string, verify func(stored string) bool) (AuthResult, int) {
	now := nowMs()
	s.mu.RLock()
	defer s.mu.RUnlock()
	in := s.st.Inbounds[inboundID]
	var acc *Account
	for _, a := range s.st.Accounts {
		if strings.EqualFold(a.Username, user) {
			acc = a
			break
		}
	}
	if in == nil || !in.Enable {
		return AuthResult{Reason: "inbound disabled"}, 0
	}
	if acc == nil || !verify(acc.Password) {
		return AuthResult{Reason: "bad credentials"}, 0
	}
	res := AuthResult{Account: acc, Email: acc.Email, Family: in.Protocol, Single: acc.SingleProto}
	switch {
	case !hasInt(acc.Inbounds, inboundID):
		res.Reason = "not a member of this inbound"
	case !acc.Enable:
		res.Reason = "account disabled"
	case acc.expired(now):
		res.Reason = "account expired"
	case acc.overQuota():
		res.Reason = "quota exhausted"
	case in.ExpiryTime > 0 && in.ExpiryTime <= now:
		res.Reason = "inbound expired"
	}
	limit := acc.LimitIP
	if limit <= 0 {
		limit = intSetting(in.Settings, "userLimit", 1)
	}
	return res, limit
}

// AuthorizeFn is Authorize with a pluggable credential check (CHAP and MS-CHAPv2 cannot
// hand the server a cleartext password; they verify against the stored one instead).
func (s *Store) AuthorizeFn(inboundID int, user string, verify func(stored string) bool, sess *Session) AuthResult {
	res, limit := s.checkAccount(inboundID, user, verify)
	if res.Reason != "" {
		return res
	}
	now := nowMs()
	email := res.Email
	s.mu.RLock()
	g := s.st.Global
	s.mu.RUnlock()

	Sessions.mu.Lock()
	live := Sessions.liveOf(email)
	var evict []*Session
	deny := func(why string) AuthResult {
		Sessions.mu.Unlock()
		res.Reason = why
		return res
	}
	// canEvict applies the panel policy to one existing session.
	canEvict := func(s *Session) string {
		if g.LimitStrategy == "reject" {
			return "device limit reached"
		}
		if now-s.Start < int64(g.EvictGraceSec)*1000 {
			return "device limit reached (other device just connected)"
		}
		return ""
	}
	same := live
	if res.Single {
		// one protocol at a time: sessions on any OTHER protocol are in the way
		same = nil
		for _, s := range live {
			if protoFamily(s.Proto) == res.Family {
				same = append(same, s)
			} else if why := canEvict(s); why != "" {
				return deny("account is connected on another protocol; " + why)
			} else {
				evict = append(evict, s)
			}
		}
	}
	// device cap among the sessions that remain relevant: evict the oldest, but never a
	// session younger than the grace window, so two devices cannot kick each other forever.
	if limit > 0 && len(same) >= limit {
		for i := 0; i < len(same)-limit+1; i++ {
			if why := canEvict(same[i]); why != "" {
				return deny(why)
			}
			evict = append(evict, same[i])
		}
	}
	for _, e := range evict {
		e.dying = true
	}
	if sess != nil {
		sess.Email = email
		sess.Start, sess.LastSeen = now, now
		Sessions.byID[sess.ID] = sess
	}
	Sessions.mu.Unlock()
	for _, e := range evict {
		if e.Kill != nil {
			go e.Kill()
		}
	}
	res.OK = true
	return res
}

// ---------------------------------------------------------------- accounting & enforcement

// AddTraffic adds a delta to an account and reports whether it is now depleted.
func (s *Store) AddTraffic(email string, up, down int64) (depleted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc := s.st.Accounts[ekey(email)]
	if acc == nil {
		return false
	}
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	acc.Up += up
	acc.Down += down
	acc.AllTime += up + down
	s.st.Global.TotalUsed += up + down
	acc.LastOnline = nowMs()
	s.touch()
	return acc.overQuota()
}

// EnforceLoop kicks sessions of accounts that became disabled, expired or depleted,
// and applies periodic traffic resets. Cheap: it only looks at accounts with live sessions.
func (s *Store) EnforceLoop(stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		now := nowMs()
		seen := map[string]bool{}
		for _, sn := range Sessions.Snapshot() {
			if seen[sn.Email] {
				continue
			}
			seen[sn.Email] = true
			s.mu.RLock()
			acc := s.st.Accounts[ekey(sn.Email)]
			dead := acc == nil || !acc.Enable || acc.expired(now) || acc.overQuota()
			s.mu.RUnlock()
			if dead {
				Sessions.KickEmail(sn.Email)
			}
		}
	}
}

// SweepStale drops sessions that have been silent for too long (daemon crashed, packet lost).
func (t *SessionTable) SweepStale(maxAge time.Duration) []*Session {
	cut := nowMs() - maxAge.Milliseconds()
	t.mu.Lock()
	defer t.mu.Unlock()
	var gone []*Session
	for id, s := range t.byID {
		if s.LastSeen < cut {
			gone = append(gone, s)
			delete(t.byID, id)
		}
	}
	return gone
}

// Touch updates a session's counters; it returns the (up, down) delta since the last call.
func (t *SessionTable) Touch(id string, up, down int64) (dUp, dDown int64, s *Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s = t.byID[id]
	if s == nil {
		return 0, 0, nil
	}
	dUp, dDown = up-s.Up, down-s.Down
	if dUp < 0 { // counter restarted
		dUp = up
	}
	if dDown < 0 {
		dDown = down
	}
	s.Up, s.Down, s.LastSeen = up, down, nowMs()
	return dUp, dDown, s
}

// protoFamily maps a session protocol to its family: "openvpn-udp" and "openvpn-tcp" are both "openvpn".
func protoFamily(p string) string {
	if i := strings.IndexByte(p, '-'); i > 0 {
		return p[:i]
	}
	return p
}
