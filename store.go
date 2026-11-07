package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Inbound is one VPN service (an OpenVPN / L2TP / OpenConnect listener).
// Server-side settings live in Settings (a free-form map) WITHOUT the client list;
// clients are Accounts and are projected into settings.clients on the way out.
type Inbound struct {
	ID         int            `json:"id"`
	Remark     string         `json:"remark"`
	Enable     bool           `json:"enable"`
	Listen     string         `json:"listen"`
	Port       int            `json:"port"`
	Protocol   string         `json:"protocol"`
	Settings   map[string]any `json:"settings"`
	Total      int64          `json:"total"`
	ExpiryTime int64          `json:"expiryTime"`
	SortOrder  int            `json:"sortOrder"`
	// Lifetime traffic carried by this service (client->server, server->client).
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Account is one sellable identity. It may be a member of several inbounds.
type Account struct {
	Email      string `json:"email"`
	Username   string `json:"username"` // VPN login name (client "id" in the old API)
	Password   string `json:"password"` // identity for the credential protocols
	SubID      string `json:"subId"`
	Enable     bool   `json:"enable"`
	TotalGB    int64  `json:"totalGB"` // bytes, despite the name
	ExpiryTime int64  `json:"expiryTime"`
	LimitIP    int    `json:"limitIp"`
	TgID       int64  `json:"tgId"`
	Comment    string `json:"comment"`
	Reset      int    `json:"reset"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
	AllTime    int64  `json:"allTime"`
	LastOnline int64  `json:"lastOnline"`
	SpeedDown  int    `json:"speedDown"` // KB/s, 0 = unlimited (server -> client)
	SpeedUp    int    `json:"speedUp"`   // KB/s, 0 = unlimited (client -> server)
	// SingleProto: although the account is served on several protocols, only ONE protocol
	// may have live sessions at a time (OpenVPN udp+tcp count as one protocol).
	SingleProto bool  `json:"singleProto"`
	LastReset   int64 `json:"lastReset"` // unix ms of the last periodic traffic reset
	Inbounds    []int `json:"inbounds"`
	CreatedAt   int64 `json:"createdAt"`
}

type Admin struct {
	User string `json:"user"`
	Hash string `json:"hash"` // salted sha256 hex "salt$hash"
}

type State struct {
	Version     int                 `json:"version"`
	NextInbound int                 `json:"nextInbound"`
	Inbounds    map[int]*Inbound    `json:"inbounds"`
	Accounts    map[string]*Account `json:"accounts"` // key = lower(email)
	Admin       Admin               `json:"admin"`
	Secret      string              `json:"secret"`       // cookie signing key
	RadiusKey   string              `json:"radiusSecret"` // shared secret for RADIUS clients
	Global      GlobalSettings      `json:"global"`
}

type GlobalSettings struct {
	BasePath       string `json:"basePath"`       // "/" or "/abc/"
	Port           int    `json:"port"`           // panel listen port
	Bind           string `json:"bind"`           // panel listen address (empty = all)
	SessionMinutes int    `json:"sessionMinutes"` // cookie lifetime
	// Policy for an account's device cap (Account.LimitIP, or inbound userLimit).
	// "reject": a new login is refused while the cap is full.
	// "evict": the OLDEST session is dropped, but never one younger than EvictGraceSec;
	// a newer-than-grace oldest session turns the login into a reject (no ping-pong).
	LimitStrategy string `json:"limitStrategy"`
	EvictGraceSec int    `json:"evictGraceSec"`
	// DefaultSingleProto applies to accounts created through the API without an explicit value (the bot).
	DefaultSingleProto bool `json:"defaultSingleProto"`
	// AllowMultiProto lets one account be connected on several protocols at the same time.
	// Off (the default): while an account is connected on one protocol, a login on another is refused.
	AllowMultiProto bool `json:"allowMultiProto"`
	// DefaultLimit is the number of simultaneous connections (all protocols together) of an
	// account whose own limit is 0.
	DefaultLimit int    `json:"defaultLimit"`
	TLSCert      string `json:"tlsCert"` // panel HTTPS certificate path (empty = HTTP or self-signed)
	TLSKey       string `json:"tlsKey"`
	// Scheduled backup to a Telegram bot.
	TgToken       string `json:"tgToken"`
	TgChat        string `json:"tgChat"`
	TgBackupHours int    `json:"tgBackupHours"` // 0 = off
	TgNoLogin     bool   `json:"tgNoLogin"`     // true = do not message panel logins
	TgCpuAlert    int    `json:"tgCpuAlert"`    // message when CPU stays above this percent (0 = off)
	TgCpuTouched  bool   `json:"tgCpuTouched"`  // set once the admin saved the field (so 0 really means off)
	// TotalUsed is the lifetime traffic of the whole server. It only ever grows: deleting an
	// account or resetting its volume never lowers it.
	TotalUsed int64 `json:"totalUsed"`
	TotalUp   int64 `json:"totalUp"`   // lifetime bytes received from clients, all services
	TotalDown int64 `json:"totalDown"` // lifetime bytes sent to clients
	TotalInit bool  `json:"totalInit"` // the counter was seeded once; a manual reset must not be undone at restart
}

type Store struct {
	mu    sync.RWMutex
	path  string
	st    State
	dirty bool
	stop  chan struct{}
	done  chan struct{}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, stop: make(chan struct{}), done: make(chan struct{})}
	s.st = State{Version: 1, NextInbound: 1, Inbounds: map[int]*Inbound{}, Accounts: map[string]*Account{}}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &s.st); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if s.st.Inbounds == nil {
		s.st.Inbounds = map[int]*Inbound{}
	}
	if s.st.Accounts == nil {
		s.st.Accounts = map[string]*Account{}
	}
	if s.st.NextInbound < 1 {
		s.st.NextInbound = 1
	}
	if s.st.Secret == "" {
		s.st.Secret = randHex(32)
		s.dirty = true
	}
	if s.st.RadiusKey == "" {
		s.st.RadiusKey = randHex(12)
		s.dirty = true
	}
	if !s.st.Global.TotalInit {
		s.rebaseTotalLocked()
		s.st.Global.TotalInit = true
		s.dirty = true
	}
	g := &s.st.Global
	if g.BasePath == "" {
		g.BasePath = "/"
		s.dirty = true
	}
	if g.TgCpuAlert == 0 && !g.TgCpuTouched {
		g.TgCpuAlert = 80
		s.dirty = true
	}
	if g.SessionMinutes == 0 {
		g.SessionMinutes = 1440
	}
	if g.DefaultLimit < 1 {
		g.DefaultLimit = 1
	}
	if g.LimitStrategy == "" {
		g.LimitStrategy = "reject"
	}
	if g.EvictGraceSec == 0 {
		g.EvictGraceSec = 30
	}
	go s.flusher()
	return s, nil
}

func (s *Store) flusher() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	defer close(s.done)
	for {
		select {
		case <-t.C:
			s.Flush()
		case <-s.stop:
			s.Flush()
			return
		}
	}
}

func (s *Store) Close() { close(s.stop); <-s.done }

// Touch marks the state dirty; callers hold s.mu.
func (s *Store) touch() { s.dirty = true }

func (s *Store) Flush() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(&s.st)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	f.Sync()
	f.Close()
	// keep one previous generation
	if _, err := os.Stat(s.path); err == nil {
		os.Rename(s.path, s.path+".bak")
	}
	return os.Rename(tmp, s.path)
}

func ekey(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func (s *Store) sortedInbounds() []*Inbound {
	out := make([]*Inbound, 0, len(s.st.Inbounds))
	for _, in := range s.st.Inbounds {
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SortOrder != out[j].SortOrder {
			return out[i].SortOrder < out[j].SortOrder
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func hasInt(a []int, v int) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}
func delInt(a []int, v int) []int {
	out := a[:0:0]
	for _, x := range a {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// rebaseTotalLocked makes sure the lifetime counters are never below what the services (or,
// for an old state without per-service counters, the accounts) already carried.
func (s *Store) rebaseTotalLocked() {
	var sum, up, down int64
	for _, in := range s.st.Inbounds {
		up += in.Up
		down += in.Down
	}
	sum = up + down
	if sum == 0 {
		for _, a := range s.st.Accounts {
			sum += a.AllTime
		}
	}
	g := &s.st.Global
	if sum > g.TotalUsed {
		g.TotalUsed = sum
		s.dirty = true
	}
	if up > g.TotalUp {
		g.TotalUp = up
		s.dirty = true
	}
	if down > g.TotalDown {
		g.TotalDown = down
		s.dirty = true
	}
}

// addInboundBytes books traffic on the service that carried it and on the lifetime totals.
func (s *Store) addInboundBytes(inbound int, up, down int64) {
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	s.mu.Lock()
	if in := s.st.Inbounds[inbound]; in != nil {
		in.Up += up
		in.Down += down
	}
	s.st.Global.TotalUp += up
	s.st.Global.TotalDown += down
	s.st.Global.TotalUsed += up + down
	s.touch()
	s.mu.Unlock()
}
