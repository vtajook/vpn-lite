package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Engine ties the protocol daemons to the store. Its Reconcile is idempotent and only
// restarts a daemon whose generated config really changed, so day-to-day account
// changes (add / edit / delete) never touch a running tunnel.
type Engine struct {
	st      *Store
	ovpn    *OvpnManager
	rad     *RadiusServer
	l2tp    *daemonSet
	oc      *daemonSet
	conf    string
	run     string
	trigger chan struct{}
	stop    chan struct{}
	once    sync.Once
}

func NewEngine(st *Store, confDir, runDir, logDir string) *Engine {
	e := &Engine{st: st, conf: confDir, run: runDir, l2tp: newDaemonSet(), oc: newDaemonSet(),
		trigger: make(chan struct{}, 1), stop: make(chan struct{})}
	e.ovpn = NewOvpnManager(st, filepath.Join(confDir, "ovpn"), runDir, logDir)
	writeLogrotate(logDir)
	e.rad = &RadiusServer{st: st, secret: st.st.RadiusKey}
	e.rad.kill = func(proto string, s *Session) {
		switch proto {
		case "l2tp":
			killPPP(s)
		case "openconnect":
			killOcserv(runDir, s)
		}
	}
	Shaper.st = st
	return e
}

func (e *Engine) Start() error {
	if err := e.rad.Start("127.0.0.1"); err != nil {
		return err
	}
	go e.reconcileLoop()
	go e.st.EnforceLoop(e.stop)
	go e.housekeeping()
	e.ReloadInbound(0)
	return nil
}

func (e *Engine) Stop() { e.once.Do(func() { close(e.stop) }) }

// ReloadInbound requests a reconcile; bursts of changes collapse into one run.
func (e *Engine) ReloadInbound(int) {
	select {
	case e.trigger <- struct{}{}:
	default:
	}
}

func (e *Engine) Kick(email string) {
	Sessions.KickEmailWhy(email, "account changed by the panel or the bot (deleted, disabled or password changed)")
}

func (e *Engine) Online() map[string]int64 {
	m := map[string]int64{}
	for _, s := range Sessions.Snapshot() {
		if s.LastSeen > m[s.Email] {
			m[s.Email] = s.LastSeen
		}
	}
	return m
}

func (e *Engine) reconcileLoop() {
	for {
		select {
		case <-e.stop:
			return
		case <-e.trigger:
		}
		time.Sleep(400 * time.Millisecond) // let a burst of API calls settle
		e.Reconcile()
	}
}

func (e *Engine) pools() []netip.Prefix {
	e.st.mu.RLock()
	defer e.st.mu.RUnlock()
	var out []netip.Prefix
	for _, in := range e.st.st.Inbounds {
		if !in.Enable {
			continue
		}
		switch in.Protocol {
		case "openvpn":
			for _, t := range transports(in) {
				out = append(out, ovpnPool(in, t))
			}
		case "l2tp":
			out = append(out, l2tpPool(in))
		case "openconnect":
			out = append(out, ocPool(in))
		}
	}
	return out
}

func (e *Engine) Reconcile() {
	e.ovpn.Reconcile()
	secret := e.st.st.RadiusKey
	e.l2tp.apply(e.l2tpDaemons(e.conf, e.run, secret))
	e.oc.apply(e.ocservDaemons(e.conf, e.run, secret))
	e.reconcileIPsec()
	if err := applyNft(e.pools()); err != nil {
		Events.Add("error", "nft", "", "%v", err)
	}
}

// writeLogrotate keeps the OpenVPN logs (written by the daemons themselves) from growing without
// limit. copytruncate: the daemons keep their file open and are never restarted for it.
func writeLogrotate(logDir string) {
	if _, err := os.Stat("/etc/logrotate.d"); err != nil {
		return
	}
	writeIfChanged("/etc/logrotate.d/vpn-lite", logDir+`/openvpn-*.log {
	daily
	rotate 5
	maxsize 50M
	missingok
	notifempty
	compress
	delaycompress
	copytruncate
}
`, 0o644)
}

// housekeeping: stale-session sweep and periodic traffic resets.
func (e *Engine) housekeeping() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
		}
		for _, s := range Sessions.SweepStale(6 * time.Minute) {
			Shaper.Remove(s)
			Events.Add("expire", s.Proto, s.Email, "no update for 6 minutes; session dropped")
		}
		now := nowMs()
		e.st.mu.Lock()
		for _, a := range e.st.st.Accounts {
			if a.Reset > 0 {
				if a.LastReset == 0 {
					a.LastReset = a.CreatedAt
				}
				if now-a.LastReset >= int64(a.Reset)*86400000 {
					a.Up, a.Down, a.LastReset = 0, 0, now
					e.st.touch()
				}
			}
		}
		e.st.mu.Unlock()
	}
}
