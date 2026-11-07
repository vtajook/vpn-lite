package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Per-account speed limits, enforced with tc on the session's own device:
//   - PPP (L2TP) and ocserv sessions each own a device (pppN / vpnsN): a plain TBF on
//     egress (download) and an ingress policer (upload) are enough.
//   - OpenVPN sessions share one tun per transport: an HTB class + u32 filter per
//     tunnel address, created on connect and deleted on disconnect.
// All tc calls run on one background worker, so the auth/accounting paths never fork.

type shaper struct {
	mu    sync.Mutex
	q     chan func()
	st    *Store
	run   func(args ...string) error  // replaceable in tests
	show  func(args ...string) string // tc output (replaceable in tests)
	route func(ip string) string      // device for a tunnel address
	htb   map[string]bool             // shared devices that already have the HTB root
}

var Shaper = newShaper()

func newShaper() *shaper {
	s := &shaper{q: make(chan func(), 4096), htb: map[string]bool{}}
	s.run = func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "tc", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("tc %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	s.show = func(args ...string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, _ := exec.CommandContext(ctx, "tc", args...).Output()
		return string(out)
	}
	s.route = func(ip string) string {
		out, err := exec.Command("ip", "-4", "-o", "route", "get", ip).Output()
		if err != nil {
			return ""
		}
		f := strings.Fields(string(out))
		for i, w := range f {
			if w == "dev" && i+1 < len(f) {
				return f[i+1]
			}
		}
		return ""
	}
	go func() {
		for f := range s.q {
			f()
		}
	}()
	return s
}

func (s *shaper) submit(f func()) {
	select {
	case s.q <- f:
	default: // queue full: drop the shaping update rather than block a caller
	}
}

func isSharedDev(dev string) bool { return strings.HasPrefix(dev, "vl") }

func burstFor(kbps int) int { // bytes
	b := kbps * 1024 / 8
	if b < 16384 {
		b = 16384
	}
	return b
}

func minorOf(vip string) int {
	a, err := netip.ParseAddr(vip)
	if err != nil {
		return 0
	}
	b := a.As4()
	m := int(b[2])<<8 | int(b[3])
	if m == 0 || m == 0xffff {
		return 0
	}
	return m
}

// Apply installs the limits of the session's account (or clears them when both are 0).
func (s *shaper) Apply(sess *Session) {
	if s.st == nil || sess == nil {
		return
	}
	Sessions.mu.Lock()
	vip, dev := sess.VIP, sess.Dev
	Sessions.mu.Unlock()
	if vip == "" {
		return
	}
	s.st.mu.RLock()
	acc := s.st.st.Accounts[ekey(sess.Email)]
	var down, up int
	if acc != nil {
		down, up = acc.SpeedDown, acc.SpeedUp
	}
	s.st.mu.RUnlock()
	s.submit(func() {
		if dev == "" {
			dev = s.route(vip)
			Sessions.mu.Lock()
			sess.Dev = dev
			Sessions.mu.Unlock()
		}
		if dev == "" {
			return
		}
		if isSharedDev(dev) {
			s.applyShared(dev, vip, down, up)
		} else {
			s.applyDedicated(dev, down, up)
		}
	})
}

func (s *shaper) Remove(sess *Session) {
	if sess == nil {
		return
	}
	Sessions.mu.Lock()
	dev, vip := sess.Dev, sess.VIP
	Sessions.mu.Unlock()
	if vip == "" || dev == "" || !isSharedDev(dev) {
		return // dedicated devices disappear with the session
	}
	s.submit(func() { s.clearShared(dev, vip) })
}

// Refresh re-applies limits for every live session of an account (after an edit).
func (s *shaper) Refresh(email string) {
	Sessions.mu.Lock()
	live := Sessions.liveOf(email)
	Sessions.mu.Unlock()
	for _, sess := range live {
		s.Apply(sess)
	}
}

func (s *shaper) applyDedicated(dev string, down, up int) {
	if down > 0 {
		s.run("qdisc", "replace", "dev", dev, "root", "tbf", "rate", fmt.Sprintf("%dkbit", down*8),
			"burst", fmt.Sprint(burstFor(down)), "latency", "100ms")
	} else {
		s.run("qdisc", "del", "dev", dev, "root")
	}
	s.run("qdisc", "del", "dev", dev, "ingress")
	if up > 0 {
		s.run("qdisc", "add", "dev", dev, "handle", "ffff:", "ingress")
		s.run("filter", "replace", "dev", dev, "parent", "ffff:", "protocol", "all", "prio", "1", "u32",
			"match", "u32", "0", "0", "police", "rate", fmt.Sprintf("%dkbit", up*8),
			"burst", fmt.Sprint(burstFor(up)), "drop", "flowid", ":1")
	}
}

func (s *shaper) applyShared(dev, vip string, down, up int) {
	m := minorOf(vip)
	if m == 0 {
		return
	}
	s.clearShared(dev, vip)
	if down > 0 {
		s.mu.Lock()
		have := s.htb[dev]
		s.htb[dev] = true
		s.mu.Unlock()
		// after a panel restart the root may already exist and carry other users' classes:
		// replacing it would silently remove their limits
		if !have && !strings.Contains(s.show("qdisc", "show", "dev", dev, "root"), "htb 1:") {
			s.run("qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", "0")
		}
		cid := fmt.Sprintf("1:%x", m)
		rate := fmt.Sprintf("%dkbit", down*8)
		s.run("class", "replace", "dev", dev, "parent", "1:", "classid", cid, "htb", "rate", rate, "ceil", rate,
			"burst", fmt.Sprint(burstFor(down)))
		s.run("filter", "replace", "dev", dev, "parent", "1:", "protocol", "ip", "prio", fmt.Sprint(m), "u32",
			"match", "ip", "dst", vip+"/32", "flowid", cid)
	}
	if up > 0 {
		s.run("qdisc", "add", "dev", dev, "handle", "ffff:", "ingress") // exists already after the first call
		s.run("filter", "replace", "dev", dev, "parent", "ffff:", "protocol", "ip", "prio", fmt.Sprint(m), "u32",
			"match", "ip", "src", vip+"/32", "police", "rate", fmt.Sprintf("%dkbit", up*8),
			"burst", fmt.Sprint(burstFor(up)), "drop", "flowid", ":1")
	}
}

func (s *shaper) clearShared(dev, vip string) {
	m := minorOf(vip)
	if m == 0 {
		return
	}
	s.run("filter", "del", "dev", dev, "parent", "1:", "prio", fmt.Sprint(m))
	s.run("class", "del", "dev", dev, "classid", fmt.Sprintf("1:%x", m))
	s.run("filter", "del", "dev", dev, "parent", "ffff:", "prio", fmt.Sprint(m))
}
