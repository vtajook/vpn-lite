package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// procDaemon supervises a daemonizing service (xl2tpd, ocserv). The daemon forks away
// from the panel and writes a pid file; the supervisor only starts it when no live
// process owns that pid file, so a panel restart never touches running tunnels.
type procDaemon struct {
	name    string
	bin     string
	args    []string
	pidFile string
	// hashFile records the config fingerprint the running daemon was started with (default
	// pidFile+".hash"); a new name starts a new fingerprint scheme without restarting anything.
	hashFile string
	match    string // substring of /proc/<pid>/cmdline identifying our process
	hash     string // fingerprint of config; a change restarts the daemon
	// adoptUnknown: a daemon started before hashes were recorded is adopted as it is instead of restarted.
	adoptUnknown bool
	stop         chan struct{}
	// reloadHash fingerprints the parts of the config the daemon re-reads on SIGHUP without
	// dropping anyone (ocserv: timers such as dpd). A change of only these parts reloads the
	// daemon instead of restarting it. Empty: the daemon has no such parts.
	mu         sync.Mutex
	reloadHash string
}

func (d *procDaemon) reloadPath() string { return d.pidFile + ".rhash" }

// syncReload makes the running daemon (pid p) re-read its config when the reloadable parts
// changed since it last read them. Nothing is disconnected by a reload.
func (d *procDaemon) syncReload(p int) {
	d.mu.Lock()
	want := d.reloadHash
	d.mu.Unlock()
	if want == "" || p <= 0 {
		return
	}
	if old, err := os.ReadFile(d.reloadPath()); err == nil && strings.TrimSpace(string(old)) == want {
		return
	}
	if err := syscall.Kill(p, syscall.SIGHUP); err != nil {
		return
	}
	os.WriteFile(d.reloadPath(), []byte(want), 0o600)
	Events.Add("daemon", d.name, "", "settings reloaded (nobody disconnected)")
}

func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func (d *procDaemon) pid() int {
	b, err := os.ReadFile(d.pidFile)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if p > 0 && syscall.Kill(p, 0) == nil {
		if cl, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p)); err == nil && strings.Contains(string(cl), d.match) {
			return p
		}
	}
	return 0
}

// reapStale stops a daemon that survived a panel restart but runs with an older config than
// the one wanted now (the in-memory hash check cannot see that, the panel process is new).
func (d *procDaemon) reapStale() {
	p := d.pid()
	if p == 0 {
		return
	}
	hf := d.hashPath()
	old, err := os.ReadFile(hf)
	if err != nil && d.adoptUnknown {
		os.WriteFile(hf, []byte(d.hash), 0o600)
		d.syncReload(p)
		return
	}
	if err == nil && strings.TrimSpace(string(old)) == d.hash {
		d.syncReload(p)
		return
	}
	Events.Add("daemon", d.name, "", "config changed: restarting")
	syscall.Kill(p, syscall.SIGTERM)
	for i := 0; i < 50 && d.pid() != 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if p := d.pid(); p > 0 {
		syscall.Kill(p, syscall.SIGKILL)
		time.Sleep(200 * time.Millisecond)
	}
	os.Remove(d.pidFile)
}

func (d *procDaemon) hashPath() string {
	if d.hashFile != "" {
		return d.hashFile
	}
	return d.pidFile + ".hash"
}

func (d *procDaemon) run() {
	backoff := time.Second
	d.reapStale()
	for {
		select {
		case <-d.stop:
			return
		default:
		}
		if d.pid() == 0 {
			os.Remove(d.pidFile)
			if out, err := exec.Command(d.bin, d.args...).CombinedOutput(); err != nil {
				Events.Add("error", d.name, "", "start failed: %v %s", err, strings.TrimSpace(string(out)))
				select {
				case <-d.stop:
					return
				case <-time.After(backoff):
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			Events.Add("daemon", d.name, "", "started")
			time.Sleep(500 * time.Millisecond)
			os.WriteFile(d.hashPath(), []byte(d.hash), 0o600)
			d.mu.Lock()
			if d.reloadHash != "" { // a fresh daemon read the whole current config
				os.WriteFile(d.reloadPath(), []byte(d.reloadHash), 0o600)
			}
			d.mu.Unlock()
		}
		backoff = time.Second
		select {
		case <-d.stop:
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (d *procDaemon) terminate() {
	close(d.stop)
	if p := d.pid(); p > 0 {
		syscall.Kill(p, syscall.SIGTERM)
	}
}

// daemonSet reconciles a keyed collection of procDaemons against a desired set.
type daemonSet struct {
	mu sync.Mutex
	m  map[string]*procDaemon
}

func newDaemonSet() *daemonSet { return &daemonSet{m: map[string]*procDaemon{}} }

// apply makes the running set match desired. A key in keep is wanted but could not be rendered
// this time (a transient error): its running daemon is left alone instead of being stopped,
// because stopping it would drop every user of that service.
func (s *daemonSet) apply(desired map[string]*procDaemon, keep map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, want := range desired {
		cur := s.m[k]
		if cur != nil && cur.hash == want.hash {
			cur.mu.Lock()
			changed := want.reloadHash != "" && cur.reloadHash != want.reloadHash
			cur.reloadHash = want.reloadHash
			cur.mu.Unlock()
			if changed {
				go cur.syncReload(cur.pid())
			}
			continue
		}
		if cur != nil {
			cur.terminate()
			time.Sleep(300 * time.Millisecond)
		}
		want.stop = make(chan struct{})
		s.m[k] = want
		go want.run()
	}
	for k, cur := range s.m {
		if _, ok := desired[k]; !ok && !keep[k] {
			cur.terminate()
			delete(s.m, k)
		}
	}
}

func writeIfChanged(path string, content string, mode os.FileMode) {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return
	}
	os.WriteFile(path, []byte(content), mode)
}
