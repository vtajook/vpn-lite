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
	match   string // substring of /proc/<pid>/cmdline identifying our process
	hash    string // fingerprint of config; a change restarts the daemon
	stop    chan struct{}
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

func (d *procDaemon) run() {
	backoff := time.Second
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

func (s *daemonSet) apply(desired map[string]*procDaemon) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, want := range desired {
		cur := s.m[k]
		if cur != nil && cur.hash == want.hash {
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
		if _, ok := desired[k]; !ok {
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
