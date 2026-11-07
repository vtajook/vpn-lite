package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// OvpnManager runs one openvpn daemon per (inbound, transport) and authenticates every
// login through the daemon's management socket (management-client-auth).
//
// Why not auth-user-pass-verify / client-connect scripts: OpenVPN executes them
// synchronously in its single event loop, so each login (an exec of a large binary
// plus a database round-trip) freezes ALL tunnels of that daemon for its duration.
// Over the management socket the daemon keeps forwarding packets while the panel
// answers, and the answer is an in-memory lookup.
//
// The daemons are started with --daemon and are independent of the panel: restarting
// the panel re-adopts them and rebuilds the session table from "status 3".
type OvpnManager struct {
	st     *Store
	dir    string // /etc/vpn-lite/ovpn
	run    string // /run/vpn-lite
	logDir string
	bin    string
	mu     sync.Mutex
	inst   map[string]*ovpnInst
}

func NewOvpnManager(st *Store, dir, run, logDir string) *OvpnManager {
	bin, _ := exec.LookPath("openvpn")
	if bin == "" {
		bin = "openvpn"
	}
	os.MkdirAll(dir, 0o700)
	os.MkdirAll(run, 0o700)
	os.MkdirAll(logDir, 0o750)
	return &OvpnManager{st: st, dir: dir, run: run, logDir: logDir, bin: bin, inst: map[string]*ovpnInst{}}
}

type ovpnInst struct {
	m        *OvpnManager
	id       int
	proto    string
	key      string
	sock     string
	pidFile  string
	confHash string
	stop     chan struct{}
	wmu      sync.Mutex
	conn     net.Conn
}

func transports(in *Inbound) []string {
	var t []string
	if boolSetting(in.Settings, "udpEnable", true) {
		t = append(t, "udp")
	}
	if boolSetting(in.Settings, "tcpEnable", true) {
		t = append(t, "tcp")
	}
	return t
}

// Reconcile makes the running daemons match the store. Cheap and idempotent: it only
// restarts a daemon whose generated config actually changed.
func (m *OvpnManager) Reconcile() {
	collect := func() (map[string]*Inbound, []int) {
		m.st.mu.RLock()
		defer m.st.mu.RUnlock()
		want := map[string]*Inbound{}
		var need []int
		for _, in := range m.st.st.Inbounds {
			if in.Protocol == "openvpn" && in.Enable {
				c := *in
				c.Settings = cloneSettings(in.Settings)
				want[fmt.Sprint(in.ID)] = &c
				if strSetting(in.Settings, "serverCert", "") == "" || strSetting(in.Settings, "caCert", "") == "" {
					need = append(need, in.ID)
				}
			}
		}
		return want, need
	}
	want, need := collect()
	for _, id := range need { // a new inbound has no certificates yet: make them, nobody should have to click for it
		m.st.ensureOvpnCerts(id)
	}
	if len(need) > 0 {
		want, _ = collect()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	live := map[string]bool{}
	for _, in := range want {
		if strSetting(in.Settings, "serverCert", "") == "" || strSetting(in.Settings, "caCert", "") == "" {
			Events.Add("error", "openvpn", "", "inbound %d has no certificates; not started", in.ID)
			continue
		}
		for _, proto := range transports(in) {
			key := fmt.Sprintf("%d-%s", in.ID, proto)
			live[key] = true
			conf, files := m.render(in, proto)
			sum := sha256.Sum256([]byte(conf + fmt.Sprint(files)))
			h := hex.EncodeToString(sum[:8])
			if cur := m.inst[key]; cur != nil {
				if cur.confHash == h {
					continue
				}
				cur.shutdown(true)
				delete(m.inst, key)
			}
			i := m.start(in, proto, key, conf, files, h)
			if i != nil {
				m.inst[key] = i
			}
		}
	}
	for key, i := range m.inst {
		if !live[key] {
			i.shutdown(true)
			delete(m.inst, key)
		}
	}
}

func (m *OvpnManager) render(in *Inbound, proto string) (string, map[string]string) {
	d := filepath.Join(m.dir, strconv.Itoa(in.ID))
	files := map[string]string{
		"ca.crt":     strSetting(in.Settings, "caCert", ""),
		"server.crt": strSetting(in.Settings, "serverCert", ""),
		"server.key": strSetting(in.Settings, "serverKey", ""),
	}
	if tc := strSetting(in.Settings, "tlsCrypt", ""); tc != "" {
		files["tc.key"] = tc
	}
	return ovpnServerConfig(in, proto, d, m.run), files
}

func (m *OvpnManager) start(in *Inbound, proto, key, conf string, files map[string]string, hash string) *ovpnInst {
	d := filepath.Join(m.dir, strconv.Itoa(in.ID))
	os.MkdirAll(d, 0o700)
	for name, content := range files {
		os.WriteFile(filepath.Join(d, name), []byte(strings.TrimSpace(content)+"\n"), 0o600)
	}
	confPath := filepath.Join(d, proto+".conf")
	os.WriteFile(confPath, []byte(conf), 0o600)
	i := &ovpnInst{m: m, id: in.ID, proto: proto, key: key, confHash: hash, stop: make(chan struct{}),
		sock:    filepath.Join(m.run, fmt.Sprintf("ovpn-%d-%s.sock", in.ID, proto)),
		pidFile: filepath.Join(m.run, fmt.Sprintf("ovpn-%d-%s.pid", in.ID, proto))}
	go i.supervise(confPath, filepath.Join(m.logDir, fmt.Sprintf("openvpn-%d-%s.log", in.ID, proto)))
	return i
}

func (i *ovpnInst) pid() int {
	b, err := os.ReadFile(i.pidFile)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if p > 0 && syscall.Kill(p, 0) == nil {
		// make sure the pid is really our openvpn (pids get reused)
		if cl, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p)); err == nil && strings.Contains(string(cl), "openvpn") {
			return p
		}
	}
	return 0
}

// supervise keeps the daemon alive and the management connection attached.
func (i *ovpnInst) supervise(confPath, logPath string) {
	backoff := time.Second
	for {
		select {
		case <-i.stop:
			return
		default:
		}
		if i.pid() == 0 {
			os.Remove(i.sock)
			cmd := exec.Command(i.m.bin, "--config", confPath, "--daemon", "--writepid", i.pidFile,
				"--log-append", logPath, "--txqueuelen", "1000")
			if out, err := cmd.CombinedOutput(); err != nil {
				Events.Add("error", "openvpn", "", "start %s failed: %v %s", i.key, err, strings.TrimSpace(string(out)))
				if !i.sleep(backoff) {
					return
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			Events.Add("daemon", "openvpn", "", "started %s", i.key)
		}
		backoff = time.Second
		i.attach()
		// attach returns when the management connection drops; loop checks the pid again
		if !i.sleep(time.Second) {
			return
		}
	}
}

func (i *ovpnInst) sleep(d time.Duration) bool {
	select {
	case <-i.stop:
		return false
	case <-time.After(d):
		return true
	}
}

func (i *ovpnInst) shutdown(killDaemon bool) {
	close(i.stop)
	i.wmu.Lock()
	if i.conn != nil {
		i.conn.Close()
	}
	i.wmu.Unlock()
	if killDaemon {
		if p := i.pid(); p > 0 {
			syscall.Kill(p, syscall.SIGTERM)
		}
		Sessions.mu.Lock()
		prefix := fmt.Sprintf("ovpn-%s-", i.key)
		for id := range Sessions.byID {
			if strings.HasPrefix(id, prefix) {
				delete(Sessions.byID, id)
			}
		}
		Sessions.mu.Unlock()
	}
}

func (i *ovpnInst) attach() {
	var conn net.Conn
	var err error
	for n := 0; n < 50; n++ {
		conn, err = net.Dial("unix", i.sock)
		if err == nil {
			break
		}
		if !i.sleep(200 * time.Millisecond) {
			return
		}
	}
	if err != nil {
		return
	}
	i.wmu.Lock()
	i.conn = conn
	i.wmu.Unlock()
	defer func() { conn.Close() }()
	i.send("bytecount 10")
	i.send("status 3")
	i.readLoop(conn)
}

// send writes one management command. A daemon that stops reading must not freeze the panel:
// after 5 s the write fails, the connection is dropped and re-attached.
func (i *ovpnInst) send(format string, a ...any) {
	i.wmu.Lock()
	defer i.wmu.Unlock()
	if i.conn == nil {
		return
	}
	i.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(i.conn, format+"\n", a...); err != nil {
		i.conn.Close()
	}
}

func (i *ovpnInst) sid(cid string) string { return fmt.Sprintf("ovpn-%s-%s", i.key, cid) }

func (i *ovpnInst) readLoop(conn net.Conn) {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var evt, cid, kid string
	env := map[string]string{}
	var listed map[string]bool
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		switch {
		case strings.HasPrefix(line, ">CLIENT:ENV,"):
			kv := line[len(">CLIENT:ENV,"):]
			if kv == "END" {
				i.dispatch(evt, cid, kid, env)
				evt = ""
				env = map[string]string{}
			} else if p := strings.IndexByte(kv, '='); p > 0 {
				env[kv[:p]] = kv[p+1:]
			}
		case strings.HasPrefix(line, ">CLIENT:"):
			parts := strings.Split(line[len(">CLIENT:"):], ",")
			evt, cid, kid = parts[0], "", ""
			if len(parts) > 1 {
				cid = parts[1]
			}
			if len(parts) > 2 {
				kid = parts[2]
			}
			if evt == "ADDRESS" { // no ENV block follows
				evt = ""
			}
		case strings.HasPrefix(line, ">BYTECOUNT_CLI:"):
			p := strings.Split(line[len(">BYTECOUNT_CLI:"):], ",")
			if len(p) == 3 {
				up, _ := strconv.ParseInt(p[1], 10, 64)
				down, _ := strconv.ParseInt(p[2], 10, 64)
				i.account(i.sid(p[0]), up, down)
			}
		case strings.HasPrefix(line, "CLIENT_LIST\t"):
			if listed == nil {
				listed = map[string]bool{}
			}
			i.adopt(strings.Split(line, "\t"), listed)
		case line == "END" && listed != nil:
			i.reconcileSessions(listed)
			listed = nil
		}
	}
}

func (i *ovpnInst) account(sid string, up, down int64) {
	dUp, dDown, s := Sessions.Touch(sid, up, down)
	if s != nil {
		i.m.st.addInboundBytes(s.InboundID, dUp, dDown)
	}
	if s != nil && i.m.st.AddTraffic(s.Email, dUp, dDown) {
		Sessions.KickEmailWhy(s.Email, "quota exhausted")
	}
}

func (i *ovpnInst) dispatch(evt, cid, kid string, env map[string]string) {
	switch evt {
	case "CONNECT", "REAUTH":
		user, pass := env["username"], env["password"]
		verify := func(stored string) bool { return stored == pass }
		sid := i.sid(cid)
		ok, reason := false, ""
		if evt == "REAUTH" {
			res, _ := i.m.st.checkAccount(i.id, user, verify)
			ok, reason = res.Reason == "", res.Reason
		} else {
			sess := &Session{ID: sid, InboundID: i.id, Proto: "openvpn-" + i.proto, SrcIP: env["untrusted_ip"], User: user}
			sess.Kill = func() { i.send("client-kill %s", cid) }
			res := i.m.st.AuthorizeFn(i.id, user, verify, sess)
			ok, reason = res.OK, res.Reason
		}
		if ok {
			i.send("client-auth-nt %s %s", cid, kid)
			return
		}
		Events.Add("reject", "openvpn", user, "%s src=%s", reason, env["untrusted_ip"])
		i.send(`client-deny %s %s "%s" "%s"`, cid, kid, strings.ReplaceAll(reason, `"`, ""), "AUTH_FAILED")
	case "ESTABLISHED":
		if s := Sessions.Get(i.sid(cid)); s != nil {
			Sessions.mu.Lock()
			s.VIP = env["ifconfig_pool_remote_ip"]
			s.Dev = fmt.Sprintf("vl%d%s", i.id, i.proto[:1])
			Sessions.mu.Unlock()
			Events.Add("connect", "openvpn-"+i.proto, s.Email, "ip=%s src=%s cipher=%s", s.VIP, s.SrcIP, env["IV_CIPHERS"])
			Shaper.Apply(s)
		}
	case "DISCONNECT":
		sid := i.sid(cid)
		up, _ := strconv.ParseInt(env["bytes_received"], 10, 64)
		down, _ := strconv.ParseInt(env["bytes_sent"], 10, 64)
		i.account(sid, up, down)
		if s := Sessions.Remove(sid); s != nil {
			Shaper.Remove(s)
			Events.Add("disconnect", "openvpn-"+i.proto, s.Email, "duration=%ss up=%d down=%d", env["time_duration"], up, down)
		}
	}
}

// adopt registers a session found by "status 3" (panel restarted while users stayed up).
// CLIENT_LIST columns: name, real addr, virtual addr, virtual v6, bytes rx, bytes tx,
// connected since, since time_t, username, client id, peer id, cipher.
func (i *ovpnInst) adopt(f []string, listed map[string]bool) {
	if len(f) < 11 {
		return
	}
	cid, user := f[10], f[9]
	sid := i.sid(cid)
	listed[sid] = true
	if Sessions.Get(sid) != nil {
		return
	}
	i.m.st.mu.RLock()
	var email string
	for _, a := range i.m.st.st.Accounts {
		if strings.EqualFold(a.Username, user) {
			email = a.Email
			break
		}
	}
	i.m.st.mu.RUnlock()
	if email == "" {
		i.send("client-kill %s", cid)
		return
	}
	up, _ := strconv.ParseInt(f[5], 10, 64)
	down, _ := strconv.ParseInt(f[6], 10, 64)
	since, _ := strconv.ParseInt(f[8], 10, 64)
	src := f[2]
	if h, _, err := net.SplitHostPort(src); err == nil {
		src = h
	}
	s := &Session{ID: sid, Email: email, User: user, InboundID: i.id, Proto: "openvpn-" + i.proto, SrcIP: src,
		VIP: f[3], Dev: fmt.Sprintf("vl%d%s", i.id, i.proto[:1]), Start: since * 1000, LastSeen: nowMs(), LastActive: nowMs(), Up: up, Down: down}
	s.Kill = func() { i.send("client-kill %s", cid) }
	Sessions.Add(s)
}

func (i *ovpnInst) reconcileSessions(listed map[string]bool) {
	prefix := fmt.Sprintf("ovpn-%s-", i.key)
	Sessions.mu.Lock()
	defer Sessions.mu.Unlock()
	for id := range Sessions.byID {
		if strings.HasPrefix(id, prefix) && !listed[id] {
			delete(Sessions.byID, id)
		}
	}
}
