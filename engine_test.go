package main

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeD struct {
	mu     sync.Mutex
	kicked []string
}

func (f *fakeD) ReloadInbound(int) {}
func (f *fakeD) Kick(e string)     { f.mu.Lock(); f.kicked = append(f.kicked, e); f.mu.Unlock() }
func (f *fakeD) Online() map[string]int64 {
	m := map[string]int64{}
	for _, s := range Sessions.Snapshot() {
		m[s.Email] = s.LastSeen
	}
	return m
}

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "s.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	st.SetAdmin("admin", "pw")
	Sessions.mu.Lock()
	Sessions.byID = map[string]*Session{}
	Sessions.mu.Unlock()
	return st
}

func seed(st *Store) {
	st.st.Inbounds[1] = &Inbound{ID: 1, Remark: "ovpn", Enable: true, Port: 1194, Protocol: "openvpn", Settings: map[string]any{}}
	st.st.Inbounds[2] = &Inbound{ID: 2, Remark: "l2tp", Enable: true, Port: 1701, Protocol: "l2tp", Settings: map[string]any{}}
	st.st.Accounts["alice@x"] = &Account{Email: "alice@x", Username: "alice", Password: "secret", Enable: true, Inbounds: []int{1, 2}}
}

// ---- OpenVPN management protocol against a fake daemon

func TestOvpnManagementAuth(t *testing.T) {
	st := testStore(t)
	seed(st)
	m := &OvpnManager{st: st}
	inst := &ovpnInst{m: m, id: 1, proto: "udp", key: "1-udp"}
	srv, cli := net.Pipe()
	inst.conn = cli
	go inst.readLoop(cli)
	rd := bufio.NewReader(srv)
	read := func() string {
		srv.SetReadDeadline(time.Now().Add(2 * time.Second))
		l, err := rd.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return strings.TrimSpace(l)
	}
	connect := func(cid, user, pass string) {
		go func() {
			srv.Write([]byte(">CLIENT:CONNECT," + cid + ",1\r\n>CLIENT:ENV,untrusted_ip=1.2.3.4\r\n>CLIENT:ENV,username=" + user +
				"\r\n>CLIENT:ENV,password=" + pass + "\r\n>CLIENT:ENV,END\r\n"))
		}()
	}
	connect("0", "alice", "wrong")
	if got := read(); !strings.HasPrefix(got, "client-deny 0 1") {
		t.Fatalf("bad password: %q", got)
	}
	connect("0", "alice", "secret")
	if got := read(); got != "client-auth-nt 0 1" {
		t.Fatalf("good password: %q", got)
	}
	// second device while the first is younger than the grace window: refused, no eviction
	connect("1", "alice", "secret")
	if got := read(); !strings.HasPrefix(got, "client-deny 1 1") {
		t.Fatalf("second device inside grace should be denied: %q", got)
	}
	// age the first session: the next login evicts it
	Sessions.mu.Lock()
	Sessions.byID["ovpn-1-udp-0"].Start -= 120_000
	Sessions.mu.Unlock()
	connect("2", "alice", "secret")
	a, b := read(), read()
	if !(a == "client-kill 0" && b == "client-auth-nt 2 1") && !(b == "client-kill 0" && a == "client-auth-nt 2 1") {
		t.Fatalf("eviction: %q %q", a, b)
	}
	// accounting through BYTECOUNT and DISCONNECT
	go srv.Write([]byte(">BYTECOUNT_CLI:2,1000,5000\r\n"))
	time.Sleep(100 * time.Millisecond)
	st.mu.RLock()
	acc := st.st.Accounts["alice@x"]
	if acc.Up != 1000 || acc.Down != 5000 {
		t.Fatalf("traffic %d/%d", acc.Up, acc.Down)
	}
	st.mu.RUnlock()
	go srv.Write([]byte(">CLIENT:DISCONNECT,2\r\n>CLIENT:ENV,bytes_received=1500\r\n>CLIENT:ENV,bytes_sent=6000\r\n>CLIENT:ENV,END\r\n"))
	time.Sleep(100 * time.Millisecond)
	st.mu.RLock()
	if acc.Up != 1500 || acc.Down != 6000 {
		t.Fatalf("final traffic %d/%d", acc.Up, acc.Down)
	}
	st.mu.RUnlock()
	if Sessions.Get("ovpn-1-udp-2") != nil {
		t.Fatal("session not removed")
	}
	// disabled account is refused
	st.mu.Lock()
	acc.Enable = false
	st.mu.Unlock()
	connect("3", "alice", "secret")
	if got := read(); !strings.Contains(got, "account disabled") {
		t.Fatalf("disabled: %q", got)
	}
}

// ---- RADIUS

func radReq(secret string, attrs []radAttr, code byte) (*radPkt, []byte) {
	p := &radPkt{Code: code, ID: 7, Attrs: attrs}
	for i := range p.Auth {
		p.Auth[i] = byte(i + 1)
	}
	return p, nil
}

func papEnc(pw, secret string, auth [16]byte) []byte {
	padded := make([]byte, (len(pw)+15)/16*16)
	copy(padded, pw)
	out := make([]byte, 0, len(padded))
	prev := auth[:]
	for i := 0; i < len(padded); i += 16 {
		h := md5.Sum(append([]byte(secret), prev...))
		blk := make([]byte, 16)
		for j := range blk {
			blk[j] = padded[i+j] ^ h[j]
		}
		out = append(out, blk...)
		prev = blk
	}
	return out
}

func TestRadiusPAPAndMSCHAP(t *testing.T) {
	st := testStore(t)
	seed(st)
	r := &RadiusServer{st: st, secret: "sh", seen: map[string]int64{}}
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	nas := radAttr{attrNASIdentifier, []byte("vl-l2tp")}

	req, _ := radReq("sh", nil, radAccessRequest)
	req.Attrs = []radAttr{{attrUserName, []byte("alice")}, nas, {attrUserPassword, papEnc("secret", "sh", req.Auth)}}
	resp, err := parseRad(r.handleAuth(from, req))
	if err != nil || resp.Code != radAccessAccept {
		t.Fatalf("PAP good: %v %+v", err, resp)
	}
	req.Attrs[2].V = papEnc("nope", "sh", req.Auth)
	if resp, _ = parseRad(r.handleAuth(from, req)); resp.Code != radAccessReject {
		t.Fatalf("PAP bad accepted")
	}

	// MS-CHAPv2 with the RFC 2759 vectors, account password = "clientPass"
	st.mu.Lock()
	st.st.Accounts["alice@x"].Username, st.st.Accounts["alice@x"].Password = "User", "clientPass"
	st.mu.Unlock()
	authChal := h("5B5D7C7D7B3F2F3E3C2C602132262628")
	peer := h("21402324255E262A28295F2B3A337C7E")
	nt := h("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
	ms := append([]byte{1, 0}, peer...)
	ms = append(ms, make([]byte, 8)...)
	ms = append(ms, nt...)
	req.Attrs = []radAttr{{attrUserName, []byte("User")}, nas, msVSA(11, authChal), msVSA(25, ms)}
	resp, _ = parseRad(r.handleAuth(from, req))
	if resp.Code != radAccessAccept {
		t.Fatalf("MSCHAPv2 rejected")
	}
	succ := resp.msAttr(26)
	if string(succ[1:]) != "S=407A5589115FD0D6209F510FE9C04566932CDA56" {
		t.Fatalf("success string %q", succ)
	}
}

func TestRadiusAccounting(t *testing.T) {
	st := testStore(t)
	seed(st)
	killed := 0
	r := &RadiusServer{st: st, secret: "sh", seen: map[string]int64{}, kill: func(string, *Session) { killed++ }}
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	acct := func(status uint32, in, out uint32, id byte) {
		p, _ := radReq("sh", nil, radAccountingReq)
		p.ID = id
		p.Auth[0] = id
		p.Attrs = []radAttr{{attrUserName, []byte("alice")}, {attrNASIdentifier, []byte("vl-l2tp")},
			{attrAcctSessionID, []byte("S1")}, u32attr(attrAcctStatus, status), u32attr(attrAcctInOctets, in),
			u32attr(attrAcctOutOctets, out), u32attr(attrNASPort, 0), {attrFramedIP, []byte{10, 1, 0, 5}}}
		if resp, _ := parseRad(r.handleAcct(from, p)); resp.Code != radAccountingResp {
			t.Fatal("no accounting response")
		}
	}
	acct(1, 0, 0, 1)
	if len(Sessions.Snapshot()) != 1 {
		t.Fatal("session not created")
	}
	acct(3, 100, 400, 2)
	acct(3, 100, 400, 2) // retransmission must not double count
	acct(2, 150, 900, 3)
	st.mu.RLock()
	a := st.st.Accounts["alice@x"]
	if a.Up != 150 || a.Down != 900 {
		t.Fatalf("counted %d/%d", a.Up, a.Down)
	}
	st.mu.RUnlock()
	if len(Sessions.Snapshot()) != 0 {
		t.Fatal("session not removed on stop")
	}
}

// ---- the bot's API contract

func TestBotAPIContract(t *testing.T) {
	st := testStore(t)
	d := &fakeD{}
	api := &API{st: st, d: d, base: "/"}
	ts := httptest.NewServer(api.Handler())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	get := func(path string) (int, map[string]any) {
		resp, err := c.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		jsonDecode(resp, &m)
		return resp.StatusCode, m
	}
	post := func(path string, form url.Values) map[string]any {
		resp, err := c.Post(ts.URL+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		jsonDecode(resp, &m)
		return m
	}
	if code, _ := get("/panel/api/inbounds/list"); code != 404 {
		t.Fatalf("unauthenticated list = %d, want 404", code)
	}
	if r := post("/login", url.Values{"username": {"admin"}, "password": {"bad"}}); r["success"] != false {
		t.Fatal("bad login accepted")
	}
	if r := post("/login", url.Values{"username": {"admin"}, "password": {"pw"}}); r["success"] != true {
		t.Fatal("login failed")
	}
	// inbound
	r := post("/panel/api/inbounds/add", url.Values{"remark": {"ovpn"}, "enable": {"true"}, "port": {"1194"},
		"protocol": {"openvpn"}, "settings": {`{"clients":[],"udpEnable":true}`}, "streamSettings": {"{}"}, "sniffing": {"{}"}})
	if r["success"] != true {
		t.Fatalf("add inbound: %v", r)
	}
	r = post("/panel/api/inbounds/add", url.Values{"remark": {"l2tp"}, "enable": {"true"}, "port": {"1701"},
		"protocol": {"l2tp"}, "settings": {`{"clients":[],"ipsecEnable":false}`}})
	if r["success"] != true {
		t.Fatalf("add l2tp: %v", r)
	}
	// addClient exactly the way vpnui.php sends it, on two inbounds
	body := url.Values{"id": {"1"}, "settings": {`{"clients":[{"email":"bob1","enable":true,"limitIp":0,"totalGB":1073741824,"expiryTime":0,"tgId":0,"subId":"abc","comment":"","reset":0,"id":"bob1","password":"pw123"}]}`},
		"inboundIds": {"1", "2"}}
	if r := post("/panel/api/inbounds/addClient", body); r["success"] != true {
		t.Fatalf("addClient: %v", r)
	}
	if r := post("/panel/api/inbounds/addClient", body); r["success"] != false {
		t.Fatal("duplicate email accepted")
	}
	_, got := get("/panel/api/inbounds/get/2")
	obj := got["obj"].(map[string]any)
	if !strings.Contains(obj["settings"].(string), `"password":"pw123"`) || len(obj["clientStats"].([]any)) != 1 {
		t.Fatalf("get/2 projection wrong: %v", obj)
	}
	_, tr := get("/panel/api/inbounds/getClientTraffics/bob1")
	if tr["success"] != true || tr["obj"].(map[string]any)["total"].(float64) != 1073741824 {
		t.Fatalf("traffic row: %v", tr)
	}
	// extend: read client from settings, change totalGB, updateClient by identity (password)
	upd := url.Values{"id": {"1"}, "settings": {`{"clients":[{"email":"bob1","enable":true,"limitIp":0,"totalGB":2147483648,"expiryTime":1999999999000,"tgId":0,"subId":"abc","comment":"","reset":0,"id":"bob1","password":"pw123"}]}`},
		"inboundIds": {"1", "2"}}
	if r := post("/panel/api/inbounds/updateClient/pw123", upd); r["success"] != true {
		t.Fatalf("updateClient: %v", r)
	}
	_, tr = get("/panel/api/inbounds/getClientTraffics/bob1")
	if tr["obj"].(map[string]any)["expiryTime"].(float64) != 1999999999000 {
		t.Fatal("update not applied")
	}
	if r := post("/panel/api/inbounds/1/resetClientTraffic/bob1", nil); r["success"] != true {
		t.Fatal("reset")
	}
	if r := post("/panel/api/inbounds/1/delClientByEmail/bob1", nil); r["success"] != true {
		t.Fatal("delByEmail")
	}
	// still a member of inbound 2, so the account lives on; deleting there removes it
	if r := post("/panel/api/inbounds/2/delClient/pw123", nil); r["success"] != true {
		t.Fatalf("delClient: %v", r)
	}
	if _, tr = get("/panel/api/inbounds/getClientTraffics/bob1"); tr["success"] != false {
		t.Fatal("account should be gone")
	}
	// .ovpn must work without any manual certificate step: they are created on demand
	resp, _ := c.Get(ts.URL + "/panel/api/inbounds/1/ovpn/udp")
	bb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(bb), "BEGIN CERTIFICATE") || !strings.Contains(string(bb), "remote ") {
		t.Fatalf("ovpn should be generated with auto certs: %.200s", body)
	}
}

func TestSingleProtocolAtATime(t *testing.T) {
	st := testStore(t)
	seed(st) // alice on openvpn (1) and l2tp (2)
	st.st.Accounts["alice@x"].LimitIP = 2
	pass := func(stored string) bool { return stored == "secret" }
	reset := func() {
		Sessions.mu.Lock()
		Sessions.byID = map[string]*Session{}
		Sessions.mu.Unlock()
	}
	reset()
	killed := make(chan string, 8)
	live := func(id, proto string, ageSec int64) {
		Sessions.Add(&Session{ID: id, Email: "alice@x", Proto: proto, Start: nowMs() - ageSec*1000, LastSeen: nowMs(),
			Kill: func() { killed <- id }})
	}
	// default: no mixing. udp + tcp are one protocol, so two OpenVPN sessions fit under limit 2 ...
	live("a", "openvpn-udp", 600)
	if r := st.AuthorizeFn(1, "alice", pass, &Session{ID: "n1", Proto: "openvpn-tcp"}); !r.OK {
		t.Fatalf("second OpenVPN transport refused: %q", r.Reason)
	}
	// ... but an L2TP login is refused outright, however old the OpenVPN sessions are, and
	// the running connections are not touched
	if r := st.AuthorizeFn(2, "alice", pass, nil); r.OK || !strings.Contains(r.Reason, "another protocol") {
		t.Fatalf("other protocol must be refused: %+v", r)
	}
	select {
	case id := <-killed:
		t.Fatalf("session %s was disconnected by a refused login", id)
	case <-time.After(300 * time.Millisecond):
	}
	// once the OpenVPN sessions are gone the other protocol is welcome
	reset()
	if r := st.AuthorizeFn(2, "alice", pass, nil); !r.OK {
		t.Fatalf("l2tp after disconnect refused: %q", r.Reason)
	}
	// the admin can allow mixing
	reset()
	live("c", "l2tp", 600)
	st.st.Global.AllowMultiProto = true
	if r := st.AuthorizeFn(1, "alice", pass, nil); !r.OK {
		t.Fatalf("mixed protocols allowed by the admin should pass: %q", r.Reason)
	}
	// ... unless that one account is pinned to a single protocol
	st.st.Accounts["alice@x"].SingleProto = true
	if r := st.AuthorizeFn(1, "alice", pass, nil); r.OK {
		t.Fatal("a pinned account must not mix")
	}
}

// Many accounts logging in at the same time on all three protocols: every account ends up on
// exactly one protocol and never above its device limit.
func TestManyUsersConcurrent(t *testing.T) {
	st := testStore(t)
	st.st.Inbounds[1] = &Inbound{ID: 1, Enable: true, Port: 1001, Protocol: "openvpn", Settings: map[string]any{}}
	st.st.Inbounds[2] = &Inbound{ID: 2, Enable: true, Port: 1701, Protocol: "l2tp", Settings: map[string]any{}}
	st.st.Inbounds[3] = &Inbound{ID: 3, Enable: true, Port: 1002, Protocol: "openconnect", Settings: map[string]any{}}
	st.st.Global.LimitStrategy = "reject"
	const N = 300
	for i := 0; i < N; i++ {
		e := fmt.Sprintf("u%d@x", i)
		st.st.Accounts[e] = &Account{Email: e, Username: fmt.Sprintf("u%d", i), Password: "pw", Enable: true, LimitIP: 1, Inbounds: []int{1, 2, 3}}
	}
	Sessions.mu.Lock()
	Sessions.byID = map[string]*Session{}
	Sessions.mu.Unlock()
	pass := func(stored string) bool { return stored == "pw" }
	var wg sync.WaitGroup
	var okCount [N]int32
	for i := 0; i < N; i++ {
		for in := 1; in <= 3; in++ {
			for dev := 0; dev < 2; dev++ { // two devices per protocol
				wg.Add(1)
				go func(i, in, dev int) {
					defer wg.Done()
					sid := fmt.Sprintf("s-%d-%d-%d", i, in, dev)
					r := st.AuthorizeFn(in, fmt.Sprintf("u%d", i), pass, &Session{ID: sid, Proto: map[int]string{1: "openvpn-udp", 2: "l2tp", 3: "openconnect"}[in]})
					if r.OK {
						atomic.AddInt32(&okCount[i], 1)
					}
				}(i, in, dev)
			}
		}
	}
	wg.Wait()
	for i := 0; i < N; i++ {
		if okCount[i] != 1 {
			t.Fatalf("account u%d got %d simultaneous sessions, want exactly 1", i, okCount[i])
		}
	}
}

// Adding, editing and removing other accounts must never disconnect anybody who is connected.
func TestAccountChangesNeverDisconnect(t *testing.T) {
	st := testStore(t)
	seed(st)
	Sessions.mu.Lock()
	Sessions.byID = map[string]*Session{}
	Sessions.mu.Unlock()
	var kicks int32
	for i := 0; i < 100; i++ {
		e := fmt.Sprintf("c%d@x", i)
		st.st.Accounts[e] = &Account{Email: e, Username: fmt.Sprintf("c%d", i), Password: "pw", Enable: true, Inbounds: []int{1},
			ExpiryTime: nowMs() + 86400000, TotalGB: 1 << 40}
		Sessions.Add(&Session{ID: "k" + e, Email: e, Proto: "openvpn-udp", InboundID: 1, Start: nowMs(), LastSeen: nowMs(),
			Kill: func() { atomic.AddInt32(&kicks, 1) }})
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // the admin / the bot keeps creating, editing and deleting OTHER accounts
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			e := fmt.Sprintf("x%d@x", i)
			st.mu.Lock()
			st.st.Accounts[e] = &Account{Email: e, Username: fmt.Sprintf("x%d", i), Password: "pw", Enable: true, Inbounds: []int{1}}
			st.st.Accounts[e].TotalGB = 5
			delete(st.st.Accounts, e)
			st.touch()
			st.mu.Unlock()
		}
	}()
	for i := 0; i < 200; i++ {
		st.enforceOnce()
		st.AddTraffic("c1@x", 10, 10)
	}
	close(stop)
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	if n := atomic.LoadInt32(&kicks); n != 0 {
		t.Fatalf("%d healthy sessions were disconnected", n)
	}
	// and the ones that really must go are still kicked
	st.mu.Lock()
	st.st.Accounts["c2@x"].Enable = false
	st.mu.Unlock()
	st.enforceOnce()
	time.Sleep(100 * time.Millisecond)
	if n := atomic.LoadInt32(&kicks); n != 1 {
		t.Fatalf("disabled account: %d kicks, want 1", n)
	}
}

func TestPortClash(t *testing.T) {
	st := testStore(t)
	st.st.Inbounds[1] = &Inbound{ID: 1, Enable: true, Port: 443, Protocol: "openvpn", Remark: "ovpn", Settings: map[string]any{"udpEnable": false}}
	// OpenVPN TCP on 443 blocks Cisco on 443 (tcp), but OpenVPN UDP alone would not
	if msg := st.portClashLocked(&Inbound{ID: 2, Enable: true, Port: 443, Protocol: "openconnect", Settings: map[string]any{}}); msg == "" {
		t.Fatal("tcp/443 clash not detected")
	}
	if msg := st.portClashLocked(&Inbound{ID: 2, Enable: true, Port: 8443, Protocol: "openconnect", Settings: map[string]any{}}); msg != "" {
		t.Fatalf("false clash: %s", msg)
	}
	// separate TCP port for OpenVPN
	in := &Inbound{ID: 3, Enable: true, Port: 1194, Protocol: "openvpn", Settings: map[string]any{"separatePorts": true, "tcpPort": float64(8443)}}
	if got := portsOf(in); len(got) != 2 || got[1] != "tcp/8443" {
		t.Fatalf("ports %v", got)
	}
}

func TestOvpnProfileBothWithCreds(t *testing.T) {
	in := &Inbound{ID: 3, Port: 1001, Listen: "", Settings: map[string]any{
		"caCert": "CA", "connDomain": "vpn.example.com", "udpEnable": true, "tcpEnable": true,
		"separatePorts": true, "tcpPort": float64(1003)}}
	cfg, err := ovpnClientConfig(in, "both", "panel:2096", "bob", "pw12345678")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"remote vpn.example.com 1001 udp", "remote vpn.example.com 1003 tcp",
		"<auth-user-pass>\nbob\npw12345678\n</auth-user-pass>"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("profile lacks %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "explicit-exit-notify") {
		t.Error("explicit-exit-notify must not be used with mixed transports")
	}
	if strings.Index(cfg, "udp") > strings.Index(cfg, "1003 tcp") {
		t.Error("UDP remote must come first")
	}
}

func TestBackupRestoreAndImport(t *testing.T) {
	st := testStore(t)
	api := &API{st: st, d: &fakeD{}, base: "/"}
	ts := httptest.NewServer(api.Handler())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	do := func(method, path, ctype, body string) map[string]any {
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", ctype)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		jsonDecode(resp, &m)
		return m
	}
	form := "application/x-www-form-urlencoded"
	do("POST", "/login", form, url.Values{"username": {"admin"}, "password": {"pw"}}.Encode())
	do("POST", "/panel/api/inbounds/add", form, url.Values{"remark": {"o"}, "enable": {"true"}, "port": {"1194"},
		"protocol": {"openvpn"}, "settings": {`{"clients":[]}`}}.Encode())
	r := do("POST", "/panel/api/inbounds/addClient", form, url.Values{"id": {"1"},
		"settings": {`{"clients":[{"id":"u1","email":"a@x","password":"pass1234","enable":true}]}`}}.Encode())
	if r["success"] != true {
		t.Fatalf("addClient: %v", r)
	}
	st.mu.Lock()
	a0 := st.st.Accounts["a@x"]
	a0.TotalGB, a0.ExpiryTime, a0.Up, a0.Down, a0.AllTime, a0.Enable, a0.LimitIP, a0.SpeedDown = 5<<30, 1893456000000, 111, 222, 333, false, 3, 500
	st.st.Inbounds[1].Enable = false
	st.touch()
	st.mu.Unlock()
	// backup
	resp, err := c.Get(ts.URL + "/panel/ui/backup")
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	io.Copy(&buf, resp.Body)
	resp.Body.Close()
	backup := buf.String()
	if !strings.Contains(backup, "pass1234") {
		t.Fatal("backup lacks the account")
	}
	// wipe, then restore
	do("POST", "/panel/api/inbounds/del/1", form, "")
	st.mu.Lock()
	st.st.Accounts = map[string]*Account{}
	st.touch()
	st.mu.Unlock()
	if r := do("POST", "/panel/ui/restore", "application/json", backup); r["success"] != true {
		t.Fatalf("restore: %v", r)
	}
	st.mu.RLock()
	_, haveAcc := st.st.Accounts["a@x"]
	_, haveIn := st.st.Inbounds[1]
	user := st.st.Admin.User
	st.mu.RUnlock()
	st.mu.RLock()
	ra, ri := st.st.Accounts["a@x"], st.st.Inbounds[1]
	st.mu.RUnlock()
	if ra == nil || ri == nil || ra.TotalGB != 5<<30 || ra.ExpiryTime != 1893456000000 || ra.Up != 111 || ra.Down != 222 ||
		ra.AllTime != 333 || ra.Enable || ra.LimitIP != 3 || ra.SpeedDown != 500 || ri.Enable || ri.Port != 1194 {
		t.Fatalf("restore changed data: account=%+v inbound=%+v", ra, ri)
	}
	if !haveAcc || !haveIn || user != "admin" {
		t.Fatalf("after restore: account=%v inbound=%v admin=%q", haveAcc, haveIn, user)
	}
	if r := do("POST", "/panel/ui/restore", "application/json", `{"hello":1}`); r["success"] == true {
		t.Fatal("garbage was accepted as a backup")
	}
}

func TestImportFromOldPanel(t *testing.T) {
	old := http.NewServeMux()
	old.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, envelope{true, "", nil})
	})
	old.HandleFunc("/panel/api/inbounds/list", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"success": true, "obj": []map[string]any{{
			"id": 7, "remark": "ovpn", "enable": true, "port": 1194, "protocol": "openvpn",
			"settings":    `{"clients":[{"id":"bob","email":"bob@x","password":"secret123","enable":true,"totalGB":1073741824}],"udpEnable":true}`,
			"clientStats": []map[string]any{{"email": "bob@x", "up": 5, "down": 6, "allTime": 11}}}}})
	})
	srv := httptest.NewServer(old)
	defer srv.Close()
	st := testStore(t)
	nIn, nAcc, _, err := importFromPanel(st, srv.URL, "u", "p", 10000, false)
	if err != nil || nIn != 1 || nAcc != 1 {
		t.Fatalf("import: %d %d %v", nIn, nAcc, err)
	}
	st.mu.RLock()
	defer st.mu.RUnlock()
	acc := st.st.Accounts["bob@x"]
	if acc == nil || acc.Username != "bob" || acc.Up != 5 || acc.TotalGB != 1073741824 {
		t.Fatalf("account not imported correctly: %+v", acc)
	}
	for _, in := range st.st.Inbounds {
		if in.Port != 11194 || in.Enable {
			t.Fatalf("inbound should be shifted and disabled: port=%d enable=%v", in.Port, in.Enable)
		}
	}
}

func TestTelegramBackup(t *testing.T) {
	var gotChat, gotName string
	var gotSize int
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/botTOKEN/sendDocument") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		r.ParseMultipartForm(32 << 20)
		gotChat = r.FormValue("chat_id")
		if f, h, err := r.FormFile("document"); err == nil {
			gotName = h.Filename
			b, _ := io.ReadAll(f)
			gotSize = len(b)
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer fake.Close()
	old := tgAPI
	tgAPI = fake.URL
	defer func() { tgAPI = old }()
	st := testStore(t)
	if err := st.SendBackup(); err == nil {
		t.Fatal("expected an error without token/chat")
	}
	st.mu.Lock()
	st.st.Global.TgToken, st.st.Global.TgChat = "TOKEN", "42"
	st.touch()
	st.mu.Unlock()
	if err := st.SendBackup(); err != nil {
		t.Fatal(err)
	}
	if gotChat != "42" || !strings.HasPrefix(gotName, "vpn-lite-") || gotSize < 50 {
		t.Fatalf("bad upload: chat=%q name=%q size=%d", gotChat, gotName, gotSize)
	}
}

func TestTelegramLoginNotice(t *testing.T) {
	got := make(chan string, 4)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got <- r.FormValue("text")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer fake.Close()
	old := tgAPI
	tgAPI = fake.URL
	defer func() { tgAPI = old }()
	st := testStore(t)
	st.mu.Lock()
	st.st.Global.TgToken, st.st.Global.TgChat = "T", "1"
	st.mu.Unlock()
	st.NotifyLogin(true, "admin", "1.2.3.4")
	select {
	case m := <-got:
		if !strings.Contains(m, "admin") || !strings.Contains(m, "1.2.3.4") {
			t.Fatalf("message lacks user/ip: %q", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no login message sent")
	}
	st.mu.Lock()
	st.st.Global.TgNoLogin = true
	st.mu.Unlock()
	st.NotifyLogin(true, "admin", "1.2.3.4")
	select {
	case m := <-got:
		t.Fatalf("message sent although disabled: %q", m)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestVpnUiDBBackup(t *testing.T) {
	b, err := os.ReadFile("testdata/vpnui_small.db")
	if err != nil {
		t.Fatal(err)
	}
	st, skipped, err := stateFromVpnUiDB(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Inbounds) != 2 || skipped != 1 || st.Inbounds[4] == nil || st.Inbounds[5] == nil || st.NextInbound != 6 {
		t.Fatalf("inbounds: %d skipped %d next %d", len(st.Inbounds), skipped, st.NextInbound)
	}
	if st.Inbounds[4].Settings["connDomain"] != "l2tp.example.com" || st.Inbounds[4].Settings["ipsecPsk"] != "123456" || st.Inbounds[4].Settings["clients"] != nil {
		t.Fatalf("l2tp settings: %v", st.Inbounds[4].Settings)
	}
	if st.Inbounds[5].Settings["caCert"] != "CA" || st.Inbounds[5].Settings["tlsCrypt"] != "TC" {
		t.Fatalf("ovpn settings: %v", st.Inbounds[5].Settings)
	}
	if len(st.Accounts) != 400 {
		t.Fatalf("accounts %d", len(st.Accounts))
	}
	a := st.Accounts["user10"]
	if a == nil || a.Enable || a.Password != "pw10" || a.Username != "vpn10" || a.Up != 10000 || a.Down != 20000 || a.AllTime != 30000 || a.ExpiryTime != 1795017077000 || len(a.Inbounds) != 2 {
		t.Fatalf("account: %+v", a)
	}
	if u := st.Accounts["user1"]; u.TotalGB != 5<<30 || len(u.Inbounds) != 2 { // pptp membership dropped
		t.Fatalf("user1: %+v", u)
	}
}

func TestLifetimeUsageNeverDrops(t *testing.T) {
	st := testStore(t)
	seed(st)
	st.AddTraffic("alice@x", 1000, 2000)
	if st.st.Global.TotalUsed != 3000 {
		t.Fatalf("total %d", st.st.Global.TotalUsed)
	}
	st.mu.Lock()
	st.st.Accounts["alice@x"].Up, st.st.Accounts["alice@x"].Down = 0, 0 // manual volume reset
	st.mu.Unlock()
	st.mu.Lock()
	delete(st.st.Accounts, "alice@x") // account deleted
	st.rebaseTotalLocked()
	st.mu.Unlock()
	if st.st.Global.TotalUsed != 3000 {
		t.Fatalf("lifetime usage dropped to %d", st.st.Global.TotalUsed)
	}
	// an old state without the counter starts from what the accounts already used
	st.mu.Lock()
	st.st.Global.TotalUsed = 0
	st.st.Accounts["bob@x"] = &Account{Email: "bob@x", AllTime: 500}
	st.rebaseTotalLocked()
	st.mu.Unlock()
	if st.st.Global.TotalUsed < 500 {
		t.Fatalf("baseline %d", st.st.Global.TotalUsed)
	}
}

func TestResetTotalAndDeleteExpired(t *testing.T) {
	st := testStore(t)
	seed(st)
	st.AddTraffic("alice@x", 100, 100)
	st.mu.Lock()
	st.st.Accounts["alice@x"].ExpiryTime = nowMs() - 1000
	st.mu.Unlock()
	a := &API{st: st, d: noDaemonsT{}, base: "/"}
	rec := httptest.NewRecorder()
	a.uiDeleteExpired(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{"dry":true}`)))
	if _, ok := st.st.Accounts["alice@x"]; !ok {
		t.Fatal("dry run deleted an account")
	}
	rec = httptest.NewRecorder()
	a.uiDeleteExpired(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if _, ok := st.st.Accounts["alice@x"]; ok {
		t.Fatal("expired account was not deleted")
	}
	if st.st.Global.TotalUsed != 200 {
		t.Fatalf("deleting lowered the total: %d", st.st.Global.TotalUsed)
	}
	a.uiResetTotal(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	st.mu.Lock()
	if st.st.Global.TotalUsed != 0 || !st.st.Global.TotalInit {
		t.Fatalf("reset: %d", st.st.Global.TotalUsed)
	}
	st.mu.Unlock()
}

func TestRadiusDictionaryHasOcservAttributes(t *testing.T) {
	// ocserv's radcli sends Connect-Info (77); a dictionary without it makes every login fail
	for _, a := range []string{"Connect-Info\t77", "NAS-IPv6-Address\t95", "Framed-IPv6-Prefix\t97"} {
		if !strings.Contains(radDictionary, a) {
			t.Fatalf("dictionary lacks %q", a)
		}
	}
}

func TestReapStaleDaemon(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip("no sleep")
	}
	go cmd.Wait()
	pf := filepath.Join(dir, "d.pid")
	os.WriteFile(pf, []byte(fmt.Sprint(cmd.Process.Pid)), 0o600)
	d := &procDaemon{name: "t", pidFile: pf, match: "sleep", hash: "new"}
	for i := 0; i < 100 && d.pid() == 0; i++ { // the child shows its final command line only after exec
		time.Sleep(10 * time.Millisecond)
	}
	// unknown hash + adoptUnknown: left running
	d.adoptUnknown = true
	d.reapStale()
	if d.pid() == 0 {
		t.Fatal("adoptUnknown daemon was killed")
	}
	// recorded hash differs: restarted (killed here, the supervisor starts it again)
	os.WriteFile(pf+".hash", []byte("old"), 0o600)
	d.reapStale()
	if d.pid() != 0 {
		t.Fatal("stale daemon still running")
	}
}

// radcli (ocserv) refuses to start when a dictionary line has a type it does not know
// ("invalid type on line N"), so only the types seen to work are allowed.
func TestRadiusDictionaryTypesAreSafe(t *testing.T) {
	ok := map[string]bool{"string": true, "integer": true, "ipaddr": true, "ipv6addr": true}
	for i, ln := range strings.Split(radDictionary, "\n") {
		f := strings.Fields(ln)
		if len(f) >= 4 && f[0] == "ATTRIBUTE" && !ok[f[3]] {
			t.Fatalf("dictionary line %d has type %q", i+1, f[3])
		}
	}
}

func TestOcservBanDisabled(t *testing.T) {
	in := &Inbound{ID: 6, Protocol: "openconnect", Port: 1002, Settings: map[string]any{}}
	c := ocservConf(in, "/d", "/r", "/r.conf")
	if !strings.Contains(c, "max-ban-score = 0") {
		t.Fatal("ocserv must not ban the shared relay address")
	}
}
