package main

import (
	"bufio"
	"crypto/md5"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
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
		"protocol": {"l2tp"}, "settings": {`{"clients":[]}`}})
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
	// .ovpn needs certs first
	resp, _ := c.Get(ts.URL + "/panel/api/inbounds/1/ovpn/udp")
	var m map[string]any
	jsonDecode(resp, &m)
	if m["success"] != false {
		t.Fatalf("ovpn without certs should fail: %v", m)
	}
}
