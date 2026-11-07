package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func resetSessions() {
	Sessions.mu.Lock()
	Sessions.byID = map[string]*Session{}
	Sessions.mu.Unlock()
}

// A reconnecting phone must not be refused because the daemon still holds its dead connection.
func TestDeadSessionIsReplaced(t *testing.T) {
	st := testStore(t)
	seed(st) // alice on openvpn (1) and l2tp (2), limit = default 1
	pass := func(stored string) bool { return stored == "secret" }
	killed := make(chan string, 4)
	add := func(id, proto string, idleSec int64) {
		Sessions.Add(&Session{ID: id, Email: "alice@x", Proto: proto, Start: nowMs() - 600_000, LastSeen: nowMs(),
			LastActive: nowMs() - idleSec*1000, Kill: func() { killed <- id }})
	}
	expectKill := func(id string) {
		select {
		case k := <-killed:
			if k != id {
				t.Fatalf("killed %s, want %s", k, id)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s was not disconnected", id)
		}
	}

	// the old OpenVPN connection has sent nothing for a minute: it is dead, the new login replaces it
	resetSessions()
	add("old", "openvpn-udp", 60)
	if r := st.AuthorizeFn(1, "alice", pass, &Session{ID: "new", Proto: "openvpn-udp"}); !r.OK {
		t.Fatalf("reconnect refused: %q", r.Reason)
	}
	expectKill("old")

	// an active connection still counts: a second device is refused and nobody is disconnected
	resetSessions()
	add("busy", "openvpn-udp", 3)
	if r := st.AuthorizeFn(1, "alice", pass, &Session{ID: "second", Proto: "openvpn-udp"}); r.OK {
		t.Fatal("second device let in while the first is active")
	}
	select {
	case k := <-killed:
		t.Fatalf("%s disconnected by a refused login", k)
	case <-time.After(200 * time.Millisecond):
	}

	// one protocol at a time: a dead L2TP link does not block an OpenVPN login
	resetSessions()
	add("ppp", "l2tp", 400)
	if r := st.AuthorizeFn(1, "alice", pass, &Session{ID: "ov", Proto: "openvpn-udp"}); !r.OK {
		t.Fatalf("login blocked by a dead session on another protocol: %q", r.Reason)
	}
	expectKill("ppp")

	// ... but a live one does
	resetSessions()
	add("ppp2", "l2tp", 20)
	if r := st.AuthorizeFn(1, "alice", pass, &Session{ID: "ov2", Proto: "openvpn-udp"}); r.OK {
		t.Fatal("protocol mixing allowed while the L2TP session is active")
	}

	// with room under the cap a dead session is left to the daemon
	resetSessions()
	st.mu.Lock()
	st.st.Accounts["alice@x"].LimitIP = 2
	st.mu.Unlock()
	add("idle", "openvpn-udp", 60)
	if r := st.AuthorizeFn(1, "alice", pass, &Session{ID: "n", Proto: "openvpn-udp"}); !r.OK {
		t.Fatalf("refused: %q", r.Reason)
	}
	select {
	case k := <-killed:
		t.Fatalf("%s disconnected although there was room", k)
	case <-time.After(200 * time.Millisecond):
	}
	resetSessions()
}

// After a panel restart the first interim of a running L2TP/Cisco session must not count the
// whole session again (that used to eat customers' quota on every update).
func TestInterimAfterRestartNotCountedTwice(t *testing.T) {
	st := testStore(t)
	seed(st)
	resetSessions()
	r := &RadiusServer{st: st, secret: "sh", seen: map[string]int64{}, kill: func(string, *Session) {}}
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}
	acct := func(status uint32, in, out uint32, id byte) {
		p, _ := radReq("sh", nil, radAccountingReq)
		p.ID, p.Auth[0] = id, id
		p.Attrs = []radAttr{{attrUserName, []byte("alice")}, {attrNASIdentifier, []byte("vl-l2tp")},
			{attrAcctSessionID, []byte("S9")}, u32attr(attrAcctStatus, status), u32attr(attrAcctInOctets, in),
			u32attr(attrAcctOutOctets, out), u32attr(attrNASPort, 0), {attrFramedIP, []byte{10, 1, 0, 9}}}
		r.handleAcct(from, p)
	}
	acct(3, 50_000_000, 900_000_000, 1) // the panel never saw the start of this session
	acct(3, 50_001_000, 900_005_000, 2)
	st.mu.RLock()
	a := st.st.Accounts["alice@x"]
	up, down := a.Up, a.Down
	st.mu.RUnlock()
	if up != 1000 || down != 5000 {
		t.Fatalf("counted %d/%d, want 1000/5000", up, down)
	}
	resetSessions()
}

// Traffic counters alone are saved once a minute; account changes are saved promptly.
func TestTrafficSavedLazily(t *testing.T) {
	st := testStore(t)
	seed(st)
	st.Flush()
	st.AddTraffic("alice@x", 10, 20)
	if st.dirty.Load() || !st.trafficDirty.Load() {
		t.Fatalf("traffic must only set trafficDirty (dirty=%v traffic=%v)", st.dirty.Load(), st.trafficDirty.Load())
	}
	if err := st.Flush(); err != nil || st.trafficDirty.Load() {
		t.Fatalf("explicit flush must save the counters: %v", err)
	}
	st2, err := OpenStore(st.path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if a := st2.st.Accounts["alice@x"]; a == nil || a.Up != 10 || a.Down != 20 {
		t.Fatalf("counters not persisted: %+v", a)
	}
}

// Account keys are normalized on load: an odd key must not make the enforcer think the account is gone.
func TestAccountKeysNormalized(t *testing.T) {
	st := testStore(t)
	st.mu.Lock()
	st.st.Accounts[" Bob@X "] = &Account{Email: "Bob@X", Username: "bob", Password: "p", Enable: true}
	st.normalizeKeysLocked()
	_, ok := st.st.Accounts["bob@x"]
	st.mu.Unlock()
	if !ok {
		t.Fatal("key not normalized")
	}
}

type blockingWriter struct {
	h       http.Header
	release chan struct{}
	wrote   chan struct{}
}

func (b *blockingWriter) Header() http.Header { return b.h }
func (b *blockingWriter) WriteHeader(int)     {}
func (b *blockingWriter) Write(p []byte) (int, error) {
	close(b.wrote)
	<-b.release
	return len(p), nil
}

// A slow client must never keep the store locked while its reply is being sent.
func TestReplyIsSentAfterLocksAreReleased(t *testing.T) {
	st := testStore(t)
	h := bufferMW(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.mu.RLock()
		defer st.mu.RUnlock()
		ok(w, "", strings.Repeat("x", 4<<20))
	}))
	bw := &blockingWriter{h: http.Header{}, release: make(chan struct{}), wrote: make(chan struct{})}
	go h.ServeHTTP(bw, httptest.NewRequest("GET", "/", nil))
	<-bw.wrote // the client is "reading" the reply now
	got := make(chan struct{})
	go func() { st.mu.Lock(); st.mu.Unlock(); close(got) }()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("store still locked while the reply is being written")
	}
	close(bw.release)
}

// A daemon whose config could not be rendered this time keeps running (stopping it would drop its users).
func TestDaemonKeptOnRenderFailure(t *testing.T) {
	ds := newDaemonSet()
	d := &procDaemon{name: "x", pidFile: t.TempDir() + "/none.pid", hash: "h", stop: make(chan struct{})}
	ds.m["4"] = d
	ds.apply(map[string]*procDaemon{}, map[string]bool{"4": true})
	if ds.m["4"] != d {
		t.Fatal("daemon removed although it is wanted")
	}
	select {
	case <-d.stop:
		t.Fatal("daemon stopped although it is wanted")
	default:
	}
	ds.apply(map[string]*procDaemon{}, nil) // really removed: now it stops
	if ds.m["4"] != nil {
		t.Fatal("removed inbound's daemon still listed")
	}
	select {
	case <-d.stop:
	default:
		t.Fatal("removed inbound's daemon not stopped")
	}
}

// pppd options must not be part of xl2tpd's restart fingerprint (pppd reads them per connection).
func TestPppOptionsDoNotRestartXl2tpd(t *testing.T) {
	in := &Inbound{ID: 4, Port: 1701, Protocol: "l2tp", Settings: map[string]any{}}
	opt := pppOptions(in, "/r")
	if !strings.Contains(opt, "lcp-echo-interval 10") || !strings.Contains(opt, "lcp-echo-failure 6") {
		t.Fatalf("dead-peer detection should allow 60 s:\n%s", opt)
	}
}
