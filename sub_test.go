package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestSubscriptionPage(t *testing.T) {
	st := testStore(t)
	st.mu.Lock()
	st.st.Inbounds[1] = &Inbound{ID: 1, Protocol: "l2tp", Remark: "L2TP", Port: 1701, Enable: true,
		Settings: map[string]any{"connDomain": "vpn.example.com", "ipsecEnable": true, "ipsecPsk": "sekrit"}}
	st.st.Inbounds[2] = &Inbound{ID: 2, Protocol: "openconnect", Remark: "Cisco", Port: 443, Enable: true,
		Settings: map[string]any{"connDomain": "vpn.example.com"}}
	st.st.Inbounds[4] = &Inbound{ID: 4, Protocol: "openvpn", Remark: "OVPN", Port: 1001, Enable: true,
		Settings: map[string]any{"caCert": "CA", "connDomain": "vpn.example.com", "udpEnable": true, "tcpEnable": true}}
	st.st.Inbounds[3] = &Inbound{ID: 3, Protocol: "l2tp", Remark: "OFF", Port: 1701, Enable: false, Settings: map[string]any{}}
	st.st.Accounts["alice"] = &Account{Email: "alice", Username: "alice", Password: "pw<&>1", SubID: "abcdef0123456789", Enable: true,
		TotalGB: 10 << 30, Up: 1 << 30, ExpiryTime: nowMs() + 5*86400000, Inbounds: []int{1, 2, 3, 4}}
	st.st.Accounts["nosub"] = &Account{Email: "nosub", Username: "nosub", Password: "x", Enable: true}
	st.mu.Unlock()
	a := &API{st: st, d: noDaemonsT{}, base: "/"}
	h := a.Handler()

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Host = "panel.example.com:2096"
		req.RemoteAddr = "1.2.3.4:5555"
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := get("/sub/abcdef0123456789")
	if rec.Code != 200 {
		t.Fatalf("page: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"alice", "pw&lt;&amp;&gt;1", "vpn.example.com", "sekrit", "فعال", "Cisco AnyConnect", "5 روز"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "OFF") {
		t.Error("a disabled service is shown")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing no-store")
	}
	j := get("/sub/abcdef0123456789?format=json")
	if !strings.Contains(j.Body.String(), `"username":"alice"`) || !strings.Contains(j.Body.String(), `"psk":"sekrit"`) {
		t.Errorf("json: %s", j.Body.String())
	}
	if c := get("/sub/0000000000000000").Code; c != http.StatusNotFound {
		t.Errorf("unknown id: %d", c)
	}
	if c := get("/sub/x").Code; c != http.StatusNotFound { // too short never matches, even an account with an empty id
		t.Errorf("short id: %d", c)
	}
	ov := get("/sub/abcdef0123456789/ovpn/4/udp")
	if ov.Code != 200 || !strings.Contains(ov.Body.String(), "remote vpn.example.com 1001 udp") || !strings.Contains(ov.Body.String(), "alice") ||
		!strings.Contains(ov.Header().Get("Content-Disposition"), "alice-udp.ovpn") {
		t.Errorf("ovpn download: %d %s", ov.Code, ov.Body.String())
	}
	// follow the download button exactly as a browser would: it must resolve to a file, not a 404
	m := regexp.MustCompile(`href="([^"]*/ovpn/4/both)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("page lacks the ovpn button")
	}
	pageURL, _ := url.Parse("https://panel.example.com/sub/abcdef0123456789")
	ref, _ := url.Parse(m[1])
	target := pageURL.ResolveReference(ref)
	if target.Path != "/sub/abcdef0123456789/ovpn/4/both" {
		t.Fatalf("the button resolves to %s", target.Path)
	}
	if dl := get(target.Path); dl.Code != 200 || !strings.Contains(dl.Body.String(), "remote vpn.example.com") {
		t.Errorf("button target: %d", dl.Code)
	}
	// someone else's inbound or a non-openvpn one is never served
	if c := get("/sub/abcdef0123456789/ovpn/1/both").Code; c != http.StatusNotFound {
		t.Errorf("ovpn of an l2tp inbound: %d", c)
	}
	// guessing is limited
	subMiss.Lock()
	subMiss.m = map[string][]int64{}
	subMiss.Unlock()
	var last int
	for i := 0; i < 30; i++ {
		last = get("/sub/ffffffffffffff" + string(rune('a'+i%6)) + "f").Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("no rate limit: %d", last)
	}
	subMiss.Lock()
	subMiss.m = map[string][]int64{}
	subMiss.Unlock()
}
