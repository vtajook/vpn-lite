package main

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Embedded RADIUS server (RFC 2865/2866/2759/2548) used by the PPP (L2TP) and ocserv
// daemons. It answers PAP, CHAP and MS-CHAPv2, and turns accounting packets into
// sessions and traffic counters. UDP is asynchronous, so a slow database or a busy
// panel can never stall a daemon's event loop the way an exec hook does.

const (
	radAccessRequest   = 1
	radAccessAccept    = 2
	radAccessReject    = 3
	radAccountingReq   = 4
	radAccountingResp  = 5
	attrUserName       = 1
	attrUserPassword   = 2
	attrCHAPPassword   = 3
	attrNASPort        = 5
	attrServiceType    = 6
	attrFramedProtocol = 7
	attrFramedIP       = 8
	attrReplyMessage   = 18
	attrVendorSpecific = 26
	attrCallingStation = 31
	attrNASIdentifier  = 32
	attrAcctStatus     = 40
	attrAcctInOctets   = 42
	attrAcctOutOctets  = 43
	attrAcctSessionID  = 44
	attrAcctInGiga     = 52
	attrAcctOutGiga    = 53
	attrCHAPChallenge  = 60
	attrAcctInterim    = 85
	vendorMS           = 311
)

type radAttr struct {
	T byte
	V []byte
}

type radPkt struct {
	Code, ID byte
	Auth     [16]byte
	Attrs    []radAttr
}

func parseRad(b []byte) (*radPkt, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("short packet")
	}
	l := int(binary.BigEndian.Uint16(b[2:4]))
	if l < 20 || l > len(b) {
		return nil, fmt.Errorf("bad length")
	}
	p := &radPkt{Code: b[0], ID: b[1]}
	copy(p.Auth[:], b[4:20])
	for i := 20; i < l; {
		if i+2 > l || b[i+1] < 2 || i+int(b[i+1]) > l {
			return nil, fmt.Errorf("bad attribute")
		}
		n := int(b[i+1])
		p.Attrs = append(p.Attrs, radAttr{b[i], append([]byte(nil), b[i+2:i+n]...)})
		i += n
	}
	return p, nil
}

func (p *radPkt) get(t byte) []byte {
	for _, a := range p.Attrs {
		if a.T == t {
			return a.V
		}
	}
	return nil
}
func (p *radPkt) str(t byte) string { return string(p.get(t)) }
func (p *radPkt) u32(t byte) uint32 {
	v := p.get(t)
	if len(v) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

// msAttr finds a Microsoft vendor-specific sub-attribute (vendor 311).
func (p *radPkt) msAttr(sub byte) []byte {
	for _, a := range p.Attrs {
		if a.T != attrVendorSpecific || len(a.V) < 6 || binary.BigEndian.Uint32(a.V[:4]) != vendorMS {
			continue
		}
		for v := a.V[4:]; len(v) >= 2 && int(v[1]) <= len(v) && v[1] >= 2; v = v[v[1]:] {
			if v[0] == sub {
				return v[2:v[1]]
			}
		}
	}
	return nil
}

func msVSA(sub byte, val []byte) radAttr {
	b := make([]byte, 6+len(val))
	binary.BigEndian.PutUint32(b, vendorMS)
	b[4], b[5] = sub, byte(2+len(val))
	copy(b[6:], val)
	return radAttr{attrVendorSpecific, b}
}

func u32attr(t byte, v uint32) radAttr {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return radAttr{t, b}
}

func (p *radPkt) encode(secret string, reqAuth [16]byte) []byte {
	n := 20
	for _, a := range p.Attrs {
		n += 2 + len(a.V)
	}
	b := make([]byte, n)
	b[0], b[1] = p.Code, p.ID
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	copy(b[4:20], reqAuth[:])
	i := 20
	for _, a := range p.Attrs {
		b[i], b[i+1] = a.T, byte(2+len(a.V))
		copy(b[i+2:], a.V)
		i += 2 + len(a.V)
	}
	sum := md5.Sum(append(b, secret...))
	copy(b[4:20], sum[:])
	return b
}

// pap decrypts User-Password (RFC 2865 5.2).
func papDecrypt(enc []byte, secret string, reqAuth [16]byte) string {
	if len(enc) == 0 || len(enc)%16 != 0 {
		return ""
	}
	out := make([]byte, 0, len(enc))
	prev := reqAuth[:]
	for i := 0; i < len(enc); i += 16 {
		h := md5.Sum(append([]byte(secret), prev...))
		for j := 0; j < 16; j++ {
			out = append(out, enc[i+j]^h[j])
		}
		prev = enc[i : i+16]
	}
	return strings.TrimRight(string(out), "\x00")
}

// ---------------------------------------------------------------- server

type RadiusServer struct {
	st     *Store
	secret string
	auth   *net.UDPConn
	acct   *net.UDPConn
	kill   func(proto string, s *Session) // how to disconnect a session of that protocol
	mu     sync.Mutex
	seen   map[string]int64 // duplicate suppression: "addr/id/code" -> time
}

func protoOfNAS(nas string) string {
	n := strings.ToLower(nas)
	switch {
	case strings.Contains(n, "l2tp"):
		return "l2tp"
	case strings.Contains(n, "oc"), strings.Contains(n, "ocserv"), strings.Contains(n, "openconnect"):
		return "openconnect"
	}
	return ""
}

// inboundOfProto finds the inbound of a protocol an account belongs to.
func (s *Store) inboundOfProto(user, proto string) (int, *Account) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.st.Accounts {
		if !strings.EqualFold(a.Username, user) {
			continue
		}
		for _, id := range a.Inbounds {
			if in := s.st.Inbounds[id]; in != nil && in.Protocol == proto {
				return id, a
			}
		}
		return 0, a
	}
	return 0, nil
}

func (r *RadiusServer) Start(addr string) error {
	a1, err := net.ResolveUDPAddr("udp", addr+":1812")
	if err != nil {
		return err
	}
	a2, _ := net.ResolveUDPAddr("udp", addr+":1813")
	if r.auth, err = net.ListenUDP("udp", a1); err != nil {
		return err
	}
	if r.acct, err = net.ListenUDP("udp", a2); err != nil {
		return err
	}
	r.seen = map[string]int64{}
	go r.loop(r.auth, r.handleAuth)
	go r.loop(r.acct, r.handleAcct)
	go func() {
		for range time.Tick(time.Minute) {
			r.mu.Lock()
			cut := time.Now().Add(-30 * time.Second).UnixMilli()
			for k, t := range r.seen {
				if t < cut {
					delete(r.seen, k)
				}
			}
			r.mu.Unlock()
		}
	}()
	return nil
}

func (r *RadiusServer) loop(c *net.UDPConn, h func(*net.UDPAddr, *radPkt) []byte) {
	buf := make([]byte, 4096)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		p, err := parseRad(buf[:n])
		if err != nil {
			continue
		}
		// each request is handled in its own goroutine: no request waits for another
		go func(from *net.UDPAddr, p *radPkt) {
			if resp := h(from, p); resp != nil {
				c.WriteToUDP(resp, from)
			}
		}(from, p)
	}
}

func (r *RadiusServer) handleAuth(from *net.UDPAddr, p *radPkt) []byte {
	if p.Code != radAccessRequest {
		return nil
	}
	user := p.str(attrUserName)
	nas := p.str(attrNASIdentifier)
	proto := protoOfNAS(nas)
	reject := func(reason string, mschapIdent int) []byte {
		Events.Add("reject", proto, user, "%s", reason)
		resp := &radPkt{Code: radAccessReject, ID: p.ID, Attrs: []radAttr{{attrReplyMessage, []byte(reason)}}}
		if mschapIdent >= 0 {
			resp.Attrs = append(resp.Attrs, msVSA(2, append([]byte{byte(mschapIdent)},
				[]byte("E=691 R=1 C=00000000000000000000000000000000 V=3 M="+reason)...)))
		}
		return resp.encode(r.secret, p.Auth)
	}
	if proto == "" {
		return reject("unknown NAS", -1)
	}
	inbound, acc := r.st.inboundOfProto(user, proto)

	var verify func(stored string) bool
	var msSuccess []byte
	msIdent := -1
	switch {
	case p.get(attrUserPassword) != nil:
		pw := papDecrypt(p.get(attrUserPassword), r.secret, p.Auth)
		verify = func(stored string) bool { return subtle.ConstantTimeCompare([]byte(stored), []byte(pw)) == 1 }
	case p.get(attrCHAPPassword) != nil:
		cp := p.get(attrCHAPPassword)
		chal := p.get(attrCHAPChallenge)
		if chal == nil {
			chal = p.Auth[:]
		}
		verify = func(stored string) bool {
			if len(cp) != 17 {
				return false
			}
			h := md5.New()
			h.Write(cp[:1])
			h.Write([]byte(stored))
			h.Write(chal)
			return subtle.ConstantTimeCompare(h.Sum(nil), cp[1:]) == 1
		}
	case p.msAttr(25) != nil:
		resp := p.msAttr(25) // ident(1) flags(1) peerChallenge(16) reserved(8) ntResponse(24)
		chal := p.msAttr(11)
		if len(resp) != 50 || len(chal) != 16 {
			return reject("malformed MS-CHAPv2", -1)
		}
		msIdent = int(resp[0])
		verify = func(stored string) bool {
			s, ok := mschapv2Verify(user, stored, chal, resp[2:18], resp[26:50])
			if ok {
				msSuccess = append([]byte{resp[0]}, []byte(s)...)
			}
			return ok
		}
	default:
		return reject("no supported credential", -1)
	}
	if acc == nil {
		verify = func(string) bool { return false }
	}
	res := r.st.AuthorizeFn(inbound, user, verify, nil)
	if !res.OK {
		return reject(res.Reason, msIdent)
	}
	resp := &radPkt{Code: radAccessAccept, ID: p.ID, Attrs: []radAttr{
		u32attr(attrServiceType, 2), u32attr(attrFramedProtocol, 1), u32attr(attrAcctInterim, 60)}}
	if msSuccess != nil {
		resp.Attrs = append(resp.Attrs, msVSA(26, msSuccess))
	}
	return resp.encode(r.secret, p.Auth)
}

func octets(p *radPkt, lo, hi byte) int64 {
	return int64(p.u32(hi))<<32 | int64(p.u32(lo))
}

func (r *RadiusServer) handleAcct(from *net.UDPAddr, p *radPkt) []byte {
	if p.Code != radAccountingReq {
		return nil
	}
	defer func() {}()
	resp := (&radPkt{Code: radAccountingResp, ID: p.ID}).encode(r.secret, p.Auth)
	key := fmt.Sprintf("%s/%d/%x", from.IP, p.ID, p.Auth)
	r.mu.Lock()
	if _, dup := r.seen[key]; dup {
		r.mu.Unlock()
		return resp // retransmission: acknowledge, don't count twice
	}
	r.seen[key] = nowMs()
	r.mu.Unlock()

	user := p.str(attrUserName)
	proto := protoOfNAS(p.str(attrNASIdentifier))
	sid := from.IP.String() + "/" + p.str(attrAcctSessionID)
	in, out := octets(p, attrAcctInOctets, attrAcctInGiga), octets(p, attrAcctOutOctets, attrAcctOutGiga)
	status := p.u32(attrAcctStatus)
	vip := ""
	if v := p.get(attrFramedIP); len(v) == 4 {
		vip = net.IP(v).String()
	}
	switch status {
	case 1, 3: // start, interim
		if Sessions.Get(sid) == nil {
			inbound, acc := r.st.inboundOfProto(user, proto)
			if acc == nil {
				return resp
			}
			s := &Session{ID: sid, Email: acc.Email, InboundID: inbound, Proto: proto,
				SrcIP: p.str(attrCallingStation), VIP: vip, Start: nowMs(), LastSeen: nowMs(),
				Up: 0, Down: 0}
			unit := int(p.u32(attrNASPort))
			s.Kill = func() { r.kill(proto, s) }
			s.Dev = ""
			if proto == "l2tp" {
				s.Dev = "ppp" + strconv.Itoa(unit)
			}
			Sessions.Add(s)
			Events.Add("connect", proto, acc.Email, "ip=%s src=%s", vip, s.SrcIP)
			Shaper.Apply(s)
		}
		dUp, dDown, s := Sessions.Touch(sid, in, out)
		if s != nil && r.st.AddTraffic(s.Email, dUp, dDown) {
			Sessions.KickEmail(s.Email)
		}
	case 2: // stop
		dUp, dDown, s := Sessions.Touch(sid, in, out)
		if s != nil {
			r.st.AddTraffic(s.Email, dUp, dDown)
			Sessions.Remove(sid)
			Events.Add("disconnect", proto, s.Email, "cause=%d up=%d down=%d", p.u32(49), in, out)
		}
	}
	return resp
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
