package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var domainRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// leStatus describes the Let's Encrypt certificate that exists for a domain on this host.
func leStatus(dom string) string {
	b, err := os.ReadFile("/etc/letsencrypt/live/" + dom + "/fullchain.pem")
	if err != nil {
		return ""
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("Let's Encrypt, valid until %s", c.NotAfter.Format("2006-01-02"))
}

// uiCertStatus tells which certificate a Cisco inbound is really using.
func (a *API) uiCertStatus(w http.ResponseWriter, r *http.Request) {
	a.st.mu.RLock()
	in := a.st.st.Inbounds[pathID(r)]
	var dom, own string
	if in != nil {
		dom = strings.TrimSpace(strSetting(in.Settings, "connDomain", ""))
		own = strSetting(in.Settings, "certificate", "")
	}
	a.st.mu.RUnlock()
	if in == nil {
		fail(w, "Inbound not found")
		return
	}
	if dom != "" {
		if s := leStatus(dom); s != "" {
			ok(w, s, nil)
			return
		}
	}
	if own != "" {
		ok(w, "self-signed (clients may warn)", nil)
		return
	}
	ok(w, "none yet (a self-signed one is made on start)", nil)
}

// uiCertIssue gets a Let's Encrypt certificate for the inbound's connection domain. It is
// optional and explicit: nothing calls it unless the admin presses the button. The reply
// always says what happened and why.
func (a *API) uiCertIssue(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	dom := strings.ToLower(strings.TrimSpace(r.Form.Get("domain")))
	a.st.mu.RLock()
	in := a.st.st.Inbounds[id]
	a.st.mu.RUnlock()
	if in == nil {
		fail(w, "Inbound not found")
		return
	}
	if !domainRe.MatchString(dom) {
		fail(w, "Enter a valid connection domain first (e.g. vpn.example.com)")
		return
	}
	var steps []string
	ips, err := net.LookupIP(dom)
	if err != nil || len(ips) == 0 {
		fail(w, "The domain does not resolve yet: create its A record pointing to this server (Cloudflare: proxy OFF / grey cloud), wait a minute and retry.")
		return
	}
	steps = append(steps, "DNS ok: "+ips[0].String())
	if ln, e := net.Listen("tcp", ":80"); e != nil {
		fail(w, "Port 80 is busy on this server, Let's Encrypt needs it for a moment: "+e.Error())
		return
	} else {
		ln.Close()
	}
	bin, e := exec.LookPath("certbot")
	if e != nil {
		fail(w, "certbot is not installed. Run `vl` and choose the certificate option once (it installs certbot), then retry.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, bin, "certonly", "--standalone", "-d", dom, "--agree-tos",
		"--register-unsafely-without-email", "-n", "--keep-until-expiring").CombinedOutput()
	if e != nil {
		tail := string(out)
		if len(tail) > 600 {
			tail = tail[len(tail)-600:]
		}
		Events.Add("error", "openconnect", "", "certificate for %s failed: %s", dom, strings.TrimSpace(tail))
		msg := "Let's Encrypt refused: " + strings.TrimSpace(tail)
		if !anyLocalIP(ips) {
			msg = "The domain " + dom + " points to " + ips[0].String() + ", which is not this server. Let's Encrypt must reach port 80 of the address in the DNS record, " +
				"so this fails when a relay/forwarder sits in front (it usually forwards only the VPN ports). " +
				"You do not need this: the built-in self-signed certificate works for VPN clients. " +
				"(Only the panel domain needs a real certificate.)  Details: " + strings.TrimSpace(tail)
		}
		fail(w, msg)
		return
	}
	a.st.mu.Lock()
	if cur := a.st.st.Inbounds[id]; cur != nil {
		if cur.Settings == nil {
			cur.Settings = map[string]any{}
		}
		cur.Settings["connDomain"] = dom
		a.st.touch()
	}
	a.st.mu.Unlock()
	Events.Add("info", "openconnect", "", "inbound %d: Let's Encrypt certificate for %s obtained", id, dom)
	a.d.ReloadInbound(id) // restart the daemon so it serves the new certificate
	ok(w, strings.Join(append(steps, "certificate obtained: "+leStatus(dom)), " · "), nil)
}

// anyLocalIP reports whether one of the addresses belongs to a network interface of this machine.
func anyLocalIP(ips []net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true // cannot tell: do not blame the DNS record
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			for _, ip := range ips {
				if ip.Equal(ipn.IP) {
					return true
				}
			}
		}
	}
	return false
}
