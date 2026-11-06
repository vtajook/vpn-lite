package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// issueCert gets a Let's Encrypt certificate for domain with certbot (standalone, port 80) and
// returns a human-readable log of every step, so the panel can show what happened.
func issueCert(domain string) (ok bool, log string) {
	var b strings.Builder
	say := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainRe.MatchString(domain) {
		say("✗ %q is not a valid domain name", domain)
		return false, b.String()
	}
	// 1. DNS
	myIP := publicIP()
	ips, err := net.LookupHost(domain)
	if err != nil {
		say("✗ the domain does not resolve yet (%v). Create an A record for %s pointing to this server.", err, domain)
		return false, b.String()
	}
	say("• %s resolves to %s; this server's public address is %s", domain, strings.Join(ips, ", "), orUnknown(myIP))
	if myIP != "" {
		match := false
		for _, ip := range ips {
			if ip == myIP {
				match = true
			}
		}
		if !match {
			say("! the domain does not point to this server. If it points to a relay/other server, TCP port 80 must be forwarded to this server, otherwise Let's Encrypt cannot verify it.")
		}
	}
	// 2. port 80
	if l, err := net.Listen("tcp", ":80"); err != nil {
		say("✗ port 80 is busy on this server (%v). Free it (stop the web server using it) and try again.", err)
		return false, b.String()
	} else {
		l.Close()
	}
	say("• port 80 is free")
	// 3. certbot
	if _, err := exec.LookPath("certbot"); err != nil {
		say("• installing certbot ...")
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		out, err := exec.CommandContext(ctx, "sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot").CombinedOutput()
		cancel()
		if err != nil {
			say("✗ could not install certbot: %v\n%s", err, tail(string(out), 600))
			return false, b.String()
		}
	}
	// 4. certificate
	say("• asking Let's Encrypt for a certificate (this takes up to a minute) ...")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "certbot", "certonly", "--standalone", "-d", domain, "--agree-tos",
		"--register-unsafely-without-email", "-n", "--keep-until-expiring").CombinedOutput()
	if err != nil {
		say("✗ Let's Encrypt refused or failed: %v\n%s", err, tail(string(out), 900))
		return false, b.String()
	}
	say("✓ certificate ready for %s (renews automatically)", domain)
	return true, b.String()
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func publicIP() string {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	return strings.TrimSpace(string(b))
}
