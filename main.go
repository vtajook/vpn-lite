package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

type dirs struct{ data, conf, run, logs string }

func parseDirs(fs *flag.FlagSet) *dirs {
	d := &dirs{}
	fs.StringVar(&d.data, "data", "/var/lib/vpn-lite", "state directory")
	fs.StringVar(&d.conf, "conf", "/etc/vpn-lite", "generated daemon configs")
	fs.StringVar(&d.run, "run", "/run/vpn-lite", "sockets and pid files")
	fs.StringVar(&d.logs, "log", "/var/log/vpn-lite", "log directory")
	return d
}

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "setup":
		err = setup(args)
	case "import":
		err = importCmd(args)
	case "info":
		err = info(args)
	case "version":
		fmt.Println("vpn-lite", version)
	default:
		fmt.Fprintf(os.Stderr, "usage: vpn-lite [serve|setup|import|version] [flags]\n")
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("vpn-lite %s: %v", cmd, err)
	}
}

// setup creates (or updates) the admin account and listen settings, and makes a
// self-signed HTTPS certificate when none is configured.
func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	d := parseDirs(fs)
	user := fs.String("user", "", "admin username")
	pass := fs.String("pass", "", "admin password")
	port := fs.Int("port", 0, "panel port")
	base := fs.String("base", "", "base path, e.g. /secret/ (default /)")
	bind := fs.String("bind", "", "listen address (default all)")
	noTLS := fs.Bool("no-tls", false, "do not create a self-signed certificate")
	crtPath := fs.String("cert", "", "HTTPS certificate file (e.g. Let's Encrypt fullchain.pem)")
	keyPath := fs.String("key", "", "HTTPS private key file")
	resetTLS := fs.Bool("reset-tls", false, "forget the configured HTTPS certificate and make a new self-signed one")
	fs.Parse(args)
	st, err := OpenStore(filepath.Join(d.data, "state.json"))
	if err != nil {
		return err
	}
	defer st.Close()
	st.mu.Lock()
	g := &st.st.Global
	if *port > 0 {
		g.Port = *port
	}
	if g.Port == 0 {
		g.Port = 2096
	}
	if *base != "" {
		b := *base
		if !strings.HasPrefix(b, "/") {
			b = "/" + b
		}
		if !strings.HasSuffix(b, "/") {
			b += "/"
		}
		g.BasePath = b
	}
	if *bind != "" {
		g.Bind = *bind
	}
	if *resetTLS {
		g.TLSCert, g.TLSKey = "", ""
	}
	if *crtPath != "" && *keyPath != "" {
		g.TLSCert, g.TLSKey = *crtPath, *keyPath
	}
	needAdmin := st.st.Admin.User == ""
	st.touch()
	st.mu.Unlock()
	if *user != "" || needAdmin {
		u, p := *user, *pass
		if u == "" {
			u = "admin"
		}
		if p == "" {
			p = randPass(14)
			fmt.Println("generated password:", p)
		}
		st.SetAdmin(u, p)
		fmt.Println("admin user:", u)
	}
	st.mu.Lock()
	need := !*noTLS && g.TLSCert == ""
	st.mu.Unlock()
	if need {
		crt, key := filepath.Join(d.data, "panel.crt"), filepath.Join(d.data, "panel.key")
		if err := makePanelCert(crt, key); err != nil {
			return err
		}
		st.mu.Lock()
		g.TLSCert, g.TLSKey = crt, key
		st.touch()
		st.mu.Unlock()
		fmt.Println("created a self-signed HTTPS certificate (replace it in Settings or with your own paths)")
	}
	st.mu.RLock()
	fmt.Printf("panel port: %d  base path: %s\n", g.Port, g.BasePath)
	st.mu.RUnlock()
	return st.Flush()
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	d := parseDirs(fs)
	noDaemons := fs.Bool("no-daemons", false, "run only the panel and API (no OpenVPN/L2TP/OpenConnect, RADIUS or nftables)")
	fs.Parse(args)
	for _, p := range []string{d.data, d.conf, d.run, d.logs} {
		os.MkdirAll(p, 0o750)
	}
	st, err := OpenStore(filepath.Join(d.data, "state.json"))
	if err != nil {
		return err
	}
	if st.st.Admin.User == "" {
		return fmt.Errorf("not set up yet: run `vpn-lite setup`")
	}
	Events.Open(filepath.Join(d.logs, "events.log"))

	var dm Daemons
	var eng *Engine
	if *noDaemons {
		dm = noDaemonsT{}
	} else {
		eng = NewEngine(st, d.conf, d.run, d.logs)
		if err := eng.Start(); err != nil {
			return fmt.Errorf("engine: %w", err)
		}
		dm = eng
	}
	st.mu.RLock()
	g := st.st.Global
	st.mu.RUnlock()
	go st.BackupLoop(st.stop)
	api := &API{st: st, d: dm, base: g.BasePath}
	srv := &http.Server{Addr: fmt.Sprintf("%s:%d", g.Bind, g.Port), Handler: api.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second}

	useTLS := g.TLSCert != "" && g.TLSKey != ""
	if useTLS {
		cr := &certReloader{crt: g.TLSCert, key: g.TLSKey}
		if _, err := cr.get(nil); err != nil {
			log.Printf("HTTPS certificate unusable (%v); serving plain HTTP", err)
			useTLS = false
		} else {
			srv.TLSConfig = &tls.Config{GetCertificate: cr.get, MinVersion: tls.VersionTLS12}
		}
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	log.Printf("vpn-lite %s listening on %s://%s%s", version, scheme, srv.Addr, g.BasePath)
	go func() {
		var e error
		if useTLS {
			e = srv.ServeTLS(ln, "", "")
		} else {
			e = srv.Serve(ln)
		}
		if e != nil && e != http.ErrServerClosed {
			log.Fatal(e)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	// Only the panel stops. The VPN daemons are independent processes and keep every
	// tunnel up; the next start re-adopts them.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	if eng != nil {
		eng.Stop()
	}
	st.Close()
	return nil
}

type noDaemonsT struct{}

func (noDaemonsT) ReloadInbound(int)        {}
func (noDaemonsT) Kick(string)              {}
func (noDaemonsT) Online() map[string]int64 { return map[string]int64{} }

// certReloader serves the certificate from disk and picks up renewals (certbot, acme.sh)
// without a restart.
type certReloader struct {
	crt, key string
	mu       sync.Mutex
	mt       time.Time
	cert     *tls.Certificate
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := os.Stat(c.crt)
	if err != nil {
		return nil, err
	}
	if c.cert == nil || st.ModTime() != c.mt {
		cert, err := tls.LoadX509KeyPair(c.crt, c.key)
		if err != nil {
			if c.cert != nil {
				return c.cert, nil
			}
			return nil, err
		}
		c.cert, c.mt = &cert, st.ModTime()
	}
	return c.cert, nil
}

// info prints the panel's port and base path without modifying anything (safe while the panel runs).
func info(args []string) error {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	d := parseDirs(fs)
	fs.Parse(args)
	st, err := OpenStore(filepath.Join(d.data, "state.json"))
	if err != nil {
		return err
	}
	defer st.Close()
	st.mu.RLock()
	defer st.mu.RUnlock()
	port := st.st.Global.Port
	if port == 0 {
		port = 2096
	}
	fmt.Printf("panel port: %d  base path: %s\n", port, st.st.Global.BasePath)
	return nil
}
