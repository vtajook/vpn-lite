package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

var gzPool = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}

type gzWriter struct {
	http.ResponseWriter
	zw *gzip.Writer
}

func (g *gzWriter) Write(b []byte) (int, error) { return g.zw.Write(b) }

// bufWriter collects a whole response in memory.
type bufWriter struct {
	h    http.Header
	code int
	buf  bytes.Buffer
}

func (b *bufWriter) Header() http.Header { return b.h }
func (b *bufWriter) WriteHeader(c int) {
	if b.code == 0 {
		b.code = c
	}
}
func (b *bufWriter) Write(p []byte) (int, error) {
	if b.code == 0 {
		b.code = http.StatusOK
	}
	return b.buf.Write(p)
}

// bufferMW lets every handler answer into memory; the reply goes to the network only after the
// handler has returned. Handlers hold the store lock while they build a reply, and writing a
// multi-megabyte reply (the bot's inbound list) to a slow client under that lock would stall
// every login and all traffic accounting until the client had read it.
func bufferMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bw := &bufWriter{h: w.Header()}
		next.ServeHTTP(bw, r)
		if bw.code == 0 {
			bw.code = http.StatusOK
		}
		w.WriteHeader(bw.code)
		w.Write(bw.buf.Bytes())
	})
}

// gzipMW compresses responses for clients that ask for it (the account list and the page
// shrink ~10x). Clients that do not send Accept-Encoding, like the bot's curl, get plain bodies.
func gzipMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		zw := gzPool.Get().(*gzip.Writer)
		zw.Reset(w)
		defer func() { zw.Close(); gzPool.Put(zw) }()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Del("Content-Length")
		next.ServeHTTP(&gzWriter{ResponseWriter: w, zw: zw}, r)
	})
}
