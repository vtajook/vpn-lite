package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Event log: a ring buffer for the UI plus an append-only file with size-based rotation.
// Every login, rejection, disconnect and eviction is recorded with its reason, which is
// what makes "why did my customers drop?" answerable after the fact.
type Event struct {
	T      int64  `json:"t"` // unix ms
	Kind   string `json:"kind"`
	Proto  string `json:"proto"`
	Email  string `json:"email"`
	Detail string `json:"detail"`
}

type eventLog struct {
	mu   sync.Mutex
	ring []Event
	pos  int
	full bool
	f    *os.File
	path string
	size int64
}

var Events = &eventLog{ring: make([]Event, 2000)}

func (l *eventLog) Open(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.path = path
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		l.f = f
		if st, e := f.Stat(); e == nil {
			l.size = st.Size()
		}
	}
}

func (l *eventLog) Add(kind, proto, email, format string, a ...any) {
	e := Event{T: nowMs(), Kind: kind, Proto: proto, Email: email, Detail: fmt.Sprintf(format, a...)}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ring[l.pos] = e
	l.pos = (l.pos + 1) % len(l.ring)
	if l.pos == 0 {
		l.full = true
	}
	if l.f != nil {
		line := fmt.Sprintf("%s %-10s %-8s %-24s %s\n", time.UnixMilli(e.T).UTC().Format("2006-01-02T15:04:05Z"), kind, proto, email, e.Detail)
		n, _ := l.f.WriteString(line)
		l.size += int64(n)
		if l.size > 20<<20 { // rotate at 20 MB, keep one old file
			l.f.Close()
			os.Rename(l.path, l.path+".1")
			l.f, _ = os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			l.size = 0
		}
	}
}

// Recent returns up to n events, newest first, optionally filtered by email substring/kind.
func (l *eventLog) Recent(n int, email, kind string) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	total := l.pos
	if l.full {
		total = len(l.ring)
	}
	out := []Event{}
	for i := 0; i < total && len(out) < n; i++ {
		idx := (l.pos - 1 - i + len(l.ring)) % len(l.ring)
		e := l.ring[idx]
		if email != "" && !containsFold(e.Email, email) {
			continue
		}
		if kind != "" && e.Kind != kind {
			continue
		}
		out = append(out, e)
	}
	return out
}
