package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// A tiny read-only SQLite file reader, just enough to read the backup (.db) files that
// the old vpn-ui panel produces: rowid tables, overflow pages, all record types. No cgo and
// no dependencies, and it never writes anything.

type sqTable struct {
	Cols []string
	Rows [][]any
}

func (t *sqTable) col(name string) int {
	for i, c := range t.Cols {
		if c == name {
			return i
		}
	}
	return -1
}

type sqDB struct {
	b      []byte
	page   int
	usable int
}

var sqliteMagic = []byte("SQLite format 3\x00")

func isSQLite(b []byte) bool { return len(b) > 100 && string(b[:16]) == string(sqliteMagic) }

func varint(b []byte) (int64, int) {
	var v uint64
	for i := 0; i < 8 && i < len(b); i++ {
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return int64(v), i + 1
		}
	}
	if len(b) >= 9 {
		v = v<<8 | uint64(b[8])
		return int64(v), 9
	}
	return 0, len(b)
}

// sqliteTables reads every table of the database.
func sqliteTables(b []byte) (map[string]*sqTable, error) {
	if !isSQLite(b) {
		return nil, fmt.Errorf("not an SQLite database")
	}
	d := &sqDB{b: b}
	d.page = int(binary.BigEndian.Uint16(b[16:18]))
	if d.page == 1 {
		d.page = 65536
	}
	d.usable = d.page - int(b[20])
	if d.page < 512 || len(b)%d.page != 0 && len(b) < d.page {
		return nil, fmt.Errorf("corrupt database header")
	}
	var master [][]any
	if err := d.walk(1, func(rowid int64, rec []any) { master = append(master, rec) }, 0); err != nil {
		return nil, err
	}
	out := map[string]*sqTable{}
	for _, m := range master {
		if len(m) < 5 || m[0] != "table" {
			continue
		}
		name, _ := m[1].(string)
		root, _ := m[3].(int64)
		sql, _ := m[4].(string)
		if name == "" || root == 0 || strings.HasPrefix(name, "sqlite_") {
			continue
		}
		t := &sqTable{Cols: sqlColumns(sql)}
		err := d.walk(int(root), func(rowid int64, rec []any) {
			row := make([]any, len(t.Cols))
			copy(row, rec)
			if len(t.Cols) > 0 && t.Cols[0] == "id" && row[0] == nil { // INTEGER PRIMARY KEY is the rowid
				row[0] = rowid
			}
			t.Rows = append(t.Rows, row)
		}, 0)
		if err != nil {
			return nil, fmt.Errorf("table %s: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}

func sqlColumns(sql string) []string {
	i := strings.Index(sql, "(")
	j := strings.LastIndex(sql, ")")
	if i < 0 || j < i {
		return nil
	}
	body := sql[i+1 : j]
	var parts []string
	depth, start := 0, 0
	for k := 0; k < len(body); k++ {
		switch body[k] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, body[start:k])
				start = k + 1
			}
		}
	}
	parts = append(parts, body[start:])
	var cols []string
	for _, p := range parts {
		f := strings.Fields(strings.TrimSpace(p))
		if len(f) == 0 {
			continue
		}
		n := strings.Trim(f[0], "`\"[]'")
		switch strings.ToUpper(n) {
		case "CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "CHECK":
			continue
		}
		cols = append(cols, n)
	}
	return cols
}

func (d *sqDB) pageBytes(n int) ([]byte, error) {
	if n < 1 || n*d.page > len(d.b) {
		return nil, fmt.Errorf("page %d out of range", n)
	}
	return d.b[(n-1)*d.page : n*d.page], nil
}

func (d *sqDB) walk(n int, fn func(int64, []any), depth int) error {
	if depth > 40 {
		return fmt.Errorf("b-tree too deep")
	}
	p, err := d.pageBytes(n)
	if err != nil {
		return err
	}
	hdr := 0
	if n == 1 {
		hdr = 100
	}
	typ := p[hdr]
	cells := int(binary.BigEndian.Uint16(p[hdr+3 : hdr+5]))
	switch typ {
	case 0x05:
		ptr := hdr + 12
		for i := 0; i < cells; i++ {
			off := int(binary.BigEndian.Uint16(p[ptr+2*i:]))
			child := int(binary.BigEndian.Uint32(p[off:]))
			if err := d.walk(child, fn, depth+1); err != nil {
				return err
			}
		}
		return d.walk(int(binary.BigEndian.Uint32(p[hdr+8:])), fn, depth+1)
	case 0x0d:
		ptr := hdr + 8
		for i := 0; i < cells; i++ {
			off := int(binary.BigEndian.Uint16(p[ptr+2*i:]))
			size, k := varint(p[off:])
			rowid, k2 := varint(p[off+k:])
			payload, err := d.payload(p[off+k+k2:], int(size))
			if err != nil {
				return err
			}
			rec, err := parseRecord(payload)
			if err != nil {
				return err
			}
			fn(rowid, rec)
		}
		return nil
	}
	return fmt.Errorf("unexpected page type %d", typ)
}

func (d *sqDB) payload(cell []byte, size int) ([]byte, error) {
	u := d.usable
	x := u - 35
	if size <= x {
		if size > len(cell) {
			return nil, fmt.Errorf("truncated cell")
		}
		return cell[:size], nil
	}
	m := ((u - 12) * 32 / 255) - 23
	k := m + ((size - m) % (u - 4))
	local := m
	if k <= x {
		local = k
	}
	if local+4 > len(cell) {
		return nil, fmt.Errorf("truncated cell")
	}
	buf := make([]byte, 0, size)
	buf = append(buf, cell[:local]...)
	next := int(binary.BigEndian.Uint32(cell[local:]))
	for len(buf) < size && next != 0 {
		p, err := d.pageBytes(next)
		if err != nil {
			return nil, err
		}
		next = int(binary.BigEndian.Uint32(p[:4]))
		chunk := p[4:u]
		if rest := size - len(buf); rest < len(chunk) {
			chunk = chunk[:rest]
		}
		buf = append(buf, chunk...)
	}
	if len(buf) != size {
		return nil, fmt.Errorf("broken overflow chain")
	}
	return buf, nil
}

func parseRecord(b []byte) ([]any, error) {
	hs, k := varint(b)
	if int(hs) > len(b) {
		return nil, fmt.Errorf("bad record header")
	}
	var types []int64
	for k < int(hs) {
		t, n := varint(b[k:])
		types = append(types, t)
		k += n
	}
	pos := int(hs)
	out := make([]any, len(types))
	need := func(n int) ([]byte, error) {
		if pos+n > len(b) {
			return nil, fmt.Errorf("truncated record")
		}
		s := b[pos : pos+n]
		pos += n
		return s, nil
	}
	for i, t := range types {
		switch {
		case t == 0:
			out[i] = nil
		case t >= 1 && t <= 6:
			n := []int{0, 1, 2, 3, 4, 6, 8}[t]
			s, err := need(n)
			if err != nil {
				return nil, err
			}
			var v int64
			if s[0]&0x80 != 0 {
				v = -1
			}
			for _, c := range s {
				v = v<<8 | int64(c)
			}
			out[i] = v
		case t == 7:
			s, err := need(8)
			if err != nil {
				return nil, err
			}
			out[i] = math.Float64frombits(binary.BigEndian.Uint64(s))
		case t == 8:
			out[i] = int64(0)
		case t == 9:
			out[i] = int64(1)
		case t >= 12 && t%2 == 0:
			s, err := need(int(t-12) / 2)
			if err != nil {
				return nil, err
			}
			out[i] = append([]byte(nil), s...)
		case t >= 13:
			s, err := need(int(t-13) / 2)
			if err != nil {
				return nil, err
			}
			out[i] = string(s)
		default:
			return nil, fmt.Errorf("bad serial type %d", t)
		}
	}
	return out, nil
}
