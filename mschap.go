package main

import (
	"crypto/des"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"strings"
	"unicode/utf16"
)

// md4 is a minimal MD4 (RFC 1320). It exists only because MS-CHAP defines the NT hash
// as MD4(UTF-16LE(password)); the standard library has no MD4.
func md4(data []byte) [16]byte {
	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)
	msg := append([]byte(nil), data...)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(data))*8)
	msg = append(msg, l[:]...)
	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	for off := 0; off < len(msg); off += 64 {
		var x [16]uint32
		for i := range x {
			x[i] = binary.LittleEndian.Uint32(msg[off+i*4:])
		}
		aa, bb, cc, dd := a, b, c, d
		r1 := [4]int{3, 7, 11, 19}
		for i := 0; i < 16; i++ {
			k := i
			t := bits.RotateLeft32(a+f(b, c, d)+x[k], r1[i%4])
			a, b, c, d = d, t, b, c
		}
		r2 := [4]int{3, 5, 9, 13}
		for i := 0; i < 16; i++ {
			k := (i%4)*4 + i/4
			t := bits.RotateLeft32(a+g(b, c, d)+x[k]+0x5a827999, r2[i%4])
			a, b, c, d = d, t, b, c
		}
		r3 := [4]int{3, 9, 11, 15}
		o3 := [16]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		for i := 0; i < 16; i++ {
			t := bits.RotateLeft32(a+h(b, c, d)+x[o3[i]]+0x6ed9eba1, r3[i%4])
			a, b, c, d = d, t, b, c
		}
		a, b, c, d = a+aa, b+bb, c+cc, d+dd
	}
	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint32(out[4:], b)
	binary.LittleEndian.PutUint32(out[8:], c)
	binary.LittleEndian.PutUint32(out[12:], d)
	return out
}

func ntHash(password string) [16]byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return md4(b)
}

// desKey expands 7 bytes into an 8-byte DES key (parity bits are ignored by crypto/des).
func desKey(k []byte) []byte {
	return []byte{k[0], k[0]<<7 | k[1]>>1, k[1]<<6 | k[2]>>2, k[2]<<5 | k[3]>>3,
		k[3]<<4 | k[4]>>4, k[4]<<3 | k[5]>>5, k[5]<<2 | k[6]>>6, k[6] << 1}
}

func challengeResponse(chal8 []byte, nt [16]byte) []byte {
	z := make([]byte, 21)
	copy(z, nt[:])
	out := make([]byte, 0, 24)
	for i := 0; i < 3; i++ {
		c, _ := des.NewCipher(desKey(z[i*7 : i*7+7]))
		blk := make([]byte, 8)
		c.Encrypt(blk, chal8)
		out = append(out, blk...)
	}
	return out
}

func stripDomain(user string) string {
	if i := strings.LastIndexByte(user, '\\'); i >= 0 {
		return user[i+1:]
	}
	return user
}

// mschapv2Verify checks an MS-CHAPv2 response (RFC 2759) and returns the
// "S=<hex>" authenticator string for MS-CHAP2-Success.
func mschapv2Verify(user, password string, authChal, peerChal, ntResp []byte) (string, bool) {
	h := sha1.New()
	h.Write(peerChal)
	h.Write(authChal)
	h.Write([]byte(stripDomain(user)))
	chal8 := h.Sum(nil)[:8]
	nt := ntHash(password)
	want := challengeResponse(chal8, nt)
	if len(ntResp) != 24 || string(want) != string(ntResp) {
		return "", false
	}
	hh := md4(nt[:])
	d := sha1.New()
	d.Write(hh[:])
	d.Write(ntResp)
	d.Write([]byte("Magic server to client signing constant"))
	digest := d.Sum(nil)
	e := sha1.New()
	e.Write(digest)
	e.Write(chal8)
	e.Write([]byte("Pad to make it do more than one iteration"))
	return "S=" + strings.ToUpper(hex.EncodeToString(e.Sum(nil))), true
}

// mschapv1Verify checks an MS-CHAP (v1) NT-Response: DES of the NT hash over the 8-byte challenge.
// Old Android versions, some modems and routers still offer only this method.
func mschapv1Verify(password string, chal, ntResp []byte) bool {
	if len(chal) != 8 || len(ntResp) != 24 {
		return false
	}
	return string(challengeResponse(chal, ntHash(password))) == string(ntResp)
}
