package main

import (
	"encoding/hex"
	"testing"
)

func h(s string) []byte { b, _ := hex.DecodeString(s); return b }

// Test vectors from RFC 2759 section 9.2 (User "User", password "clientPass").
func TestMSCHAPv2RFC2759(t *testing.T) {
	auth := h("5B5D7C7D7B3F2F3E3C2C602132262628")
	peer := h("21402324255E262A28295F2B3A337C7E")
	nt := h("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
	got, ok := mschapv2Verify("User", "clientPass", auth, peer, nt)
	if !ok {
		t.Fatal("NT-Response did not verify")
	}
	if got != "S=407A5589115FD0D6209F510FE9C04566932CDA56" {
		t.Fatalf("authenticator response = %s", got)
	}
	if _, ok := mschapv2Verify("User", "wrong", auth, peer, nt); ok {
		t.Fatal("wrong password verified")
	}
}

func TestMD4(t *testing.T) {
	cases := map[string]string{"": "31d6cfe0d16ae931b73c59d7e0c089c0", "abc": "a448017aaf21d8525fc10ae87aa6729d",
		"message digest": "d9130a8164549fe818874806e1c7014b"}
	for in, want := range cases {
		d := md4([]byte(in))
		if hex.EncodeToString(d[:]) != want {
			t.Errorf("md4(%q)=%x want %s", in, d, want)
		}
	}
}
