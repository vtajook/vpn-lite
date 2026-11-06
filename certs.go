package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"time"
)

type certBundle struct {
	CaCert, CaKey, ServerCert, ServerKey, TlsCrypt string
}

func pemOf(typ string, der []byte) string {
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})))
}

// genCerts mints a CA, a server certificate and an OpenVPN tls-crypt key (static key v1).
func genCerts(cn string) (certBundle, error) {
	var out certBundle
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return out, err
	}
	serial := func() *big.Int { n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100)); return n }
	caTpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: cn + " CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(15, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return out, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(15, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return out, err
	}
	ck, _ := x509.MarshalECPrivateKey(caKey)
	sk, _ := x509.MarshalECPrivateKey(srvKey)
	out.CaCert, out.CaKey = pemOf("CERTIFICATE", caDER), pemOf("EC PRIVATE KEY", ck)
	out.ServerCert, out.ServerKey = pemOf("CERTIFICATE", srvDER), pemOf("EC PRIVATE KEY", sk)
	key := make([]byte, 256)
	rand.Read(key)
	h := hex.EncodeToString(key)
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i:i+32] + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----")
	out.TlsCrypt = b.String()
	return out, nil
}
