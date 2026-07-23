// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privPKCS1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	pubPKCS1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))
	pkixBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPKIX := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixBytes}))

	msg := []byte("attack at dawn")

	// Encrypt/decrypt round trips: OAEP and PKCS1v15, and a PKIX public key.
	for _, tc := range []struct{ pad, pub string }{
		{"OAEP", pubPKCS1}, {"PKCS1v15", pubPKCS1}, {"OAEP", pubPKIX},
	} {
		ct, err := Run("rsa-encrypt", msg, Args{"key": tc.pub, "padding": tc.pad, "hash": "SHA256"})
		if err != nil {
			t.Fatalf("encrypt %s: %v", tc.pad, err)
		}
		pt, err := Run("rsa-decrypt", ct, Args{"key": privPKCS1, "padding": tc.pad, "hash": "SHA256"})
		if err != nil {
			t.Fatalf("decrypt %s: %v", tc.pad, err)
		}
		if string(pt) != string(msg) {
			t.Fatalf("%s round trip = %q", tc.pad, pt)
		}
	}

	// Sign/verify: PKCS1v15 and PSS; a tampered message must fail.
	for _, scheme := range []string{"PKCS1v15", "PSS"} {
		sig, err := Run("rsa-sign", msg, Args{"key": privPKCS1, "scheme": scheme, "hash": "SHA256"})
		if err != nil {
			t.Fatalf("sign %s: %v", scheme, err)
		}
		v := Args{"key": pubPKCS1, "scheme": scheme, "hash": "SHA256", "signature": hex.EncodeToString(sig), "sigFormat": "Hex"}
		if out, err := Run("rsa-verify", msg, v); err != nil || string(out) != "Signature valid." {
			t.Fatalf("verify %s: out=%q err=%v", scheme, out, err)
		}
		if _, err := Run("rsa-verify", []byte("tampered"), v); err == nil {
			t.Fatalf("verify %s accepted a tampered message", scheme)
		}
	}

	// Clear errors on bad keys.
	if _, err := Run("rsa-encrypt", msg, Args{"key": "not a pem", "padding": "OAEP"}); err == nil {
		t.Fatal("expected error on invalid public key")
	}
}
