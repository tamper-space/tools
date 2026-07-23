// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import (
	"encoding/hex"
	"testing"
)

func hx2b(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestAESKnownAnswers checks NIST SP 800-38A vectors (AES-128), so the wiring of
// key/IV/mode is provably correct, not just self-consistent.
func TestAESKnownAnswers(t *testing.T) {
	key := "2b7e151628aed2a6abf7158809cf4f3c"
	pt := "6bc1bee22e409f96e93d7e117393172a" // one block

	// CTR: keystream mode, no padding — full output is a known answer.
	ctr, err := Run("aes-encrypt", hx2b(t, pt), Args{"mode": "CTR", "key": key, "keyFormat": "Hex", "iv": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "ivFormat": "Hex"})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ctr); got != "874d6191b620e3261bef6864990db6ce" {
		t.Fatalf("AES-CTR = %s", got)
	}

	// CBC: first ciphertext block is independent of the padding block that follows.
	cbc, err := Run("aes-encrypt", hx2b(t, pt), Args{"mode": "CBC", "key": key, "keyFormat": "Hex", "iv": "000102030405060708090a0b0c0d0e0f", "ivFormat": "Hex"})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(cbc[:16]); got != "7649abac8119b246cee98e9b12e9197d" {
		t.Fatalf("AES-CBC block1 = %s", got)
	}
}

// TestSymmetricRoundTrips: encrypt then decrypt returns the original across every
// mode and key size, with a non-block-aligned plaintext to exercise padding.
func TestSymmetricRoundTrips(t *testing.T) {
	msg := "the quick brown fox jumps over the lazy dog!" // 44 bytes, not block-aligned
	iv16 := "000102030405060708090a0b0c0d0e0f"
	iv8 := "0001020304050607"
	nonce := "000102030405060708090a0b"

	type tc struct {
		enc, dec, key, keyFmt, iv string
		modes                     []string
	}
	cases := []tc{
		{"aes-encrypt", "aes-decrypt", "000102030405060708090a0b0c0d0e0f", "Hex", iv16, []string{"CBC", "CFB", "OFB", "CTR", "ECB"}},
		{"aes-encrypt", "aes-decrypt", "000102030405060708090a0b0c0d0e0f1011121314151617", "Hex", iv16, []string{"CBC", "CTR"}},                 // AES-192
		{"aes-encrypt", "aes-decrypt", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "Hex", iv16, []string{"CBC", "CTR"}}, // AES-256
		{"des-encrypt", "des-decrypt", "0123456789abcdef", "Hex", iv8, []string{"CBC", "CTR", "ECB"}},
		{"triple-des-encrypt", "triple-des-decrypt", "0123456789abcdef23456789abcdef010123456789abcdef", "Hex", iv8, []string{"CBC", "ECB"}},
	}
	for _, c := range cases {
		for _, mode := range c.modes {
			a := Args{"mode": mode, "key": c.key, "keyFormat": c.keyFmt, "iv": c.iv, "ivFormat": "Hex"}
			enc, err := Run(c.enc, []byte(msg), a)
			if err != nil {
				t.Fatalf("%s %s: %v", c.enc, mode, err)
			}
			dec, err := Run(c.dec, enc, a)
			if err != nil {
				t.Fatalf("%s %s: %v", c.dec, mode, err)
			}
			if string(dec) != msg {
				t.Fatalf("%s %s round trip = %q", c.enc, mode, dec)
			}
		}
	}

	// AES-GCM round trip + tamper detection (nonce, not a block IV).
	gcmArgs := Args{"mode": "GCM", "key": "000102030405060708090a0b0c0d0e0f", "keyFormat": "Hex", "iv": nonce, "ivFormat": "Hex"}
	ct, err := Run("aes-encrypt", []byte(msg), gcmArgs)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Run("aes-decrypt", ct, gcmArgs)
	if err != nil || string(back) != msg {
		t.Fatalf("GCM round trip: %v %q", err, back)
	}
	ct[0] ^= 0xff // flip a byte: authentication must fail
	if _, err := Run("aes-decrypt", ct, gcmArgs); err == nil {
		t.Fatal("GCM accepted tampered ciphertext")
	}
}

func TestRC4KnownAnswer(t *testing.T) {
	// Canonical RC4 vector: key "Key", plaintext "Plaintext".
	out, err := Run("rc4", []byte("Plaintext"), Args{"key": "Key", "keyFormat": "UTF8"})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(out); got != "bbf316e8d940af0ad3" {
		t.Fatalf("RC4 = %s", got)
	}
	// RC4 is symmetric: applying it again returns the plaintext.
	back, _ := Run("rc4", out, Args{"key": "Key", "keyFormat": "UTF8"})
	if string(back) != "Plaintext" {
		t.Fatalf("RC4 not symmetric: %q", back)
	}
}

func TestClassicCiphers(t *testing.T) {
	cases := []struct {
		id, in, want string
		args         Args
	}{
		{"rot13", "Hello, World!", "Uryyb, Jbeyq!", nil},
		{"rot13", "abc", "bcd", Args{"amount": "1"}},
		{"atbash", "abcXYZ", "zyxCBA", nil},
		{"vigenere-encode", "attackatdawn", "lxfopvefrnhr", Args{"key": "lemon"}},
		{"vigenere-decode", "lxfopvefrnhr", "attackatdawn", Args{"key": "lemon"}},
	}
	for _, c := range cases {
		out, err := Run(c.id, []byte(c.in), c.args)
		if err != nil {
			t.Fatalf("%s(%q): %v", c.id, c.in, err)
		}
		if string(out) != c.want {
			t.Errorf("%s(%q) = %q, want %q", c.id, c.in, out, c.want)
		}
	}

	// ROT47 is its own inverse after two applications; affine round-trips.
	r := mustRun(t, "rot47", "Hello, World!", nil)
	if back := mustRun(t, "rot47", r, nil); back != "Hello, World!" {
		t.Fatalf("ROT47 double = %q", back)
	}
	af := mustRun(t, "affine-encode", "Affine Cipher", Args{"a": "5", "b": "8"})
	if back := mustRun(t, "affine-decode", af, Args{"a": "5", "b": "8"}); back != "Affine Cipher" {
		t.Fatalf("affine round trip = %q", back)
	}
	if _, err := Run("affine-encode", []byte("x"), Args{"a": "2", "b": "1"}); err == nil {
		t.Fatal("affine must reject a not coprime with 26")
	}
}
