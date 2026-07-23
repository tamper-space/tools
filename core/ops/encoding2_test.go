// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import (
	"encoding/hex"
	"testing"
)

func TestEncoding2Vectors(t *testing.T) {
	cases := []struct {
		id, in, want string
		args         Args
	}{
		// URL-safe base64: bytes ff ff fe are +/ in standard, -_ url-safe.
		{"to-base64-url", "\xff\xff\xfe", "___-", nil},
		{"from-base64-url", "___-", "\xff\xff\xfe", nil},
		// Title case.
		{"title-case", "hello there, general", "Hello There, General", nil},
		// Unicode escape: default escapes only non-ASCII.
		{"escape-unicode", "café", "caf\\u00e9", nil},
		{"escape-unicode", "AB", "\\u0041\\u0042", Args{"all": "true"}},
		{"unescape-unicode", "caf\\u00e9", "café", nil},
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
}

func TestEncoding2RoundTrips(t *testing.T) {
	roundTrip := func(enc, dec string, inputs []string) {
		for _, in := range inputs {
			e, err := Run(enc, []byte(in), nil)
			if err != nil {
				t.Fatalf("%s(%q): %v", enc, in, err)
			}
			back, err := Run(dec, e, nil)
			if err != nil {
				t.Fatalf("%s(%q): %v", dec, in, err)
			}
			if string(back) != in {
				t.Errorf("%s->%s(%q) = %q", enc, dec, in, back)
			}
		}
	}
	// Byte codecs are binary-safe: leading NUL and non-UTF-8 bytes must survive.
	binary := []string{"", "hello", "\x00\x00binary\xff\xfe"}
	roundTrip("to-base85", "from-base85", binary)
	roundTrip("to-base62", "from-base62", binary)
	// Text codecs operate on runes; feed valid UTF-8 including an astral char
	// (exercises surrogate-pair handling).
	text := []string{"", "hello world", "café", "emoji 😀 mix"}
	roundTrip("escape-unicode", "unescape-unicode", text)
	roundTrip("utf16-encode", "utf16-decode", text)
}

func TestUTF16Endianness(t *testing.T) {
	le, _ := Run("utf16-encode", []byte("AB"), Args{"endian": "LE"})
	if got := hex.EncodeToString(le); got != "41004200" {
		t.Fatalf("UTF-16 LE = %s", got)
	}
	be, _ := Run("utf16-encode", []byte("AB"), Args{"endian": "BE"})
	if got := hex.EncodeToString(be); got != "00410042" {
		t.Fatalf("UTF-16 BE = %s", got)
	}
}
