// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import "testing"

// run is a test helper: apply op id to input with args, expect output or an error.
func mustRun(t *testing.T, id, in string, a Args) string {
	t.Helper()
	out, err := Run(id, []byte(in), a)
	if err != nil {
		t.Fatalf("%s(%q): %v", id, in, err)
	}
	return string(out)
}

func TestCatalogVectors(t *testing.T) {
	cases := []struct {
		id, in, want string
		args         Args
	}{
		// Encoding (known values).
		{"to-base32", "foobar", "MZXW6YTBOI======", nil},
		{"from-base32", "MZXW6YTBOI======", "foobar", nil},
		{"to-base58", "hello", "Cn8eVZg", nil},
		{"from-base58", "Cn8eVZg", "hello", nil},
		{"to-binary", "A", "01000001", nil},
		{"from-binary", "01000001 01000010", "AB", nil},
		{"to-charcode", "AB", "65 66", nil},
		{"to-charcode", "AB", "41 42", Args{"base": "16"}},
		{"from-charcode", "41 42", "AB", Args{"base": "16"}},
		{"to-html-entity", "<a href=\"x\">", "&lt;a href=&#34;x&#34;&gt;", nil},
		{"from-html-entity", "&lt;a&gt;&amp;", "<a>&", nil},
		{"to-quoted-printable", "café", "caf=C3=A9", nil},

		// Hashing (canonical digests of "abc").
		{"md5", "abc", "900150983cd24fb0d6963f7d28e17f72", nil},
		{"sha1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d", nil},
		{"sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", nil},
		{"crc32", "abc", "352441c2", nil},
		// HMAC-SHA256 of "" with key "key" is a fixed known value.
		{"hmac", "", "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0", Args{"key": "key", "hash": "SHA256"}},

		// Bitwise.
		{"not", "\x00\xff", "\xff\x00", nil},
		{"add", "AB", "BC", Args{"key": "01"}},
		{"sub", "BC", "AB", Args{"key": "01"}},
		{"rotate-left", "\x01", "\x02", Args{"amount": "1"}},
		{"rotate-right", "\x02", "\x01", Args{"amount": "1"}},
		{"and", "\xff", "\x0f", Args{"key": "0f"}},

		// Text.
		{"find-replace", "aXbXc", "a-b-c", Args{"find": "X", "replace": "-"}},
		{"find-replace", "a1b22c", "a_b_c", Args{"find": `\d+`, "replace": "_", "regex": "true"}},
		{"remove-whitespace", "a b\tc\n", "abc", nil},
		{"swap-case", "AbC", "aBc", nil},
		{"sort-lines", "b\na\nc", "a\nb\nc", nil},
		{"unique-lines", "a\na\nb\na", "a\nb", nil},
		{"reverse-lines", "a\nb\nc", "c\nb\na", nil},
		{"filter-lines", "foo\nbar\nfoobar", "foo\nfoobar", Args{"regex": "foo"}},
		{"filter-lines", "foo\nbar\nfoobar", "bar", Args{"regex": "foo", "invert": "true"}},

		// Extractors.
		{"extract-ip", "host 10.0.0.1 and 8.8.8.8!", "10.0.0.1\n8.8.8.8", nil},
		{"extract-email", "a@b.com, c@d.org", "a@b.com\nc@d.org", nil},
		{"extract-urls", "see https://x.io/p and nope", "https://x.io/p", nil},
		{"regex-extract", "a1b2c3", "1\n2\n3", Args{"regex": `\d`}},
	}
	for _, c := range cases {
		if got := mustRun(t, c.id, c.in, c.args); got != c.want {
			t.Errorf("%s(%q, %v) = %q, want %q", c.id, c.in, c.args, got, c.want)
		}
	}
}

// TestCompressionRoundTrips: each codec's compress/decompress (or gzip's) is its
// own inverse. bzip2 is decompress-only in the stdlib, so it rides gzip's data
// through a fixed fixture instead.
func TestCompressionRoundTrips(t *testing.T) {
	msg := "the quick brown fox jumps over the lazy dog, twice: the quick brown fox"
	pairs := [][2]string{
		{"gzip", "gunzip"},
		{"zlib-deflate", "zlib-inflate"},
		{"raw-deflate", "raw-inflate"},
	}
	for _, p := range pairs {
		comp, err := Run(p[0], []byte(msg), nil)
		if err != nil {
			t.Fatalf("%s: %v", p[0], err)
		}
		back := mustRun(t, p[1], string(comp), nil)
		if back != msg {
			t.Errorf("%s->%s round trip = %q", p[0], p[1], back)
		}
		if len(comp) == 0 {
			t.Errorf("%s produced no output", p[0])
		}
	}
}

func TestManifestGrew(t *testing.T) {
	m := Manifest()
	if len(m) < 45 {
		t.Fatalf("manifest has %d ops, expected the expanded catalog", len(m))
	}
	// Params must serialize with the new fields for the host to render controls.
	var sawSelect, sawBool bool
	for _, op := range m {
		for _, p := range op.Params {
			if p.Type == ParamSelect && len(p.Options) > 0 {
				sawSelect = true
			}
			if p.Type == ParamBool {
				sawBool = true
			}
		}
	}
	if !sawSelect || !sawBool {
		t.Fatalf("expected select+bool params in the catalog (select=%v bool=%v)", sawSelect, sawBool)
	}
}
