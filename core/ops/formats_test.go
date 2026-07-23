// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import (
	"strings"
	"testing"
)

func TestFormats(t *testing.T) {
	cases := []struct {
		id, in, want string
		args         Args
	}{
		{"ipv4-to-int", "1.2.3.4", "16909060", nil},
		{"int-to-ipv4", "16909060", "1.2.3.4", nil},
		{"ipv4-to-hex", "1.2.3.4", "0x01020304", nil},
		{"ipv4-to-int", "255.255.255.255", "4294967295", nil},
		{"from-unix-timestamp", "0", "1970-01-01 00:00:00 UTC", nil},
		{"from-unix-timestamp", "1000000000", "2001-09-09 01:46:40 UTC", nil},
		{"to-unix-timestamp", "2001-09-09T01:46:40Z", "1000000000", nil},
		{"extract-mac", "dev 00:1b:63:84:45:e6 up", "00:1b:63:84:45:e6", nil},
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
	// Errors.
	if _, err := Run("ipv4-to-int", []byte("1.2.3"), nil); err == nil {
		t.Error("ipv4-to-int should reject a 3-octet address")
	}
	if _, err := Run("ipv4-to-int", []byte("1.2.3.999"), nil); err == nil {
		t.Error("ipv4-to-int should reject an out-of-range octet")
	}
}

func TestJWTDecode(t *testing.T) {
	// Canonical jwt.io example token (HS256).
	tok := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	out, err := Run("jwt-decode", []byte(tok), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"alg": "HS256"`) || !strings.Contains(s, `"name": "John Doe"`) {
		t.Fatalf("jwt-decode missing expected claims:\n%s", s)
	}
	if _, err := Run("jwt-decode", []byte("notatoken"), nil); err == nil {
		t.Error("jwt-decode should reject a non-JWT")
	}
}
