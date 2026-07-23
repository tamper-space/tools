// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import "testing"

func TestRun(t *testing.T) {
	cases := []struct {
		op   string
		in   string
		args Args
		want string
	}{
		{"to-base64", "hi", nil, "aGk="},
		{"from-base64", "aGk=", nil, "hi"},
		{"to-hex", "AB", nil, "4142"},
		{"from-hex", "41 42", nil, "AB"},
		{"url-encode", "a b&c", nil, "a+b%26c"},
		{"url-decode", "a+b%26c", nil, "a b&c"},
		{"reverse", "abc", nil, "cba"},
		{"to-upper", "aB", nil, "AB"},
		{"to-lower", "aB", nil, "ab"},
		{"xor", "abc", Args{"key": "\x00"}, "abc"},
	}
	for _, c := range cases {
		got, err := Run(c.op, []byte(c.in), c.args)
		if err != nil || string(got) != c.want {
			t.Errorf("Run(%q, %q) = %q, %v; want %q", c.op, c.in, got, err, c.want)
		}
	}

	// XOR is its own inverse.
	x, _ := Run("xor", []byte("secret"), Args{"key": "k"})
	back, _ := Run("xor", x, Args{"key": "k"})
	if string(back) != "secret" {
		t.Errorf("xor round-trip = %q", back)
	}

	// Gzip round-trips through gunzip.
	gz, err := Run("gzip", []byte("hello hello hello"), nil)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	un, err := Run("gunzip", gz, nil)
	if err != nil || string(un) != "hello hello hello" {
		t.Errorf("gunzip = %q, %v", un, err)
	}

	if _, err := Run("nope", nil, nil); err == nil {
		t.Errorf("unknown op should error")
	}
}

func TestManifest(t *testing.T) {
	m := Manifest()
	if len(m) < 10 {
		t.Fatalf("manifest has %d ops, want >= 10", len(m))
	}
	if m[0].ID == "" || m[0].Name == "" || m[0].Category == "" {
		t.Errorf("manifest entry missing fields: %+v", m[0])
	}
	// The XOR op advertises its key parameter.
	for _, op := range m {
		if op.ID == "xor" {
			if len(op.Params) != 1 || op.Params[0].Name != "key" {
				t.Errorf("xor params = %+v", op.Params)
			}
		}
	}
}
