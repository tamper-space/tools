// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import (
	"strings"
	"testing"
)

func TestMagic(t *testing.T) {
	mkHex := mustRun(t, "to-hex", "Hello, world!", nil)
	mkB64 := mustRun(t, "to-base64", "Hello, world!", nil)
	gz, err := Run("gzip", []byte("Hello, world! Hello, world!"), nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, input, wantGuess string
	}{
		{"hex", mkHex, "From Hex"},
		{"base64", mkB64, "From Base64"},
		{"url", "hello%20world%21", "URL Decode"},
		{"html", "a &lt;tag&gt; here", "From HTML Entity"},
	}
	for _, c := range cases {
		out := mustRun(t, "magic", c.input, nil)
		if !strings.Contains(out, "Best guess: "+c.wantGuess) {
			t.Errorf("%s: magic report did not lead with %q:\n%s", c.name, c.wantGuess, out)
		}
	}

	// gzip is detected by magic byte (binary input).
	gzReport, _ := Run("magic", gz, nil)
	if !strings.Contains(string(gzReport), "Best guess: Gunzip") {
		t.Errorf("gzip not detected:\n%s", gzReport)
	}

	// Plain text: no false decode.
	plain := mustRun(t, "magic", "just some ordinary words here", nil)
	if !strings.Contains(plain, "already plain text") {
		t.Errorf("plain text misidentified:\n%s", plain)
	}
}

func TestMagicSuggest(t *testing.T) {
	b64 := mustRun(t, "to-base64", "Hello, world!", nil)
	hits := MagicSuggest([]byte(b64))
	if len(hits) == 0 {
		t.Fatalf("expected a suggestion for base64 input")
	}
	if hits[0].OpID != "from-base64" {
		t.Errorf("best suggestion opID = %q, want from-base64", hits[0].OpID)
	}
	if hits[0].Score <= 0 || hits[0].Score > 1 {
		t.Errorf("score out of range: %v", hits[0].Score)
	}
	if !strings.Contains(hits[0].Preview, "Hello") {
		t.Errorf("preview did not show the decoded text: %q", hits[0].Preview)
	}

	// Plain text yields no confident suggestions.
	if got := MagicSuggest([]byte("just some ordinary words here")); len(got) != 0 {
		t.Errorf("plain text produced suggestions: %+v", got)
	}
}
