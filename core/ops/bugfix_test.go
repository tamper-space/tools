// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import (
	"bytes"
	"testing"
)

// Regression tests for defects found in the recipe-engine bug audit.

// to-charcode / from-charcode: an out-of-range base fed strconv.FormatInt, which
// panics for base <2 or >36. It must return an error instead.
func TestCharcodeBaseValidation(t *testing.T) {
	for _, base := range []string{"0", "1", "37", "-5"} {
		if _, err := Run("to-charcode", []byte("AB"), Args{"base": base}); err == nil {
			t.Errorf("to-charcode base=%s: want error, got nil", base)
		}
		if _, err := Run("from-charcode", []byte("65"), Args{"base": base}); err == nil {
			t.Errorf("from-charcode base=%s: want error, got nil", base)
		}
	}
	if got := mustRun(t, "to-charcode", "AB", Args{"base": "16", "delim": "Space"}); got != "41 42" {
		t.Errorf("to-charcode base16 = %q, want %q", got, "41 42")
	}
}

// from-charcode narrowed values with byte(n), silently wrapping codes > 255.
func TestFromCharcodeRange(t *testing.T) {
	if _, err := Run("from-charcode", []byte("300 65"), Args{"base": "10"}); err == nil {
		t.Errorf("from-charcode 300: want out-of-range error, got nil")
	}
	if got := mustRun(t, "from-charcode", "72 105", Args{"base": "10"}); got != "Hi" {
		t.Errorf("from-charcode = %q, want %q", got, "Hi")
	}
}

// from-base85 sized its decode buffer at len(in)+4, but the 'z' shortcut expands one
// input char to four output bytes, so runs of zero bytes were silently truncated.
func TestBase85ZeroShortcutRoundTrip(t *testing.T) {
	for _, n := range []int{4, 8, 16, 40} {
		in := make([]byte, n) // all zero -> encodes with 'z' shortcuts
		enc := mustRun(t, "to-base85", string(in), nil)
		dec, err := Run("from-base85", []byte(enc), nil)
		if err != nil {
			t.Fatalf("from-base85(%q): %v", enc, err)
		}
		if !bytes.Equal(dec, in) {
			t.Errorf("%d zero bytes: round-tripped to %d bytes", n, len(dec))
		}
	}
	in := append(append([]byte("HDR"), make([]byte, 12)...), []byte("END")...)
	enc := mustRun(t, "to-base85", string(in), nil)
	dec, err := Run("from-base85", []byte(enc), nil)
	if err != nil || !bytes.Equal(dec, in) {
		t.Errorf("mixed round-trip: got %v (err %v), want %v", dec, err, in)
	}
}

// escape-unicode left backslashes unescaped in default mode, so a literal
// backslash-u sequence decoded on the reverse pass and broke the round trip.
func TestEscapeUnicodeRoundTripBackslash(t *testing.T) {
	in := `win path C:\users and a A literal`
	esc := mustRun(t, "escape-unicode", in, nil)
	if got := mustRun(t, "unescape-unicode", esc, nil); got != in {
		t.Errorf("escape/unescape round-trip = %q, want %q (esc=%q)", got, in, esc)
	}
}

// take-bytes/drop-bytes computed start+length unguarded, overflowing for a huge
// length (panic for take, corrupted output for drop).
func TestTakeDropBytesHugeLength(t *testing.T) {
	const huge = "9223372036854775807" // MaxInt64
	if got := mustRun(t, "take-bytes", "abcdef", Args{"start": "1", "length": huge}); got != "bcdef" {
		t.Errorf("take-bytes huge length = %q, want %q", got, "bcdef")
	}
	if got := mustRun(t, "drop-bytes", "abcdef", Args{"start": "1", "length": huge}); got != "a" {
		t.Errorf("drop-bytes huge length = %q, want %q", got, "a")
	}
}

// fork advertises a "Line feed" default, but RunRecipe does not apply Param.Default
// and delimValue maps an empty arg to a space, so an omitted delimiter split on
// spaces instead of newlines.
func TestForkDefaultDelimiterIsLineFeed(t *testing.T) {
	r := RunRecipe(steps(step("fork"), step("reverse"), step("merge")), []byte("ab\ncd"))
	if r.FailedAt != -1 {
		t.Fatalf("recipe failed at %d: %s", r.FailedAt, r.Error)
	}
	if string(r.Output) != "ba\ndc" {
		t.Errorf("fork default delim = %q, want %q", string(r.Output), "ba\ndc")
	}
}

// MagicSuggest must not offer a decoder that returns its input unchanged (a no-op
// html-entity "decode") nor one whose result is only whitespace (blank preview).
func TestMagicSuggestNoFalsePositives(t *testing.T) {
	for _, in := range []string{"AT&T; great deal here", "R&D; budget up this year"} {
		for _, h := range MagicSuggest([]byte(in)) {
			if h.OpID == "from-html-entity" {
				t.Errorf("MagicSuggest(%q) offered no-op from-html-entity: %+v", in, h)
			}
		}
	}
	for _, h := range MagicSuggest([]byte("0a0a0a0a")) {
		if h.Preview == "" {
			t.Errorf("MagicSuggest offered a blank-preview suggestion: %+v", h)
		}
	}
	// A genuine entity is still detected.
	var found bool
	for _, h := range MagicSuggest([]byte("a &lt;tag&gt; b")) {
		if h.OpID == "from-html-entity" {
			found = true
		}
	}
	if !found {
		t.Errorf("MagicSuggest dropped a real from-html-entity suggestion")
	}
}
