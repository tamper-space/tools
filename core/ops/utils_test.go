// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package ops

import (
	"strings"
	"testing"
)

func TestUtils(t *testing.T) {
	cases := []struct {
		id, in, want string
		args         Args
	}{
		{"defang-url", "http://evil.com/x", "hxxp[://]evil[.]com/x", nil},
		{"fang-url", "hxxp[://]evil[.]com/x", "http://evil.com/x", nil},
		{"defang-ip", "8.8.8.8", "8[.]8[.]8[.]8", nil},
		{"fang-ip", "8[.]8[.]8[.]8", "8.8.8.8", nil},
		{"count-occurrences", "abababab", "4", Args{"search": "ab"}},
		{"change-base", "255", "ff", Args{"in": "10", "out": "16"}},
		{"change-base", "ff", "255", Args{"in": "16", "out": "10"}},
		{"change-base", "1010", "10", Args{"in": "2", "out": "10"}},
		{"head", "1\n2\n3\n4\n5", "1\n2", Args{"n": "2"}},
		{"tail", "1\n2\n3\n4\n5", "4\n5", Args{"n": "2"}},
		{"take-bytes", "abcdef", "cd", Args{"start": "2", "length": "2"}},
		{"drop-bytes", "abcdef", "abef", Args{"start": "2", "length": "2"}},
		{"pad-lines", "ab", "0000ab", Args{"width": "6", "char": "0", "side": "left"}},
		{"extract-hashes", "x 900150983cd24fb0d6963f7d28e17f72 y", "900150983cd24fb0d6963f7d28e17f72", nil},
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

func TestEntropyAndFrequency(t *testing.T) {
	// All-identical input has zero entropy; mixed input is positive.
	if got := mustRun(t, "entropy", "aaaaaaaa", nil); !strings.Contains(got, "0.000000") {
		t.Errorf("entropy of uniform input = %q", got)
	}
	if got := mustRun(t, "entropy", "\x00\x01\x02\x03\x04\x05\x06\x07", nil); !strings.Contains(got, "3.000000") {
		t.Errorf("entropy of 8 distinct bytes should be 3 bits/byte, got %q", got)
	}
	freq := mustRun(t, "char-frequency", "aaab", nil)
	if !strings.Contains(freq, "0x61 a  3") {
		t.Errorf("frequency missing expected row: %q", freq)
	}
}
