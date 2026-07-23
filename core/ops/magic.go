// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Magic (tranche 6 toward CyberChef parity): detect the input's likely encoding
// and preview the decode. Depth-1 detection over the encodings where a
// printable-ratio score is a reliable signal (base64/hex/base32/url/gzip/zlib/
// html). Cipher and XOR-brute guessing, and recursive multi-layer detection, are
// deliberately out: they need dictionary scoring to avoid confident-but-wrong
// output, which would be worse than none.
package ops

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

func init() {
	reg(Op{ID: "magic", Name: "Magic", Category: "Utils", run: magicRun})
}

var (
	reAllHex = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reB64    = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	reB32    = regexp.MustCompile(`^[A-Z2-7]+=*$`)
	reURLEnc = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	reHTMLE  = regexp.MustCompile(`&(#[0-9]+|#x[0-9a-fA-F]+|[a-zA-Z]+);`)
)

// magicDetector is one candidate decoding: a label, the op that performs it, and
// a predicate over the trimmed string form and the raw bytes.
type magicDetector struct {
	label, opID string
	detect      func(s string, b []byte) bool
}

var magicDetectors = []magicDetector{
	{"From Hex", "from-hex", func(s string, b []byte) bool {
		s = strings.Join(strings.Fields(s), "")
		return len(s) >= 4 && len(s)%2 == 0 && reAllHex.MatchString(s)
	}},
	{"From Base64", "from-base64", func(s string, b []byte) bool {
		return len(s) >= 8 && len(s)%4 == 0 && reB64.MatchString(s)
	}},
	{"From Base32", "from-base32", func(s string, b []byte) bool {
		return len(s) >= 8 && reB32.MatchString(s)
	}},
	{"URL Decode", "url-decode", func(s string, b []byte) bool {
		return reURLEnc.MatchString(s)
	}},
	{"From HTML Entity", "from-html-entity", func(s string, b []byte) bool {
		return reHTMLE.MatchString(s)
	}},
	{"Gunzip", "gunzip", func(s string, b []byte) bool {
		return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
	}},
	{"Zlib Inflate", "zlib-inflate", func(s string, b []byte) bool {
		return len(b) >= 2 && b[0] == 0x78 && (uint16(b[0])<<8|uint16(b[1]))%31 == 0
	}},
}

type magicHit struct {
	label   string
	opID    string
	preview string
	score   float64 // printable ratio of the decoded result
	entropy float64
}

// magicDetect runs each candidate decoder over the input and keeps the ones that
// yield confident (mostly printable) text, ranked best first. Shared by the Magic
// op (text report) and MagicSuggest (structured, for the wand UI).
func magicDetect(in []byte) []magicHit {
	var hits []magicHit
	trimmed := strings.TrimSpace(string(in))
	for _, d := range magicDetectors {
		if !d.detect(trimmed, in) {
			continue
		}
		out, err := Run(d.opID, in, nil)
		if err != nil || len(out) == 0 {
			continue
		}
		// A decoder that returns its input unchanged (e.g. From HTML Entity on
		// "AT&T; ...", where UnescapeString passes unknown entities through) has not
		// actually decoded anything, so it should not be offered as a suggestion.
		if bytes.Equal(out, in) {
			continue
		}
		score := printableRatio(out)
		prev := preview(out, 80)
		if score < 0.85 || prev == "" { // binary/garbage, or decodes to only whitespace
			continue
		}
		hits = append(hits, magicHit{d.label, d.opID, prev, score, shannon(out)})
	}
	// Rank: most printable first, then lowest entropy (more structured).
	for i := 0; i < len(hits); i++ {
		for j := i + 1; j < len(hits); j++ {
			if hits[j].score > hits[i].score || (hits[j].score == hits[i].score && hits[j].entropy < hits[i].entropy) {
				hits[i], hits[j] = hits[j], hits[i]
			}
		}
	}
	return hits
}

// MagicHit is one candidate decoding surfaced to a host: a human label, the op
// that performs it, a printable preview of the result, and a 0..1 confidence.
type MagicHit struct {
	Label   string  `json:"label"`
	OpID    string  `json:"opID"`
	Preview string  `json:"preview"`
	Score   float64 `json:"score"`
}

// MagicSuggest returns ranked candidate decodings for the input (best first), for
// an ambient "magic wand" affordance. Empty when nothing decodes confidently.
func MagicSuggest(in []byte) []MagicHit {
	hits := magicDetect(in)
	out := make([]MagicHit, 0, len(hits))
	for _, h := range hits {
		out = append(out, MagicHit{Label: h.label, OpID: h.opID, Preview: h.preview, Score: h.score})
	}
	return out
}

func magicRun(in []byte, a Args) ([]byte, error) {
	hits := magicDetect(in)

	var b strings.Builder
	fmt.Fprintf(&b, "Input: %d bytes, %.0f%% printable, entropy %.2f bits/byte\n\n", len(in), printableRatio(in)*100, shannon(in))
	switch {
	case len(hits) > 0:
		fmt.Fprintf(&b, "Best guess: %s\n\nCandidates (best first):\n", hits[0].label)
		for _, h := range hits {
			fmt.Fprintf(&b, "  %-18s printable %.0f%%  ->  %s\n", h.label, h.score*100, h.preview)
		}
	case printableRatio(in) >= 0.9:
		b.WriteString("Best guess: already plain text (no encoding detected).\n")
	default:
		b.WriteString("No confident decoding found. The input may be raw binary, encrypted, or use an encoding Magic does not detect.\n")
	}
	return []byte(b.String()), nil
}

func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var n int
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e) {
			n++
		}
	}
	return float64(n) / float64(len(b))
}

// preview returns a single-line, printable-only snippet of at most max bytes.
func preview(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			sb.WriteByte(' ')
		case c >= 0x20 && c <= 0x7e:
			sb.WriteByte(c)
		default:
			sb.WriteByte('.')
		}
	}
	return strings.TrimSpace(sb.String())
}
