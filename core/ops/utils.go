// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Utility operations (recipe tranche 4 toward CyberChef parity): analysis,
// defanging, base conversion, and line/byte slicing. Standard-library only.
package ops

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// reHash matches standalone MD5 (32), SHA1 (40), and SHA256 (64) hex digests.
var reHash = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b`)

func init() {
	registerUtils()
}

func registerUtils() {
	reg(Op{ID: "entropy", Name: "Entropy", Category: "Utils", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(fmt.Sprintf("Shannon entropy: %.6f bits/byte", shannon(in))), nil
	}})
	reg(Op{ID: "char-frequency", Name: "Frequency Distribution", Category: "Utils", run: func(in []byte, a Args) ([]byte, error) {
		return charFrequency(in), nil
	}})
	reg(Op{ID: "count-occurrences", Name: "Count Occurrences", Category: "Utils", Params: []Param{
		{Name: "search", Label: "Search", Type: ParamText},
	}, run: func(in []byte, a Args) ([]byte, error) {
		s := a.Get("search")
		if s == "" {
			return []byte("0"), nil
		}
		return []byte(strconv.Itoa(strings.Count(string(in), s))), nil
	}})

	reg(Op{ID: "defang-url", Name: "Defang URL", Category: "Utils", run: func(in []byte, a Args) ([]byte, error) {
		s := strings.ReplaceAll(string(in), "://", "[://]")
		s = strings.ReplaceAll(s, ".", "[.]")
		s = strings.ReplaceAll(s, "http", "hxxp")
		s = strings.ReplaceAll(s, "HTTP", "HXXP")
		return []byte(s), nil
	}})
	reg(Op{ID: "fang-url", Name: "Fang URL", Category: "Utils", run: func(in []byte, a Args) ([]byte, error) {
		s := strings.ReplaceAll(string(in), "hxxp", "http")
		s = strings.ReplaceAll(s, "HXXP", "HTTP")
		s = strings.ReplaceAll(s, "[://]", "://")
		s = strings.ReplaceAll(s, "[.]", ".")
		return []byte(s), nil
	}})
	reg(Op{ID: "defang-ip", Name: "Defang IP Addresses", Category: "Utils", run: func(in []byte, a Args) ([]byte, error) {
		s := strings.ReplaceAll(string(in), ".", "[.]")
		s = strings.ReplaceAll(s, ":", "[:]")
		return []byte(s), nil
	}})
	reg(Op{ID: "fang-ip", Name: "Fang IP Addresses", Category: "Utils", run: func(in []byte, a Args) ([]byte, error) {
		s := strings.ReplaceAll(string(in), "[.]", ".")
		s = strings.ReplaceAll(s, "[:]", ":")
		return []byte(s), nil
	}})
	reg(Op{ID: "extract-hashes", Name: "Extract Hashes", Category: "Extractors", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(strings.Join(reToStrings(reHash.FindAll(in, -1)), "\n")), nil
	}})

	reg(Op{ID: "change-base", Name: "Change Numeric Base", Category: "Utils", Params: []Param{
		{Name: "in", Label: "Input base", Type: ParamNumber, Default: "10"},
		{Name: "out", Label: "Output base", Type: ParamNumber, Default: "16"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		inBase, outBase := a.Int("in", 10), a.Int("out", 16)
		if inBase < 2 || inBase > 36 || outBase < 2 || outBase > 36 {
			return nil, fmt.Errorf("bases must be between 2 and 36")
		}
		n, ok := new(big.Int).SetString(strings.TrimSpace(string(in)), inBase)
		if !ok {
			return nil, fmt.Errorf("input is not a valid base-%d number", inBase)
		}
		return []byte(n.Text(outBase)), nil
	}})

	reg(Op{ID: "pad-lines", Name: "Pad Lines", Category: "Text", Params: []Param{
		{Name: "width", Label: "Width", Type: ParamNumber, Default: "16"},
		{Name: "char", Label: "Character", Type: ParamText, Default: " "},
		{Name: "side", Label: "Side", Type: ParamSelect, Default: "left", Options: []string{"left", "right"}},
	}, run: func(in []byte, a Args) ([]byte, error) {
		width := a.Int("width", 16)
		pad := a.Get("char")
		if pad == "" {
			pad = " "
		}
		left := !strings.EqualFold(a.Get("side"), "right")
		lines := strings.Split(string(in), "\n")
		for i, l := range lines {
			for len([]rune(l)) < width {
				if left {
					l = pad + l
				} else {
					l = l + pad
				}
			}
			lines[i] = l
		}
		return []byte(strings.Join(lines, "\n")), nil
	}})
	reg(Op{ID: "head", Name: "Head", Category: "Text", Params: []Param{
		{Name: "n", Label: "Lines", Type: ParamNumber, Default: "10"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		return firstOrLastLines(string(in), a.Int("n", 10), true), nil
	}})
	reg(Op{ID: "tail", Name: "Tail", Category: "Text", Params: []Param{
		{Name: "n", Label: "Lines", Type: ParamNumber, Default: "10"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		return firstOrLastLines(string(in), a.Int("n", 10), false), nil
	}})

	reg(Op{ID: "take-bytes", Name: "Take Bytes", Category: "Utils", Params: []Param{
		{Name: "start", Label: "Start", Type: ParamNumber, Default: "0"},
		{Name: "length", Label: "Length", Type: ParamNumber, Default: "0"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		start := clampIndex(a.Int("start", 0), len(in))
		end := sliceEnd(start, a.Int("length", 0), len(in))
		return append([]byte(nil), in[start:end]...), nil
	}})
	reg(Op{ID: "drop-bytes", Name: "Drop Bytes", Category: "Utils", Params: []Param{
		{Name: "start", Label: "Start", Type: ParamNumber, Default: "0"},
		{Name: "length", Label: "Length", Type: ParamNumber, Default: "0"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		start := clampIndex(a.Int("start", 0), len(in))
		end := sliceEnd(start, a.Int("length", 0), len(in))
		out := append([]byte(nil), in[:start]...)
		return append(out, in[end:]...), nil
	}})
}

func shannon(in []byte) float64 {
	if len(in) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range in {
		counts[b]++
	}
	n := float64(len(in))
	var h float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func charFrequency(in []byte) []byte {
	var counts [256]int
	for _, b := range in {
		counts[b]++
	}
	type row struct {
		b byte
		c int
	}
	var rows []row
	for b := 0; b < 256; b++ {
		if counts[b] > 0 {
			rows = append(rows, row{byte(b), counts[b]})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].c > rows[j].c })
	total := float64(len(in))
	var out strings.Builder
	for _, r := range rows {
		label := "."
		if r.b >= 0x20 && r.b <= 0x7e {
			label = string(rune(r.b))
		}
		fmt.Fprintf(&out, "0x%02x %s  %d  (%.2f%%)\n", r.b, label, r.c, float64(r.c)/total*100)
	}
	return []byte(out.String())
}

func firstOrLastLines(s string, n int, head bool) []byte {
	if n < 0 {
		n = 0
	}
	lines := strings.Split(s, "\n")
	if n > len(lines) {
		n = len(lines)
	}
	if head {
		lines = lines[:n]
	} else {
		lines = lines[len(lines)-n:]
	}
	return []byte(strings.Join(lines, "\n"))
}

func clampIndex(i, n int) int {
	if i < 0 {
		return 0
	}
	if i > n {
		return n
	}
	return i
}

// sliceEnd returns the exclusive end of a [start, start+length) window clamped to
// n. length <= 0 means "to the end". The comparison is written to avoid the
// start+length integer overflow that a huge length would otherwise cause.
func sliceEnd(start, length, n int) int {
	if length > 0 && length < n-start {
		return start + length
	}
	return n
}
