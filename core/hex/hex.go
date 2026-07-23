// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package hex

import (
	"encoding/base64"
	"math"
	"strconv"
	"strings"
)

type Category uint8

const (
	CatNull Category = iota
	CatPrintable
	CatWhitespace
	CatControl
	CatHigh
)

func Categorize(b byte) Category {
	switch {
	case b == 0x00:
		return CatNull
	case b == ' ', b == '\t', b == '\n', b == '\r', b == '\v', b == '\f':
		return CatWhitespace
	case b >= 0x21 && b <= 0x7e:
		return CatPrintable
	case b >= 0x80:
		return CatHigh
	default:
		return CatControl
	}
}

type Analysis struct {
	Size       int
	Entropy    float64
	Categories []Category
}

func Analyze(data []byte) Analysis {
	cats := make([]Category, len(data))
	var counts [256]int
	for i, b := range data {
		cats[i] = Categorize(b)
		counts[b]++
	}
	return Analysis{Size: len(data), Entropy: entropy(counts[:], len(data)), Categories: cats}
}

func entropy(counts []int, n int) float64 {
	if n == 0 {
		return 0
	}
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// Find returns the offset of every occurrence of needle in data, up to max
// (max <= 0 means unlimited). When ci is true, ASCII letters match case-insensitively.
func Find(data, needle []byte, max int, ci bool) []int {
	if len(needle) == 0 || len(needle) > len(data) {
		return nil
	}
	var hits []int
	for i := 0; i+len(needle) <= len(data); i++ {
		if match(data[i:i+len(needle)], needle, ci) {
			hits = append(hits, i)
			if max > 0 && len(hits) >= max {
				break
			}
		}
	}
	return hits
}

func match(a, b []byte, ci bool) bool {
	for i := range a {
		x, y := a[i], b[i]
		if ci {
			x, y = fold(x), fold(y)
		}
		if x != y {
			return false
		}
	}
	return true
}

func fold(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// StringHit is a run of printable ASCII found by Strings.
type StringHit struct {
	Offset int
	Text   string
}

// Strings extracts runs of printable ASCII at least min bytes long, up to max
// hits (max <= 0 means unlimited).
func Strings(data []byte, min, max int) []StringHit {
	if min < 1 {
		min = 1
	}
	var hits []StringHit
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= min {
			hits = append(hits, StringHit{Offset: start, Text: string(data[start:end])})
		}
		start = -1
	}
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
		} else {
			flush(i)
			if max > 0 && len(hits) >= max {
				return hits
			}
		}
	}
	flush(len(data))
	return hits
}

// Encode renders data as text in the given format: "hex", "hexdump", "base64",
// "c", "rust", "go", "python", "json", "intelhex".
func Encode(data []byte, format string) string {
	var b strings.Builder
	switch format {
	case "hex":
		for _, x := range data {
			writeHex(&b, x)
		}
	case "base64":
		return base64.StdEncoding.EncodeToString(data)
	case "python":
		b.WriteString("b'")
		for _, x := range data {
			b.WriteString("\\x")
			writeHex(&b, x)
		}
		b.WriteByte('\'')
	case "json":
		b.WriteByte('[')
		for i, x := range data {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(strconv.Itoa(int(x)))
		}
		b.WriteByte(']')
	case "c":
		writeArray(&b, data, "unsigned char data["+strconv.Itoa(len(data))+"] = {", "\n};")
	case "rust":
		writeArray(&b, data, "pub const DATA: [u8; "+strconv.Itoa(len(data))+"] = [", "\n];")
	case "go":
		writeArray(&b, data, "data := []byte{", "\n}")
	case "hexdump":
		writeHexdump(&b, data)
	case "intelhex":
		writeIntelHex(&b, data)
	default:
		return ""
	}
	return b.String()
}

const hexdigits = "0123456789abcdef"

func writeHex(b *strings.Builder, x byte) {
	b.WriteByte(hexdigits[x>>4])
	b.WriteByte(hexdigits[x&0x0f])
}

func writeArray(b *strings.Builder, data []byte, open, close string) {
	b.WriteString(open)
	for i, x := range data {
		if i%12 == 0 {
			b.WriteString("\n    ")
		}
		b.WriteString("0x")
		writeHex(b, x)
		b.WriteByte(',')
	}
	b.WriteString(close)
}

func writeHexdump(b *strings.Builder, data []byte) {
	for off := 0; off < len(data); off += 16 {
		for i := 28; i >= 0; i -= 4 {
			b.WriteByte(hexdigits[(off>>uint(i))&0xf])
		}
		b.WriteString("  ")
		end := min(off+16, len(data))
		for i := 0; i < 16; i++ {
			if off+i < end {
				writeHex(b, data[off+i])
				b.WriteByte(' ')
			} else {
				b.WriteString("   ")
			}
			if i == 7 {
				b.WriteByte(' ')
			}
		}
		b.WriteString(" |")
		for i := off; i < end; i++ {
			if data[i] >= 0x20 && data[i] <= 0x7e {
				b.WriteByte(data[i])
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
}

func writeIntelHex(b *strings.Builder, data []byte) {
	var upper uint16
	for off := 0; off < len(data); off += 16 {
		if hi := uint16(off >> 16); hi != upper {
			upper = hi
			ihexRecord(b, 0, 0x04, []byte{byte(hi >> 8), byte(hi)})
		}
		end := min(off+16, len(data))
		ihexRecord(b, uint16(off), 0x00, data[off:end])
	}
	ihexRecord(b, 0, 0x01, nil)
}

func ihexRecord(b *strings.Builder, addr uint16, typ byte, data []byte) {
	b.WriteByte(':')
	ln := byte(len(data))
	sum := ln + byte(addr>>8) + byte(addr) + typ
	writeHex(b, ln)
	writeHex(b, byte(addr>>8))
	writeHex(b, byte(addr))
	writeHex(b, typ)
	for _, x := range data {
		writeHex(b, x)
		sum += x
	}
	writeHex(b, -sum)
	b.WriteByte('\n')
}
