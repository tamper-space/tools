// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// More data-format encodings (recipe tranche 3 toward CyberChef parity):
// URL-safe base64, Ascii85, base62, unicode escaping, UTF-16, and title case.
// Standard-library only.
package ops

import (
	"encoding/ascii85"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf16"
)

func init() {
	registerEncoding2()
}

func registerEncoding2() {
	reg(Op{ID: "to-base64-url", Name: "To Base64 (URL safe)", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(base64.URLEncoding.EncodeToString(in)), nil
	}})
	reg(Op{ID: "from-base64-url", Name: "From Base64 (URL safe)", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		s := strings.TrimSpace(string(in))
		if enc := pickURLB64(s); enc != nil {
			return enc.DecodeString(s)
		}
		return base64.RawURLEncoding.DecodeString(s)
	}})

	reg(Op{ID: "to-base85", Name: "To Base85 (Ascii85)", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		buf := make([]byte, ascii85.MaxEncodedLen(len(in)))
		n := ascii85.Encode(buf, in)
		return buf[:n], nil
	}})
	reg(Op{ID: "from-base85", Name: "From Base85 (Ascii85)", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		// Decode writes a full 4-byte group at a time, so the final partial group
		// needs slack past len(in); +4 covers the last group's rounding.
		dst := make([]byte, len(in)+4)
		ndst, _, err := ascii85.Decode(dst, in, true)
		if err != nil {
			return nil, err
		}
		return dst[:ndst], nil
	}})

	reg(Op{ID: "to-base62", Name: "To Base62", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(base62Encode(in)), nil
	}})
	reg(Op{ID: "from-base62", Name: "From Base62", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return base62Decode(strings.TrimSpace(string(in)))
	}})

	reg(Op{ID: "escape-unicode", Name: "Escape Unicode", Category: "Encoding", Params: []Param{
		{Name: "all", Label: "Escape all chars", Type: ParamBool, Default: "false"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		return escapeUnicode(in, a.Bool("all")), nil
	}})
	reg(Op{ID: "unescape-unicode", Name: "Unescape Unicode", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return unescapeUnicode(in), nil
	}})

	endian := Param{Name: "endian", Label: "Byte order", Type: ParamSelect, Default: "LE", Options: []string{"LE", "BE"}}
	reg(Op{ID: "utf16-encode", Name: "Encode UTF-16", Category: "Encoding", Params: []Param{endian}, run: func(in []byte, a Args) ([]byte, error) {
		units := utf16.Encode([]rune(string(in)))
		be := strings.EqualFold(a.Get("endian"), "BE")
		out := make([]byte, len(units)*2)
		for i, u := range units {
			if be {
				out[i*2], out[i*2+1] = byte(u>>8), byte(u)
			} else {
				out[i*2], out[i*2+1] = byte(u), byte(u>>8)
			}
		}
		return out, nil
	}})
	reg(Op{ID: "utf16-decode", Name: "Decode UTF-16", Category: "Encoding", Params: []Param{endian}, run: func(in []byte, a Args) ([]byte, error) {
		if len(in)%2 != 0 {
			return nil, fmt.Errorf("UTF-16 input must be an even number of bytes")
		}
		be := strings.EqualFold(a.Get("endian"), "BE")
		units := make([]uint16, len(in)/2)
		for i := range units {
			if be {
				units[i] = uint16(in[i*2])<<8 | uint16(in[i*2+1])
			} else {
				units[i] = uint16(in[i*2+1])<<8 | uint16(in[i*2])
			}
		}
		return []byte(string(utf16.Decode(units))), nil
	}})

	reg(Op{ID: "title-case", Name: "To Title Case", Category: "Text", run: func(in []byte, a Args) ([]byte, error) {
		out := make([]byte, len(in))
		prevLetter := false
		for i, b := range in {
			isLetter := (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
			switch {
			case isLetter && !prevLetter && b >= 'a' && b <= 'z':
				out[i] = b - 32
			case isLetter && prevLetter && b >= 'A' && b <= 'Z':
				out[i] = b + 32
			default:
				out[i] = b
			}
			prevLetter = isLetter
		}
		return out, nil
	}})
}

// pickURLB64 chooses the padded URL encoding when the string is correctly padded,
// so both padded and unpadded inputs decode (the unpadded fallback is in the op).
func pickURLB64(s string) *base64.Encoding {
	if len(s)%4 == 0 && strings.HasSuffix(s, "=") {
		return base64.URLEncoding
	}
	if len(s)%4 == 0 && !strings.Contains(s, "=") {
		return base64.URLEncoding
	}
	return nil
}

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func base62Encode(in []byte) string {
	if len(in) == 0 {
		return ""
	}
	var zeros int
	for zeros < len(in) && in[zeros] == 0 {
		zeros++
	}
	x := new(big.Int).SetBytes(in)
	radix := big.NewInt(62)
	mod := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, radix, mod)
		out = append(out, base62Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, base62Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base62Decode(s string) ([]byte, error) {
	x := new(big.Int)
	radix := big.NewInt(62)
	for _, r := range s {
		idx := strings.IndexRune(base62Alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base62 character %q", r)
		}
		x.Mul(x, radix)
		x.Add(x, big.NewInt(int64(idx)))
	}
	var zeros int
	for zeros < len(s) && s[zeros] == base62Alphabet[0] {
		zeros++
	}
	return append(make([]byte, zeros), x.Bytes()...), nil
}

// escapeUnicode emits \uXXXX per UTF-16 code unit (so astral chars become surrogate
// pairs). By default only non-printable/non-ASCII units are escaped; all=true
// escapes every unit.
func escapeUnicode(in []byte, all bool) []byte {
	var b strings.Builder
	for _, u := range utf16.Encode([]rune(string(in))) {
		if all || u < 0x20 || u > 0x7e {
			fmt.Fprintf(&b, "\\u%04x", u)
		} else {
			b.WriteByte(byte(u))
		}
	}
	return []byte(b.String())
}

// unescapeUnicode reverses escapeUnicode. Consecutive \uXXXX are decoded together
// so surrogate pairs recombine; other bytes pass through unchanged.
func unescapeUnicode(in []byte) []byte {
	s := string(in)
	var out strings.Builder
	for i := 0; i < len(s); {
		if isUnicodeEsc(s, i) {
			var units []uint16
			for isUnicodeEsc(s, i) {
				n, _ := strconv.ParseUint(s[i+2:i+6], 16, 16)
				units = append(units, uint16(n))
				i += 6
			}
			out.WriteString(string(utf16.Decode(units)))
		} else {
			out.WriteByte(s[i])
			i++
		}
	}
	return []byte(out.String())
}

func isUnicodeEsc(s string, i int) bool {
	if i+6 > len(s) || s[i] != '\\' || s[i+1] != 'u' {
		return false
	}
	for _, c := range s[i+2 : i+6] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
