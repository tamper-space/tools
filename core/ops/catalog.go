// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Catalog expansion toward CyberChef parity (see tamper-space TAM-26 / the recipe
// parity plan). Tranche 1: data-format encodings, hashing, compression, bitwise
// arithmetic, text transforms, and extractors. Standard-library only, so the
// module stays dependency-free and TinyGo-clean. Symmetric/asymmetric crypto,
// flow control, and Magic detection are tracked follow-ups.
package ops

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/zlib"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"hash/crc32"
	"html"
	"io"
	"math/big"
	"mime/quotedprintable"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func init() {
	registerEncoding()
	registerHashing()
	registerCompression()
	registerBitwise()
	registerText()
	registerExtractors()
}

// ---- data format / encoding ------------------------------------------------

func registerEncoding() {
	reg(Op{ID: "to-base32", Name: "To Base32", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(base32.StdEncoding.EncodeToString(in)), nil
	}})
	reg(Op{ID: "from-base32", Name: "From Base32", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return base32.StdEncoding.DecodeString(strings.TrimSpace(string(in)))
	}})

	reg(Op{ID: "to-base58", Name: "To Base58", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(base58Encode(in)), nil
	}})
	reg(Op{ID: "from-base58", Name: "From Base58", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return base58Decode(strings.TrimSpace(string(in)))
	}})

	baseParam := Param{Name: "base", Label: "Base", Type: ParamSelect, Default: "10", Options: []string{"2", "8", "10", "16"}}
	delimParam := Param{Name: "delim", Label: "Delimiter", Type: ParamText, Default: "Space"}
	reg(Op{ID: "to-charcode", Name: "To Charcode", Category: "Encoding", Params: []Param{delimParam, baseParam}, run: func(in []byte, a Args) ([]byte, error) {
		base := a.Int("base", 10)
		if base < 2 || base > 36 {
			return nil, fmt.Errorf("base must be between 2 and 36")
		}
		sep := delimValue(a.Get("delim"))
		parts := make([]string, len(in))
		for i, b := range in {
			parts[i] = strconv.FormatInt(int64(b), base)
		}
		return []byte(strings.Join(parts, sep)), nil
	}})
	reg(Op{ID: "from-charcode", Name: "From Charcode", Category: "Encoding", Params: []Param{baseParam}, run: func(in []byte, a Args) ([]byte, error) {
		base := a.Int("base", 10)
		if base < 2 || base > 36 {
			return nil, fmt.Errorf("base must be between 2 and 36")
		}
		fields := strings.FieldsFunc(string(in), func(r rune) bool { return !isBaseDigit(r, base) })
		out := make([]byte, 0, len(fields))
		for _, f := range fields {
			n, err := strconv.ParseInt(f, base, 64)
			if err != nil {
				return nil, err
			}
			if n < 0 || n > 255 {
				return nil, fmt.Errorf("char code %d out of byte range (0-255)", n)
			}
			out = append(out, byte(n))
		}
		return out, nil
	}})

	reg(Op{ID: "to-binary", Name: "To Binary", Category: "Encoding", Params: []Param{delimParam}, run: func(in []byte, a Args) ([]byte, error) {
		sep := delimValue(a.Get("delim"))
		parts := make([]string, len(in))
		for i, b := range in {
			parts[i] = fmt.Sprintf("%08b", b)
		}
		return []byte(strings.Join(parts, sep)), nil
	}})
	reg(Op{ID: "from-binary", Name: "From Binary", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		var bitStr strings.Builder
		for _, r := range string(in) {
			if r == '0' || r == '1' {
				bitStr.WriteRune(r)
			}
		}
		bits := bitStr.String()
		if len(bits)%8 != 0 {
			return nil, fmt.Errorf("binary length %d is not a multiple of 8", len(bits))
		}
		out := make([]byte, len(bits)/8)
		for i := range out {
			n, _ := strconv.ParseUint(bits[i*8:i*8+8], 2, 8)
			out[i] = byte(n)
		}
		return out, nil
	}})

	reg(Op{ID: "to-html-entity", Name: "To HTML Entity", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(html.EscapeString(string(in))), nil
	}})
	reg(Op{ID: "from-html-entity", Name: "From HTML Entity", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(html.UnescapeString(string(in))), nil
	}})

	reg(Op{ID: "to-quoted-printable", Name: "To Quoted Printable", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		var b bytes.Buffer
		w := quotedprintable.NewWriter(&b)
		if _, err := w.Write(in); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}})
	reg(Op{ID: "from-quoted-printable", Name: "From Quoted Printable", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return io.ReadAll(quotedprintable.NewReader(bytes.NewReader(in)))
	}})
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(in []byte) string {
	if len(in) == 0 {
		return ""
	}
	var zeros int
	for zeros < len(in) && in[zeros] == 0 {
		zeros++
	}
	x := new(big.Int).SetBytes(in)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, base58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	x := new(big.Int)
	radix := big.NewInt(58)
	for _, r := range s {
		idx := strings.IndexRune(base58Alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", r)
		}
		x.Mul(x, radix)
		x.Add(x, big.NewInt(int64(idx)))
	}
	dec := x.Bytes()
	var zeros int
	for zeros < len(s) && s[zeros] == base58Alphabet[0] {
		zeros++
	}
	return append(make([]byte, zeros), dec...), nil
}

// delimArg resolves a delimiter arg, falling back to def when the arg is absent or
// blank. RunRecipe does not apply Param.Default, so flow-control ops use this to
// honor their advertised default (e.g. fork's "Line feed") instead of delimValue's
// empty-string case (which maps to a space).
func delimArg(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// delimValue maps CyberChef-style delimiter names to their literal string.
func delimValue(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "space":
		return " "
	case "comma":
		return ","
	case "semi-colon", "semicolon":
		return ";"
	case "colon":
		return ":"
	case "line feed", "newline", "lf":
		return "\n"
	case "none":
		return ""
	default:
		return name
	}
}

func isBaseDigit(r rune, base int) bool {
	_, err := strconv.ParseInt(string(r), base, 64)
	return err == nil
}

// ---- hashing ---------------------------------------------------------------

func registerHashing() {
	hashes := []struct {
		id, name string
		mk       func() hash.Hash
	}{
		{"md5", "MD5", md5.New},
		{"sha1", "SHA1", sha1.New},
		{"sha224", "SHA224", sha256.New224},
		{"sha256", "SHA256", sha256.New},
		{"sha384", "SHA384", sha512.New384},
		{"sha512", "SHA512", sha512.New},
	}
	for _, h := range hashes {
		mk := h.mk
		reg(Op{ID: h.id, Name: h.name, Category: "Hashing", run: func(in []byte, a Args) ([]byte, error) {
			d := mk()
			d.Write(in)
			return []byte(fmt.Sprintf("%x", d.Sum(nil))), nil
		}})
	}
	reg(Op{ID: "crc32", Name: "CRC-32", Category: "Hashing", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(fmt.Sprintf("%08x", crc32.ChecksumIEEE(in))), nil
	}})
	reg(Op{ID: "hmac", Name: "HMAC", Category: "Hashing", Params: []Param{
		{Name: "key", Label: "Key", Type: ParamText},
		{Name: "hash", Label: "Hashing function", Type: ParamSelect, Default: "SHA256", Options: []string{"MD5", "SHA1", "SHA256", "SHA512"}},
	}, run: func(in []byte, a Args) ([]byte, error) {
		var mk func() hash.Hash
		switch a.Get("hash") {
		case "MD5":
			mk = md5.New
		case "SHA1":
			mk = sha1.New
		case "SHA512":
			mk = sha512.New
		default:
			mk = sha256.New
		}
		mac := hmac.New(mk, []byte(a.Get("key")))
		mac.Write(in)
		return []byte(fmt.Sprintf("%x", mac.Sum(nil))), nil
	}})
}

// ---- compression -----------------------------------------------------------

func registerCompression() {
	reg(Op{ID: "zlib-deflate", Name: "Zlib Deflate", Category: "Compression", run: func(in []byte, a Args) ([]byte, error) {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		if _, err := w.Write(in); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}})
	reg(Op{ID: "zlib-inflate", Name: "Zlib Inflate", Category: "Compression", run: func(in []byte, a Args) ([]byte, error) {
		r, err := zlib.NewReader(bytes.NewReader(in))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	}})
	reg(Op{ID: "raw-deflate", Name: "Raw Deflate", Category: "Compression", run: func(in []byte, a Args) ([]byte, error) {
		var b bytes.Buffer
		w, _ := flate.NewWriter(&b, flate.DefaultCompression)
		if _, err := w.Write(in); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}})
	reg(Op{ID: "raw-inflate", Name: "Raw Inflate", Category: "Compression", run: func(in []byte, a Args) ([]byte, error) {
		r := flate.NewReader(bytes.NewReader(in))
		defer r.Close()
		return io.ReadAll(r)
	}})
	reg(Op{ID: "bzip2-decompress", Name: "Bzip2 Decompress", Category: "Compression", run: func(in []byte, a Args) ([]byte, error) {
		return io.ReadAll(bzip2.NewReader(bytes.NewReader(in)))
	}})
}

// ---- bitwise / arithmetic --------------------------------------------------

func registerBitwise() {
	keyParam := Param{Name: "key", Label: "Key (hex)", Type: ParamText}
	perByte := func(fn func(b, k byte) byte) func([]byte, Args) ([]byte, error) {
		return func(in []byte, a Args) ([]byte, error) {
			key, err := parseHexLoose(a.Get("key"))
			if err != nil {
				return nil, err
			}
			if len(key) == 0 {
				return in, nil
			}
			out := make([]byte, len(in))
			for i := range in {
				out[i] = fn(in[i], key[i%len(key)])
			}
			return out, nil
		}
	}
	reg(Op{ID: "and", Name: "AND", Category: "Bitwise", Params: []Param{keyParam}, run: perByte(func(b, k byte) byte { return b & k })})
	reg(Op{ID: "or", Name: "OR", Category: "Bitwise", Params: []Param{keyParam}, run: perByte(func(b, k byte) byte { return b | k })})
	reg(Op{ID: "add", Name: "ADD", Category: "Bitwise", Params: []Param{keyParam}, run: perByte(func(b, k byte) byte { return b + k })})
	reg(Op{ID: "sub", Name: "SUB", Category: "Bitwise", Params: []Param{keyParam}, run: perByte(func(b, k byte) byte { return b - k })})
	reg(Op{ID: "not", Name: "NOT", Category: "Bitwise", run: func(in []byte, a Args) ([]byte, error) {
		out := make([]byte, len(in))
		for i, b := range in {
			out[i] = ^b
		}
		return out, nil
	}})
	amount := Param{Name: "amount", Label: "Amount", Type: ParamNumber, Default: "1"}
	reg(Op{ID: "rotate-left", Name: "Rotate Left", Category: "Bitwise", Params: []Param{amount}, run: func(in []byte, a Args) ([]byte, error) {
		n := a.Int("amount", 1) & 7
		out := make([]byte, len(in))
		for i, b := range in {
			out[i] = b<<n | b>>(8-n)
		}
		return out, nil
	}})
	reg(Op{ID: "rotate-right", Name: "Rotate Right", Category: "Bitwise", Params: []Param{amount}, run: func(in []byte, a Args) ([]byte, error) {
		n := a.Int("amount", 1) & 7
		out := make([]byte, len(in))
		for i, b := range in {
			out[i] = b>>n | b<<(8-n)
		}
		return out, nil
	}})
}

func parseHexLoose(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, s)
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex key has odd length")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		n, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(n)
	}
	return out, nil
}

// ---- text transforms -------------------------------------------------------

func registerText() {
	reg(Op{ID: "find-replace", Name: "Find / Replace", Category: "Text", Params: []Param{
		{Name: "find", Label: "Find", Type: ParamText},
		{Name: "replace", Label: "Replace", Type: ParamText},
		{Name: "regex", Label: "Regex", Type: ParamBool, Default: "false"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		find := a.Get("find")
		if find == "" {
			return in, nil
		}
		if a.Bool("regex") {
			re, err := regexp.Compile(find)
			if err != nil {
				return nil, err
			}
			return re.ReplaceAll(in, []byte(a.Get("replace"))), nil
		}
		return bytes.ReplaceAll(in, []byte(find), []byte(a.Get("replace"))), nil
	}})
	reg(Op{ID: "remove-whitespace", Name: "Remove Whitespace", Category: "Text", run: func(in []byte, a Args) ([]byte, error) {
		return bytes.Map(func(r rune) rune {
			switch r {
			case ' ', '\t', '\n', '\r', '\v', '\f':
				return -1
			}
			return r
		}, in), nil
	}})
	reg(Op{ID: "remove-null-bytes", Name: "Remove Null Bytes", Category: "Text", run: func(in []byte, a Args) ([]byte, error) {
		return bytes.ReplaceAll(in, []byte{0}, nil), nil
	}})
	reg(Op{ID: "swap-case", Name: "Swap Case", Category: "Text", run: func(in []byte, a Args) ([]byte, error) {
		out := make([]byte, len(in))
		for i, b := range in {
			switch {
			case b >= 'a' && b <= 'z':
				out[i] = b - 32
			case b >= 'A' && b <= 'Z':
				out[i] = b + 32
			default:
				out[i] = b
			}
		}
		return out, nil
	}})
	reg(Op{ID: "sort-lines", Name: "Sort Lines", Category: "Text", Params: []Param{
		{Name: "reverse", Label: "Reverse", Type: ParamBool, Default: "false"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		lines := strings.Split(string(in), "\n")
		sort.Strings(lines)
		if a.Bool("reverse") {
			for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
				lines[i], lines[j] = lines[j], lines[i]
			}
		}
		return []byte(strings.Join(lines, "\n")), nil
	}})
	reg(Op{ID: "unique-lines", Name: "Unique Lines", Category: "Text", run: func(in []byte, a Args) ([]byte, error) {
		seen := map[string]struct{}{}
		var out []string
		for _, l := range strings.Split(string(in), "\n") {
			if _, ok := seen[l]; ok {
				continue
			}
			seen[l] = struct{}{}
			out = append(out, l)
		}
		return []byte(strings.Join(out, "\n")), nil
	}})
	reg(Op{ID: "filter-lines", Name: "Filter Lines", Category: "Text", Params: []Param{
		{Name: "regex", Label: "Regex", Type: ParamText},
		{Name: "invert", Label: "Invert", Type: ParamBool, Default: "false"},
	}, run: func(in []byte, a Args) ([]byte, error) {
		re, err := regexp.Compile(a.Get("regex"))
		if err != nil {
			return nil, err
		}
		invert := a.Bool("invert")
		var out []string
		for _, l := range strings.Split(string(in), "\n") {
			if re.MatchString(l) != invert {
				out = append(out, l)
			}
		}
		return []byte(strings.Join(out, "\n")), nil
	}})
	reg(Op{ID: "reverse-lines", Name: "Reverse Lines", Category: "Text", run: func(in []byte, a Args) ([]byte, error) {
		lines := strings.Split(string(in), "\n")
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
		return []byte(strings.Join(lines, "\n")), nil
	}})
}

// ---- extractors ------------------------------------------------------------

var (
	reIPv4  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reURL   = regexp.MustCompile(`https?://[^\s"'<>]+`)
)

func registerExtractors() {
	extractWith := func(re *regexp.Regexp) func([]byte, Args) ([]byte, error) {
		return func(in []byte, a Args) ([]byte, error) {
			return []byte(strings.Join(reToStrings(re.FindAll(in, -1)), "\n")), nil
		}
	}
	reg(Op{ID: "extract-ip", Name: "Extract IP Addresses", Category: "Extractors", run: extractWith(reIPv4)})
	reg(Op{ID: "extract-email", Name: "Extract Email Addresses", Category: "Extractors", run: extractWith(reEmail)})
	reg(Op{ID: "extract-urls", Name: "Extract URLs", Category: "Extractors", run: extractWith(reURL)})
	reg(Op{ID: "regex-extract", Name: "Regular Expression", Category: "Extractors", Params: []Param{
		{Name: "regex", Label: "Regex", Type: ParamText},
	}, run: func(in []byte, a Args) ([]byte, error) {
		re, err := regexp.Compile(a.Get("regex"))
		if err != nil {
			return nil, err
		}
		return []byte(strings.Join(reToStrings(re.FindAll(in, -1)), "\n")), nil
	}})
}

func reToStrings(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}
