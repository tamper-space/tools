// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Networking, date/time, and token formats (tranche 7 toward CyberChef parity).
// Standard-library only and deterministic (no crypto/rand, which is unreliable
// under TinyGo+wasm), and IPv4 is parsed by hand to avoid the heavy net package.
package ops

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	registerFormats()
}

var reMAC = regexp.MustCompile(`(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}`)

func registerFormats() {
	// ---- networking ----
	reg(Op{ID: "ipv4-to-int", Name: "IPv4 to Integer", Category: "Networking", run: func(in []byte, a Args) ([]byte, error) {
		n, err := ipv4ToUint(strings.TrimSpace(string(in)))
		if err != nil {
			return nil, err
		}
		return []byte(strconv.FormatUint(uint64(n), 10)), nil
	}})
	reg(Op{ID: "int-to-ipv4", Name: "Integer to IPv4", Category: "Networking", run: func(in []byte, a Args) ([]byte, error) {
		n, err := strconv.ParseUint(strings.TrimSpace(string(in)), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("not a valid 32-bit integer")
		}
		return []byte(uintToIPv4(uint32(n))), nil
	}})
	reg(Op{ID: "ipv4-to-hex", Name: "IPv4 to Hex", Category: "Networking", run: func(in []byte, a Args) ([]byte, error) {
		n, err := ipv4ToUint(strings.TrimSpace(string(in)))
		if err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf("0x%08x", n)), nil
	}})
	reg(Op{ID: "extract-mac", Name: "Extract MAC Addresses", Category: "Extractors", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(strings.Join(reToStrings(reMAC.FindAll(in, -1)), "\n")), nil
	}})

	// ---- date / time ----
	reg(Op{ID: "from-unix-timestamp", Name: "From UNIX Timestamp", Category: "Date / Time", Params: []Param{
		{Name: "unit", Label: "Units", Type: ParamSelect, Default: "Seconds", Options: []string{"Seconds", "Milliseconds"}},
	}, run: func(in []byte, a Args) ([]byte, error) {
		n, err := strconv.ParseInt(strings.TrimSpace(string(in)), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("not a valid integer timestamp")
		}
		var t time.Time
		if strings.EqualFold(a.Get("unit"), "Milliseconds") {
			t = time.UnixMilli(n)
		} else {
			t = time.Unix(n, 0)
		}
		return []byte(t.UTC().Format("2006-01-02 15:04:05 UTC")), nil
	}})
	reg(Op{ID: "to-unix-timestamp", Name: "To UNIX Timestamp", Category: "Date / Time", Params: []Param{
		{Name: "unit", Label: "Units", Type: ParamSelect, Default: "Seconds", Options: []string{"Seconds", "Milliseconds"}},
	}, run: func(in []byte, a Args) ([]byte, error) {
		t, err := parseFlexibleTime(strings.TrimSpace(string(in)))
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(a.Get("unit"), "Milliseconds") {
			return []byte(strconv.FormatInt(t.UnixMilli(), 10)), nil
		}
		return []byte(strconv.FormatInt(t.Unix(), 10)), nil
	}})

	// ---- tokens ----
	reg(Op{ID: "jwt-decode", Name: "JWT Decode", Category: "Encoding", run: jwtDecode})
}

func ipv4ToUint(s string) (uint32, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("not a dotted IPv4 address")
	}
	var n uint32
	for _, p := range parts {
		oct, err := strconv.Atoi(p)
		if err != nil || oct < 0 || oct > 255 {
			return 0, fmt.Errorf("octet %q out of range", p)
		}
		n = n<<8 | uint32(oct)
	}
	return n, nil
}

func uintToIPv4(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func parseFlexibleTime(s string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02", time.RFC1123Z, time.RFC1123,
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("could not parse a date/time from %q", s)
}

// jwtDecode splits a JWT and base64url-decodes the header and payload segments
// (it does NOT verify the signature). Output is both segments, pretty-printed.
func jwtDecode(in []byte, a Args) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(string(in)), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a JWT (expected header.payload.signature)")
	}
	decode := func(seg string) (string, error) {
		raw, err := base64.RawURLEncoding.DecodeString(seg)
		if err != nil {
			return "", err
		}
		var buf bytes.Buffer
		if json.Indent(&buf, raw, "", "  ") != nil {
			return string(raw), nil // not JSON: return as-is
		}
		return buf.String(), nil
	}
	header, err := decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	payload, err := decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	return []byte("Header:\n" + header + "\n\nPayload:\n" + payload), nil
}
