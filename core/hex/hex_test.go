// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package hex

import (
	"strings"
	"testing"
)

func TestCategorize(t *testing.T) {
	cases := map[byte]Category{
		0x00: CatNull,
		' ':  CatWhitespace,
		'\n': CatWhitespace,
		'A':  CatPrintable,
		'~':  CatPrintable,
		0x07: CatControl,
		0x7f: CatControl,
		0x80: CatHigh,
		0xff: CatHigh,
	}
	for b, want := range cases {
		if got := Categorize(b); got != want {
			t.Errorf("Categorize(%#x) = %d, want %d", b, got, want)
		}
	}
}

func TestAnalyze(t *testing.T) {
	a := Analyze([]byte("AAAA"))
	if a.Size != 4 {
		t.Errorf("Size = %d, want 4", a.Size)
	}
	if a.Entropy != 0 {
		t.Errorf("Entropy of uniform data = %f, want 0", a.Entropy)
	}
	if len(a.Categories) != 4 || a.Categories[0] != CatPrintable {
		t.Errorf("Categories = %v", a.Categories)
	}

	// Two equally-likely symbols -> 1 bit of entropy.
	if e := Analyze([]byte{0x00, 0xff}).Entropy; e < 0.999 || e > 1.001 {
		t.Errorf("Entropy of {00,ff} = %f, want ~1", e)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	a := Analyze(nil)
	if a.Size != 0 || a.Entropy != 0 || len(a.Categories) != 0 {
		t.Errorf("empty analysis = %+v", a)
	}
}

func TestFind(t *testing.T) {
	data := []byte("abcabcabc")
	if got := Find(data, []byte("abc"), 0, false); len(got) != 3 || got[0] != 0 || got[1] != 3 || got[2] != 6 {
		t.Errorf("Find abc = %v", got)
	}
	if got := Find(data, []byte("abc"), 2, false); len(got) != 2 {
		t.Errorf("Find with cap 2 = %v", got)
	}
	if got := Find(data, []byte("xyz"), 0, false); got != nil {
		t.Errorf("Find missing = %v", got)
	}
	if got := Find(data, nil, 0, false); got != nil {
		t.Errorf("Find empty needle = %v", got)
	}
	if got := Find([]byte("AbCabc"), []byte("abc"), 0, true); len(got) != 2 {
		t.Errorf("Find case-insensitive = %v", got)
	}
	if got := Find([]byte("AbCabc"), []byte("abc"), 0, false); len(got) != 1 {
		t.Errorf("Find case-sensitive = %v", got)
	}
}

func TestStrings(t *testing.T) {
	data := []byte{0x00, 'h', 'i', 0x00, 'a', 'b', 'c', 'd'}
	hits := Strings(data, 3, 0)
	if len(hits) != 1 || hits[0].Offset != 4 || hits[0].Text != "abcd" {
		t.Errorf("Strings = %+v", hits)
	}
	if hits := Strings(data, 2, 0); len(hits) != 2 || hits[0].Text != "hi" {
		t.Errorf("Strings min 2 = %+v", hits)
	}
	if hits := Strings(data, 2, 1); len(hits) != 1 {
		t.Errorf("Strings cap = %+v", hits)
	}
}

func TestEncode(t *testing.T) {
	data := []byte{0xde, 0xad}
	if got := Encode(data, "hex"); got != "dead" {
		t.Errorf("hex = %q", got)
	}
	if got := Encode(data, "base64"); got != "3q0=" {
		t.Errorf("base64 = %q", got)
	}
	if got := Encode(data, "python"); got != `b'\xde\xad'` {
		t.Errorf("python = %q", got)
	}
	if got := Encode(data, "c"); got == "" || got[:13] != "unsigned char" {
		t.Errorf("c = %q", got)
	}
	if got := Encode(data, "json"); got != "[222,173]" {
		t.Errorf("json = %q", got)
	}
	if got := Encode(data, "rust"); !strings.HasPrefix(got, "pub const DATA: [u8; 2] = [") {
		t.Errorf("rust = %q", got)
	}
	if got := Encode(data, "go"); !strings.HasPrefix(got, "data := []byte{") {
		t.Errorf("go = %q", got)
	}
	if got := Encode([]byte("AB"), "hexdump"); !strings.HasPrefix(got, "00000000  41 42 ") || !strings.Contains(got, "|AB|") {
		t.Errorf("hexdump = %q", got)
	}
	if got := Encode(data, "intelhex"); got != ":02000000dead73\n:00000001ff\n" {
		t.Errorf("intelhex = %q", got)
	}
	if got := Encode(data, "nope"); got != "" {
		t.Errorf("unknown format = %q", got)
	}
}
