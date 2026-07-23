// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestRoundTripInline(t *testing.T) {
	d := New("hex", []byte{0xde, 0xad}, json.RawMessage(`{"offset":16}`))
	b, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tool != "hex" || !bytes.Equal(got.Src.Inline, []byte{0xde, 0xad}) {
		t.Fatalf("round trip mangled doc: %+v", got)
	}
	if string(got.View) != `{"offset":16}` {
		t.Fatalf("view mangled: %s", got.View)
	}
}

func TestRoundTripRef(t *testing.T) {
	d := Doc{V: EnvelopeVersion, Tool: "recipe", Src: Source{Ref: &Ref{Workspace: "w1", Artifact: "a1", Version: 3}}}
	b, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Src.Ref == nil || got.Src.Ref.Artifact != "a1" || got.Src.Ref.Version != 3 {
		t.Fatalf("ref mangled: %+v", got.Src.Ref)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		doc  Doc
		want error
	}{
		{"wrong version", Doc{V: 2, Tool: "hex", Src: Source{Inline: []byte{}}}, ErrVersion},
		{"no source", Doc{V: 1, Tool: "hex"}, ErrSource},
		{"both sources", Doc{V: 1, Tool: "hex", Src: Source{Inline: []byte{1}, Ref: &Ref{Workspace: "w", Artifact: "a"}}}, ErrSource},
		{"empty tool", Doc{V: 1, Src: Source{Inline: []byte{1}}}, nil},
		{"ref missing artifact", Doc{V: 1, Tool: "hex", Src: Source{Ref: &Ref{Workspace: "w"}}}, nil},
	}
	for _, c := range cases {
		err := c.doc.Validate()
		if err == nil {
			t.Errorf("%s: expected error", c.name)
			continue
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestEmptyInlineIsValid(t *testing.T) {
	b, err := New("hex", nil, nil).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatalf("empty inline doc must parse: %v", err)
	}
}
