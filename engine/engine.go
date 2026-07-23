// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Package engine defines the public contract every tool engine exposes to hosts:
// the JS API version and the serialization envelope an embedding host persists
// (a Tiptap node, a workspace artifact, any document). Engines are models only;
// hosts own presentation, storage, and collaboration. See docs/ENGINE-API.md.
package engine

import (
	"encoding/json"
	"errors"
	"fmt"
)

// APIVersion is the semver of the JS-facing engine API (the tamperEngines
// namespace). Additive changes bump minor; breaking changes bump major and keep
// the old major mounted alongside during a deprecation window.
const APIVersion = "1.1.0"

// EnvelopeVersion is the version of the serialized Doc format.
const EnvelopeVersion = 1

// Doc is what a host persists for an embedded tool: the tool id, the data
// source, and an opaque tool-owned view config (cursor, encoding, recipe chain).
// Exactly one of Src.Inline and Src.Ref is set.
type Doc struct {
	V    int             `json:"v"`
	Tool string          `json:"tool"`
	Src  Source          `json:"src"`
	View json.RawMessage `json:"view,omitempty"`
}

// Source carries the artifact bytes inline (base64 in JSON) or points at a
// tamper.space workspace artifact. Engines never fetch: resolving a Ref to
// bytes is the host's job.
type Source struct {
	Inline []byte `json:"inline,omitempty"`
	Ref    *Ref   `json:"ref,omitempty"`
}

// MarshalJSON emits exactly the set field, keeping an empty (but valid) inline
// buffer distinguishable from an absent one, which omitempty would drop.
func (s Source) MarshalJSON() ([]byte, error) {
	if s.Ref != nil {
		return json.Marshal(struct {
			Ref *Ref `json:"ref"`
		}{s.Ref})
	}
	return json.Marshal(struct {
		Inline []byte `json:"inline"`
	}{s.Inline})
}

// Ref addresses a workspace artifact. Version 0 means latest.
type Ref struct {
	Workspace string `json:"workspace"`
	Artifact  string `json:"artifact"`
	Version   int    `json:"version,omitempty"`
}

var (
	ErrVersion = errors.New("engine: unsupported envelope version")
	ErrSource  = errors.New("engine: source must set exactly one of inline and ref")
)

// Validate checks structural invariants; it does not resolve refs.
func (d *Doc) Validate() error {
	if d.V != EnvelopeVersion {
		return fmt.Errorf("%w: %d", ErrVersion, d.V)
	}
	if d.Tool == "" {
		return errors.New("engine: tool is required")
	}
	hasInline := d.Src.Inline != nil
	hasRef := d.Src.Ref != nil
	if hasInline == hasRef {
		return ErrSource
	}
	if hasRef && (d.Src.Ref.Workspace == "" || d.Src.Ref.Artifact == "") {
		return errors.New("engine: ref requires workspace and artifact")
	}
	return nil
}

// New builds an inline-source Doc for tool with the given bytes and view.
func New(tool string, data []byte, view json.RawMessage) Doc {
	if data == nil {
		data = []byte{}
	}
	return Doc{V: EnvelopeVersion, Tool: tool, Src: Source{Inline: data}, View: view}
}

// Parse decodes and validates a serialized Doc.
func Parse(b []byte) (Doc, error) {
	var d Doc
	if err := json.Unmarshal(b, &d); err != nil {
		return Doc{}, fmt.Errorf("engine: bad envelope: %w", err)
	}
	if err := d.Validate(); err != nil {
		return Doc{}, err
	}
	return d, nil
}

// Marshal encodes the Doc after validating it.
func (d Doc) Marshal() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}
