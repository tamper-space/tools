// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Package ops is the catalog of recipe operations: pure byte->byte transforms
// that chain into a recipe. Each op is deterministic and self-contained so the
// whole recipe can run client-side in WebAssembly.
package ops

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

type ParamType string

const (
	ParamText   ParamType = "text"
	ParamNumber ParamType = "number"
)

type Param struct {
	Name    string    `json:"name"`
	Label   string    `json:"label"`
	Type    ParamType `json:"type"`
	Default string    `json:"default,omitempty"`
}

// Args are an operation's parameter values, keyed by Param.Name.
type Args map[string]string

func (a Args) Get(k string) string { return a[k] }
func (a Args) Int(k string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(a[k])); err == nil {
		return n
	}
	return def
}

type Op struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Params   []Param `json:"params,omitempty"`
	run      func(in []byte, a Args) ([]byte, error)
}

var (
	registry = map[string]Op{}
	order    []string
)

func reg(op Op) {
	registry[op.ID] = op
	order = append(order, op.ID)
}

// Run applies operation id to in with the given args.
func Run(id string, in []byte, a Args) ([]byte, error) {
	op, ok := registry[id]
	if !ok {
		return nil, fmt.Errorf("unknown operation %q", id)
	}
	return op.run(in, a)
}

// Manifest returns the catalog metadata (no run funcs), in registration order,
// for the UI to render the operations list and parameter inputs.
func Manifest() []Op {
	out := make([]Op, 0, len(order))
	for _, id := range order {
		out = append(out, registry[id])
	}
	return out
}

func init() {
	reg(Op{ID: "from-base64", Name: "From Base64", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return base64.StdEncoding.DecodeString(strings.TrimSpace(string(in)))
	}})
	reg(Op{ID: "to-base64", Name: "To Base64", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(base64.StdEncoding.EncodeToString(in)), nil
	}})
	reg(Op{ID: "from-hex", Name: "From Hex", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return hex.DecodeString(strings.Join(strings.Fields(string(in)), ""))
	}})
	reg(Op{ID: "to-hex", Name: "To Hex", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(hex.EncodeToString(in)), nil
	}})
	reg(Op{ID: "url-decode", Name: "URL Decode", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		s, err := url.QueryUnescape(string(in))
		return []byte(s), err
	}})
	reg(Op{ID: "url-encode", Name: "URL Encode", Category: "Encoding", run: func(in []byte, a Args) ([]byte, error) {
		return []byte(url.QueryEscape(string(in))), nil
	}})
	reg(Op{ID: "gunzip", Name: "Gunzip", Category: "Compression", run: func(in []byte, a Args) ([]byte, error) {
		r, err := gzip.NewReader(bytes.NewReader(in))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	}})
	reg(Op{ID: "gzip", Name: "Gzip", Category: "Compression", run: func(in []byte, a Args) ([]byte, error) {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		if _, err := w.Write(in); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}})
	reg(Op{ID: "xor", Name: "XOR", Category: "Cipher", Params: []Param{{Name: "key", Label: "Key", Type: ParamText}}, run: func(in []byte, a Args) ([]byte, error) {
		key := []byte(a.Get("key"))
		if len(key) == 0 {
			return in, nil
		}
		out := make([]byte, len(in))
		for i := range in {
			out[i] = in[i] ^ key[i%len(key)]
		}
		return out, nil
	}})
	reg(Op{ID: "reverse", Name: "Reverse", Category: "Transform", run: func(in []byte, a Args) ([]byte, error) {
		out := make([]byte, len(in))
		for i, b := range in {
			out[len(in)-1-i] = b
		}
		return out, nil
	}})
	reg(Op{ID: "to-upper", Name: "To Upper Case", Category: "Transform", run: func(in []byte, a Args) ([]byte, error) {
		return bytes.ToUpper(in), nil
	}})
	reg(Op{ID: "to-lower", Name: "To Lower Case", Category: "Transform", run: func(in []byte, a Args) ([]byte, error) {
		return bytes.ToLower(in), nil
	}})
}
