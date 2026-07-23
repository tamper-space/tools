// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

//go:build js && wasm

// Package wasmutil is shared syscall/js glue for the tool engine shims: byte
// copies across the boundary, JSON bridging, and the versioned tamperEngines
// namespace every engine registers into.
package wasmutil

import (
	"syscall/js"

	"github.com/tamper-space/tools/engine"
)

// Namespace returns the shared tamperEngines global, creating it (stamped with
// engine.APIVersion) on first use so load order between engines is irrelevant.
func Namespace() js.Value {
	g := js.Global()
	ns := g.Get("tamperEngines")
	if ns.Type() != js.TypeObject {
		ns = g.Get("Object").New()
		ns.Set("apiVersion", engine.APIVersion)
		g.Set("tamperEngines", ns)
	}
	return ns
}

// ToGo copies a Uint8Array into Go memory.
func ToGo(v js.Value) []byte {
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b
}

// ToJS copies Go bytes into a fresh Uint8Array.
func ToJS(b []byte) js.Value {
	u8 := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u8, b)
	return u8
}

// JSONParse turns a Go-side JSON string into a JS value (undefined for "").
func JSONParse(s string) js.Value {
	if s == "" {
		return js.Undefined()
	}
	return js.Global().Get("JSON").Call("parse", s)
}

// JSONStringify serializes a JS value to JSON ("" for undefined/null).
func JSONStringify(v js.Value) string {
	if v.IsUndefined() || v.IsNull() {
		return ""
	}
	return js.Global().Get("JSON").Call("stringify", v).String()
}

// Err wraps an error message the way instance methods report failure.
func Err(msg string) js.Value {
	o := js.Global().Get("Object").New()
	o.Set("error", msg)
	return o
}

// Funcs collects js.FuncOf handles so an instance can release them on dispose.
type Funcs struct{ fns []js.Func }

// Bind registers fn as a method named name on obj and tracks it for release.
func (f *Funcs) Bind(obj js.Value, name string, fn func(js.Value, []js.Value) any) {
	jf := js.FuncOf(fn)
	f.fns = append(f.fns, jf)
	obj.Set(name, jf)
}

// Release frees every bound function; the instance is unusable afterwards.
func (f *Funcs) Release() {
	for _, fn := range f.fns {
		fn.Release()
	}
	f.fns = nil
}
