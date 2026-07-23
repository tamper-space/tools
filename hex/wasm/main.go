// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/tamper-space/tools/core/hex"
)

func main() {
	api := js.Global().Get("Object").New()
	api.Set("analyze", js.FuncOf(analyze))
	api.Set("find", js.FuncOf(find))
	api.Set("encode", js.FuncOf(encode))
	api.Set("strings", js.FuncOf(strings))
	js.Global().Set("tamperHex", api)
	select {}
}

func toGo(v js.Value) []byte {
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b
}

func analyze(_ js.Value, args []js.Value) any {
	res := hex.Analyze(toGo(args[0]))
	cats := make([]byte, len(res.Categories))
	for i, c := range res.Categories {
		cats[i] = byte(c)
	}
	jsCats := js.Global().Get("Uint8Array").New(len(cats))
	js.CopyBytesToJS(jsCats, cats)

	out := js.Global().Get("Object").New()
	out.Set("size", res.Size)
	out.Set("entropy", res.Entropy)
	out.Set("categories", jsCats)
	return out
}

func find(_ js.Value, args []js.Value) any {
	ci := len(args) > 2 && args[2].Bool()
	hits := hex.Find(toGo(args[0]), toGo(args[1]), 100000, ci)
	arr := js.Global().Get("Array").New(len(hits))
	for i, h := range hits {
		arr.SetIndex(i, h)
	}
	return arr
}

func encode(_ js.Value, args []js.Value) any {
	return hex.Encode(toGo(args[0]), args[1].String())
}

func strings(_ js.Value, args []js.Value) any {
	min := 4
	if len(args) > 1 {
		min = args[1].Int()
	}
	hits := hex.Strings(toGo(args[0]), min, 20000)
	arr := js.Global().Get("Array").New(len(hits))
	for i, h := range hits {
		o := js.Global().Get("Object").New()
		o.Set("offset", h.Offset)
		o.Set("text", h.Text)
		arr.SetIndex(i, o)
	}
	return arr
}
