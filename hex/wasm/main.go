// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

//go:build js && wasm

// Exposes the hex engine to the browser two ways: the versioned instantiable
// API on tamperEngines.hex (the public contract, docs/ENGINE-API.md) and the
// legacy stateless tamperHex global the bundled single-file UI still uses.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/tamper-space/tools/core/hex"
	"github.com/tamper-space/tools/engine"
	"github.com/tamper-space/tools/wasmutil"
)

const engineVersion = "0.1.0"

func main() {
	ns := wasmutil.Namespace()
	h := js.Global().Get("Object").New()
	h.Set("tool", "hex")
	h.Set("engineVersion", engineVersion)
	caps := js.Global().Get("Array").New()
	for i, c := range []string{"model", "analyze", "find", "strings", "encode", "doc"} {
		caps.SetIndex(i, c)
	}
	h.Set("capabilities", caps)
	h.Set("create", js.FuncOf(create))
	ns.Set("hex", h)

	registerLegacy()
	select {}
}

// instance binds one hex.Model to a JS object. Bytes are copied at the
// boundary in both directions; mutators return null on success or {error}.
type instance struct {
	m    *hex.Model
	fns  wasmutil.Funcs
	subs map[int]js.Value
	next int
}

func create(_ js.Value, _ []js.Value) any {
	inst := &instance{m: hex.NewModel(), subs: map[int]js.Value{}}
	inst.m.OnEvent(func(e hex.Event) {
		o := js.Global().Get("Object").New()
		o.Set("type", e.Type)
		if e.Type == "bytes" {
			o.Set("offset", e.Offset)
			o.Set("length", e.Length)
		}
		for _, cb := range inst.subs {
			cb.Invoke(o)
		}
	})

	obj := js.Global().Get("Object").New()
	b := &inst.fns
	b.Bind(obj, "load", func(_ js.Value, a []js.Value) any { inst.m.Load(wasmutil.ToGo(a[0])); return nil })
	b.Bind(obj, "bytes", func(_ js.Value, _ []js.Value) any { return wasmutil.ToJS(inst.m.Bytes()) })
	b.Bind(obj, "len", func(_ js.Value, _ []js.Value) any { return inst.m.Len() })
	b.Bind(obj, "cursor", func(_ js.Value, _ []js.Value) any { return inst.m.Cursor() })
	b.Bind(obj, "setCursor", func(_ js.Value, a []js.Value) any { inst.m.SetCursor(a[0].Int()); return nil })
	b.Bind(obj, "selection", func(_ js.Value, _ []js.Value) any {
		s, e, ok := inst.m.Selection()
		if !ok {
			return nil
		}
		o := js.Global().Get("Object").New()
		o.Set("start", s)
		o.Set("end", e)
		return o
	})
	b.Bind(obj, "select", func(_ js.Value, a []js.Value) any { inst.m.Select(a[0].Int(), a[1].Int()); return nil })
	b.Bind(obj, "clearSelection", func(_ js.Value, _ []js.Value) any { inst.m.ClearSelection(); return nil })
	b.Bind(obj, "insert", func(_ js.Value, a []js.Value) any { return errOrNil(inst.m.Insert(a[0].Int(), wasmutil.ToGo(a[1]))) })
	b.Bind(obj, "del", func(_ js.Value, a []js.Value) any { return errOrNil(inst.m.Delete(a[0].Int(), a[1].Int())) })
	b.Bind(obj, "overwrite", func(_ js.Value, a []js.Value) any { return errOrNil(inst.m.Overwrite(a[0].Int(), wasmutil.ToGo(a[1]))) })
	b.Bind(obj, "analyze", func(_ js.Value, _ []js.Value) any { return analysisToJS(hex.Analyze(inst.m.Bytes())) })
	b.Bind(obj, "find", func(_ js.Value, a []js.Value) any {
		ci := len(a) > 1 && a[1].Bool()
		return intsToJS(hex.Find(inst.m.Bytes(), wasmutil.ToGo(a[0]), 100000, ci))
	})
	b.Bind(obj, "strings", func(_ js.Value, a []js.Value) any {
		min := 4
		if len(a) > 0 {
			min = a[0].Int()
		}
		return hitsToJS(hex.Strings(inst.m.Bytes(), min, 20000))
	})
	b.Bind(obj, "encode", func(_ js.Value, a []js.Value) any { return hex.Encode(inst.m.Bytes(), a[0].String()) })
	b.Bind(obj, "doc", func(_ js.Value, a []js.Value) any {
		var view json.RawMessage
		if len(a) > 0 {
			if s := wasmutil.JSONStringify(a[0]); s != "" {
				view = json.RawMessage(s)
			}
		}
		out, err := engine.New("hex", inst.m.Bytes(), view).Marshal()
		if err != nil {
			return wasmutil.Err(err.Error())
		}
		return string(out)
	})
	b.Bind(obj, "loadDoc", func(_ js.Value, a []js.Value) any {
		d, err := engine.Parse([]byte(a[0].String()))
		if err != nil {
			return wasmutil.Err(err.Error())
		}
		if d.Tool != "hex" {
			return wasmutil.Err("engine: doc is for tool " + d.Tool)
		}
		o := js.Global().Get("Object").New()
		o.Set("tool", d.Tool)
		o.Set("view", wasmutil.JSONParse(string(d.View)))
		if d.Src.Ref != nil {
			// The host resolves refs to bytes and calls load itself.
			r := js.Global().Get("Object").New()
			r.Set("workspace", d.Src.Ref.Workspace)
			r.Set("artifact", d.Src.Ref.Artifact)
			r.Set("version", d.Src.Ref.Version)
			o.Set("ref", r)
			o.Set("loaded", false)
			return o
		}
		inst.m.Load(d.Src.Inline)
		o.Set("loaded", true)
		return o
	})
	b.Bind(obj, "subscribe", func(_ js.Value, a []js.Value) any {
		inst.next++
		inst.subs[inst.next] = a[0]
		return inst.next
	})
	b.Bind(obj, "unsubscribe", func(_ js.Value, a []js.Value) any { delete(inst.subs, a[0].Int()); return nil })
	b.Bind(obj, "dispose", func(_ js.Value, _ []js.Value) any {
		inst.m.OnEvent(nil)
		inst.subs = map[int]js.Value{}
		inst.fns.Release()
		return nil
	})
	return obj
}

func errOrNil(err error) any {
	if err != nil {
		return wasmutil.Err(err.Error())
	}
	return nil
}

func analysisToJS(res hex.Analysis) js.Value {
	cats := make([]byte, len(res.Categories))
	for i, c := range res.Categories {
		cats[i] = byte(c)
	}
	out := js.Global().Get("Object").New()
	out.Set("size", res.Size)
	out.Set("entropy", res.Entropy)
	out.Set("categories", wasmutil.ToJS(cats))
	return out
}

func intsToJS(ns []int) js.Value {
	arr := js.Global().Get("Array").New(len(ns))
	for i, n := range ns {
		arr.SetIndex(i, n)
	}
	return arr
}

func hitsToJS(hits []hex.StringHit) js.Value {
	arr := js.Global().Get("Array").New(len(hits))
	for i, h := range hits {
		o := js.Global().Get("Object").New()
		o.Set("offset", h.Offset)
		o.Set("text", h.Text)
		arr.SetIndex(i, o)
	}
	return arr
}

// registerLegacy keeps the pre-API tamperHex global alive for the bundled UI.
func registerLegacy() {
	api := js.Global().Get("Object").New()
	api.Set("analyze", js.FuncOf(func(_ js.Value, a []js.Value) any { return analysisToJS(hex.Analyze(wasmutil.ToGo(a[0]))) }))
	api.Set("find", js.FuncOf(func(_ js.Value, a []js.Value) any {
		ci := len(a) > 2 && a[2].Bool()
		return intsToJS(hex.Find(wasmutil.ToGo(a[0]), wasmutil.ToGo(a[1]), 100000, ci))
	}))
	api.Set("encode", js.FuncOf(func(_ js.Value, a []js.Value) any { return hex.Encode(wasmutil.ToGo(a[0]), a[1].String()) }))
	api.Set("strings", js.FuncOf(func(_ js.Value, a []js.Value) any {
		min := 4
		if len(a) > 1 {
			min = a[1].Int()
		}
		return hitsToJS(hex.Strings(wasmutil.ToGo(a[0]), min, 20000))
	}))
	js.Global().Set("tamperHex", api)
}
