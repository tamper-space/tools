// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

//go:build js && wasm

// Exposes the recipe engine to the browser two ways: the versioned instantiable
// API on tamperEngines.recipe (the public contract, docs/ENGINE-API.md) and the
// legacy tamperOps/tamperCRDT globals the bundled single-file UI still uses.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/tamper-space/tools/core/crdt"
	"github.com/tamper-space/tools/core/ops"
	"github.com/tamper-space/tools/engine"
	"github.com/tamper-space/tools/wasmutil"
)

const engineVersion = "0.1.0"

func main() {
	ns := wasmutil.Namespace()
	r := js.Global().Get("Object").New()
	r.Set("tool", "recipe")
	r.Set("engineVersion", engineVersion)
	caps := js.Global().Get("Array").New()
	for i, c := range []string{"ops", "crdt", "doc"} {
		caps.SetIndex(i, c)
	}
	r.Set("capabilities", caps)
	r.Set("create", js.FuncOf(create))
	ns.Set("recipe", r)

	registerLegacy()
	select {}
}

// instance is one recipe session: a CRDT input document plus the op catalog.
// The recipe chain itself (which ops, which args) is view config: the host owns
// it and persists it in the Doc envelope's view field.
type instance struct {
	doc *crdt.Doc
	fns wasmutil.Funcs
}

// create(opts): opts.site seeds the CRDT site id (defaults to 1; hosts running
// collaboration must pass their own).
func create(_ js.Value, a []js.Value) any {
	site := uint64(1)
	if len(a) > 0 && a[0].Type() == js.TypeObject && !a[0].Get("site").IsUndefined() {
		site = uint64(a[0].Get("site").Int())
	}
	inst := &instance{doc: crdt.New(site)}

	obj := js.Global().Get("Object").New()
	b := &inst.fns
	b.Bind(obj, "manifest", func(_ js.Value, _ []js.Value) any {
		out, _ := json.Marshal(ops.Manifest())
		return string(out)
	})
	b.Bind(obj, "run", func(_ js.Value, a []js.Value) any { return runOp(a) })
	b.Bind(obj, "seed", func(_ js.Value, a []js.Value) any {
		out, _ := json.Marshal(inst.doc.Load(wasmutil.ToGo(a[0])))
		return string(out)
	})
	b.Bind(obj, "loadOps", func(_ js.Value, a []js.Value) any {
		var incoming []crdt.Op
		if json.Unmarshal([]byte(a[0].String()), &incoming) == nil {
			for _, op := range incoming {
				inst.doc.Apply(op)
			}
		}
		return nil
	})
	b.Bind(obj, "insert", func(_ js.Value, a []js.Value) any {
		out, _ := json.Marshal(inst.doc.InsertAt(a[0].Int(), byte(a[1].Int())))
		return string(out)
	})
	b.Bind(obj, "del", func(_ js.Value, a []js.Value) any {
		op, ok := inst.doc.DeleteAt(a[0].Int())
		if !ok {
			return "null"
		}
		out, _ := json.Marshal(op)
		return string(out)
	})
	b.Bind(obj, "text", func(_ js.Value, _ []js.Value) any { return wasmutil.ToJS(inst.doc.Bytes()) })
	b.Bind(obj, "doc", func(_ js.Value, a []js.Value) any {
		var view json.RawMessage
		if len(a) > 0 {
			if s := wasmutil.JSONStringify(a[0]); s != "" {
				view = json.RawMessage(s)
			}
		}
		out, err := engine.New("recipe", inst.doc.Bytes(), view).Marshal()
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
		if d.Tool != "recipe" {
			return wasmutil.Err("engine: doc is for tool " + d.Tool)
		}
		o := js.Global().Get("Object").New()
		o.Set("tool", d.Tool)
		o.Set("view", wasmutil.JSONParse(string(d.View)))
		if d.Src.Ref != nil {
			r := js.Global().Get("Object").New()
			r.Set("workspace", d.Src.Ref.Workspace)
			r.Set("artifact", d.Src.Ref.Artifact)
			r.Set("version", d.Src.Ref.Version)
			o.Set("ref", r)
			o.Set("loaded", false)
			return o
		}
		inst.doc.Load(d.Src.Inline)
		o.Set("loaded", true)
		return o
	})
	b.Bind(obj, "dispose", func(_ js.Value, _ []js.Value) any { inst.fns.Release(); return nil })
	return obj
}

func runOp(a []js.Value) any {
	args := ops.Args{}
	if len(a) > 2 && a[2].Type() == js.TypeObject {
		keys := js.Global().Get("Object").Call("keys", a[2])
		for i := 0; i < keys.Length(); i++ {
			k := keys.Index(i).String()
			args[k] = a[2].Get(k).String()
		}
	}
	out, err := ops.Run(a[0].String(), wasmutil.ToGo(a[1]), args)
	res := js.Global().Get("Object").New()
	if err != nil {
		res.Set("error", err.Error())
		return res
	}
	res.Set("output", wasmutil.ToJS(out))
	return res
}

// registerLegacy keeps the pre-API globals alive for the bundled UI: stateless
// tamperOps, and tamperCRDT backed by one default document.
func registerLegacy() {
	api := js.Global().Get("Object").New()
	api.Set("run", js.FuncOf(func(_ js.Value, a []js.Value) any { return runOp(a) }))
	api.Set("manifest", js.FuncOf(func(_ js.Value, _ []js.Value) any {
		out, _ := json.Marshal(ops.Manifest())
		return string(out)
	}))
	js.Global().Set("tamperOps", api)

	var doc *crdt.Doc
	c := js.Global().Get("Object").New()
	c.Set("init", js.FuncOf(func(_ js.Value, a []js.Value) any { doc = crdt.New(uint64(a[0].Int())); return nil }))
	c.Set("seed", js.FuncOf(func(_ js.Value, a []js.Value) any {
		if doc == nil {
			return "[]"
		}
		out, _ := json.Marshal(doc.Load(wasmutil.ToGo(a[0])))
		return string(out)
	}))
	c.Set("loadOps", js.FuncOf(func(_ js.Value, a []js.Value) any {
		if doc == nil {
			return nil
		}
		var incoming []crdt.Op
		if json.Unmarshal([]byte(a[0].String()), &incoming) == nil {
			for _, op := range incoming {
				doc.Apply(op)
			}
		}
		return nil
	}))
	c.Set("insert", js.FuncOf(func(_ js.Value, a []js.Value) any {
		if doc == nil {
			return "null"
		}
		out, _ := json.Marshal(doc.InsertAt(a[0].Int(), byte(a[1].Int())))
		return string(out)
	}))
	c.Set("del", js.FuncOf(func(_ js.Value, a []js.Value) any {
		if doc == nil {
			return "null"
		}
		op, ok := doc.DeleteAt(a[0].Int())
		if !ok {
			return "null"
		}
		out, _ := json.Marshal(op)
		return string(out)
	}))
	c.Set("text", js.FuncOf(func(_ js.Value, _ []js.Value) any {
		if doc == nil {
			return js.Global().Get("Uint8Array").New(0)
		}
		return wasmutil.ToJS(doc.Bytes())
	}))
	js.Global().Set("tamperCRDT", c)
}
