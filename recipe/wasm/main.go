//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/tamper-space/tools/core/crdt"
	"github.com/tamper-space/tools/core/ops"
)

func main() {
	api := js.Global().Get("Object").New()
	api.Set("run", js.FuncOf(run))
	api.Set("manifest", js.FuncOf(manifest))
	js.Global().Set("tamperOps", api)

	// tamperCRDT: a single collaborative document for the recipe input.
	c := js.Global().Get("Object").New()
	c.Set("init", js.FuncOf(crdtInit))
	c.Set("seed", js.FuncOf(crdtSeed))
	c.Set("loadOps", js.FuncOf(crdtLoadOps))
	c.Set("insert", js.FuncOf(crdtInsert))
	c.Set("del", js.FuncOf(crdtDelete))
	c.Set("text", js.FuncOf(crdtText))
	js.Global().Set("tamperCRDT", c)
	select {}
}

var doc *crdt.Doc

func crdtInit(_ js.Value, args []js.Value) any {
	doc = crdt.New(uint64(args[0].Int()))
	return nil
}

// crdtSeed loads initial bytes as this site's inserts, returning the ops (JSON)
// for the first participant to broadcast.
func crdtSeed(_ js.Value, args []js.Value) any {
	if doc == nil {
		return "[]"
	}
	b, _ := json.Marshal(doc.Load(toGo(args[0])))
	return string(b)
}

func crdtLoadOps(_ js.Value, args []js.Value) any {
	if doc == nil {
		return nil
	}
	var ops []crdt.Op
	if json.Unmarshal([]byte(args[0].String()), &ops) == nil {
		for _, op := range ops {
			doc.Apply(op)
		}
	}
	return nil
}

func crdtInsert(_ js.Value, args []js.Value) any {
	if doc == nil {
		return "null"
	}
	b, _ := json.Marshal(doc.InsertAt(args[0].Int(), byte(args[1].Int())))
	return string(b)
}

func crdtDelete(_ js.Value, args []js.Value) any {
	if doc == nil {
		return "null"
	}
	op, ok := doc.DeleteAt(args[0].Int())
	if !ok {
		return "null"
	}
	b, _ := json.Marshal(op)
	return string(b)
}

func crdtText(_ js.Value, _ []js.Value) any {
	if doc == nil {
		return js.Global().Get("Uint8Array").New(0)
	}
	b := doc.Bytes()
	u8 := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u8, b)
	return u8
}

func toGo(v js.Value) []byte {
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b
}

// run applies one operation: run(id, inputUint8, argsObject) -> {output} | {error}.
func run(_ js.Value, args []js.Value) any {
	a := ops.Args{}
	if len(args) > 2 && args[2].Type() == js.TypeObject {
		obj := args[2]
		keys := js.Global().Get("Object").Call("keys", obj)
		for i := 0; i < keys.Length(); i++ {
			k := keys.Index(i).String()
			a[k] = obj.Get(k).String()
		}
	}
	out, err := ops.Run(args[0].String(), toGo(args[1]), a)
	res := js.Global().Get("Object").New()
	if err != nil {
		res.Set("error", err.Error())
		return res
	}
	u8 := js.Global().Get("Uint8Array").New(len(out))
	js.CopyBytesToJS(u8, out)
	res.Set("output", u8)
	return res
}

func manifest(_ js.Value, _ []js.Value) any {
	b, _ := json.Marshal(ops.Manifest())
	return string(b)
}
