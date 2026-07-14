//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/tamper-space/tools/core/ops"
)

func main() {
	api := js.Global().Get("Object").New()
	api.Set("run", js.FuncOf(run))
	api.Set("manifest", js.FuncOf(manifest))
	js.Global().Set("tamperOps", api)
	select {}
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
