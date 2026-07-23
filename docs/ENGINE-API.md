# Engine API

The public contract between the tool engines and any host that embeds them: the
tamper.space workbench (its first consumer), a Tiptap/ProseMirror NodeView, or
anything else that can load WASM. Engines are models only: bytes, cursor,
selection, transforms, events. Presentation, persistence, history, and
collaboration transport belong to the host.

## Versioning

- `tamperEngines.apiVersion` (currently `1.1.0`) is the semver of the JS surface
  described here. Additive changes bump minor. A breaking change bumps major and
  the old major stays mounted alongside for a deprecation window.
- Each engine reports its own `engineVersion`, versioning behavior (new ops, new
  encodings) independently of the API shape.
- The serialization envelope carries its own integer version (`v`, currently 1).
  Parsers reject versions they do not know.

## The namespace

Loading an engine's WASM registers it into a shared global:

```js
tamperEngines = {
  apiVersion: "1.1.0",
  hex:    { tool, engineVersion, capabilities, create() },
  recipe: { tool, engineVersion, capabilities, create() },
}
```

`create()` returns an isolated instance; instances never share state. Call
`dispose()` when done: it releases the Go-side function handles, and the
instance is unusable afterwards.

## Boundary semantics

- Bytes are copied in both directions (`Uint8Array` in, fresh `Uint8Array`
  out). Instances never alias host memory, and snapshots never change under
  the host's feet.
- Mutating methods return `null` on success or `{error: string}` on failure.
  Out-of-range writes fail; cursor and selection inputs clamp.
- Events are delivered synchronously after a mutation applies, to every
  callback registered with `subscribe`.

## Hex instance

```js
const hex = tamperEngines.hex.create();
hex.load(u8);                    // replace buffer (copies), resets cursor/selection
hex.bytes(); hex.len();          // snapshot (copy) / length
hex.cursor(); hex.setCursor(n);  // clamped to 0..len
hex.selection();                 // {start, end} half-open, or null
hex.select(a, b); hex.clearSelection();
hex.insert(off, u8);             // null | {error}
hex.del(off, n);                 // null | {error}
hex.overwrite(off, u8);          // null | {error}
hex.analyze();                   // {size, entropy, categories: Uint8Array}
hex.find(needleU8, ci);          // [offset, ...]
hex.strings(min);                // [{offset, text}, ...]
hex.encode(format);              // "hex"|"hexdump"|"base64"|"c"|"rust"|"go"|"python"|"json"|"intelhex"
hex.encode(format, start, end);  // same, over a half-open byte range
const id = hex.subscribe(ev => {}); hex.unsubscribe(id);
hex.dispose();
```

Events: `{type: "bytes", offset, length}` after load/insert/del/overwrite,
`{type: "cursor"}`, `{type: "selection"}`. Edits shift the cursor and selection
the way a text editor would (positions after an insert move right; positions
inside a deleted range collapse to the cut).

## Recipe instance

```js
const rec = tamperEngines.recipe.create({site: 42}); // CRDT site id, default 1
rec.manifest();                  // JSON op catalog [{id, name, category, params, options}]
rec.run(id, inputU8, args);      // one op: {output: Uint8Array} | {error}
rec.runRecipe(stepsJSON, inputU8); // whole chain incl. flow control (see below)
rec.seed(u8); rec.loadOps(json); // CRDT: load initial bytes / apply remote ops
rec.insert(pos, byte); rec.del(pos); // CRDT edits -> op JSON to broadcast
rec.text();                      // current CRDT bytes
rec.dispose();
```

The recipe chain (which ops in which order, with which args) is view config:
the host owns it and persists it in the envelope's `view` field. The engine
executes ops; it does not store the chain.

**runRecipe** runs the entire chain in one call, including flow control. `stepsJSON`
is `[{id, args, disabled?}]`; it returns `{output: Uint8Array, failedAt: number
(-1 if none), error: string, steps: [{error}]}`. Op arguments arrive as strings
(the engine parses per param type); native booleans/numbers are coerced. Flow-control
operations are interpreted here, not as standalone ops:

- **Fork** (`splitDelim`, `mergeDelim`) splits the data into branches that later
  steps apply to independently.
- **Merge** recombines the branches with the fork's merge delimiter.
- **Register** (`regex`) captures the pattern's groups into `$R0`, `$R1`, ... which
  are substituted into later steps' argument strings.

If a chain is still forked at the end, the output joins the branches on the merge
delimiter.

## Serialization envelope

What a host persists for an embedded tool (a Tiptap node attribute, a document
block, a file). Built and parsed by `doc(view)` / `loadDoc(json)` on any
instance, or by the `engine` Go package directly.

```json
{"v": 1, "tool": "hex", "src": {"inline": "<base64>"}, "view": {"offset": 16}}
{"v": 1, "tool": "hex", "src": {"ref": {"workspace": "w", "artifact": "a", "version": 3}}, "view": null}
```

- `src` sets exactly one of `inline` (the bytes, base64 in JSON) or `ref` (a
  tamper.space workspace artifact; `version` 0 or absent means latest).
- **Engines never fetch.** `loadDoc` with an inline source loads the bytes and
  returns `{loaded: true}`; with a ref it returns `{loaded: false, ref}` and the
  host resolves the ref to bytes and calls `load` itself.
- `view` is tool-owned and opaque to the host: it round-trips through hosts and
  the envelope untouched (hex: cursor/offset/encoding; recipe: the chain).

## Consumers

The bundled single-file UIs (and through them the tamper.space workbench) run
entirely on this API; the pre-API globals (`tamperHex`, `tamperOps`,
`tamperCRDT`) are gone. `tamperEngines` is the only surface the WASM binaries
register.
