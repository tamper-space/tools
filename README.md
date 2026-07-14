# tamper.space tools

Open, browser-based tools for reverse engineering and low-level tinkering. Each
tool is a pure Go engine compiled to WebAssembly and wrapped in a small vanilla
UI, built into a single self-contained HTML file that also opens offline from
`file://`.

These tools power [tamper.space](https://tamper.space) but carry no dependency on
it. The platform layer (accounts, sharing, collaboration) is separate and speaks
to any tool through the postMessage protocol below.

## Layout

- `core/<tool>` — the pure engine (no I/O, no UI), the single source of truth.
- `<tool>/wasm` — a `syscall/js` shim exposing the engine to the browser.
- `<tool>/ui` — the tool's HTML/CSS/JS.
- `<tool>/build` — bundler that compiles the engine and inlines everything.
- `theme` — shared design tokens and fonts, embedded into each bundle.

## Build

```sh
go run ./hex/build -out dist
```

Open `dist/hex/index.html` in a browser. [TinyGo](https://tinygo.org) is used
when present for a much smaller bundle; otherwise the standard Go toolchain is
used (set `TAMPER_WASM=go` to force it).

## Platform protocol

A tool runs standalone. When embedded in an iframe by a host, it exposes its
state over `postMessage` (same origin only):

- tool → host `tamper:ready` `{tool, capabilities}` on load.
- host → tool `tamper:getState` → tool → host `tamper:state` `{data, title}`.
- host → tool `tamper:loadState` `{data}`.

## License

Copyright 2026 Justus Johnson. Licensed under the [Apache License 2.0](LICENSE).
