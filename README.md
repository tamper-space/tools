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
- `engine/` — the public contract: API version and the serialization envelope
  hosts persist (see [docs/ENGINE-API.md](docs/ENGINE-API.md)).
- `<tool>/wasm` — a `syscall/js` shim exposing the engine to the browser as
  `tamperEngines.<tool>` (versioned, instantiable) plus the legacy globals the
  bundled UIs still use.
- `<tool>/ui` — the tool's HTML/CSS/JS.
- `build` — bundler that compiles each engine and inlines everything.
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

Dual-licensed: [GNU General Public License v3.0](LICENSE) for open use, with
commercial licenses available for proprietary embedding (see
[COMMERCIAL.md](COMMERCIAL.md)). Contributions require the sign-off and license
grant described in [CONTRIBUTING.md](CONTRIBUTING.md).
