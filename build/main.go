// Builds each self-contained tool into <out>/<slug>/index.html: compiles the
// tool's engine to WASM and inlines it (base64) with wasm_exec.js and the UI, so
// each file also opens from file://. Run: go run ./build [-out dir]
package main

import (
	"encoding/base64"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tamper-space/tools"
)

type tool struct{ slug, wasmPkg, uiDir string }

var all = []tool{
	{"hex", "github.com/tamper-space/tools/hex/wasm", "hex/ui"},
	{"recipe", "github.com/tamper-space/tools/recipe/wasm", "recipe/ui"},
}

func main() {
	out := flag.String("out", "dist", "output directory for tool bundles")
	flag.Parse()
	fonts := fontFace("Tamper Sans", "theme/fonts/TamperSans.woff2", "100 1000") +
		fontFace("Tamper Mono", "theme/fonts/TamperMono.woff2", "100 700")
	tokens := embedStr("theme/tokens.css")
	for _, t := range all {
		bundle(t, *out, fonts, tokens)
	}
}

func bundle(t tool, out, fonts, tokens string) {
	wasm := filepath.Join(os.TempDir(), "tamper-"+t.slug+".wasm")
	wasmExec := compile(wasm, t.wasmPkg)
	html := replace(embedStr(t.uiDir+"/index.tmpl.html"),
		"/*WASM_EXEC*/", string(readFile(wasmExec)),
		"/*FONTS_CSS*/", fonts,
		"/*TOKENS_CSS*/", tokens,
		"/*APP_CSS*/", embedStr(t.uiDir+"/app.css"),
		"/*APP_JS*/", embedStr(t.uiDir+"/app.js"),
		"__WASM_B64__", base64.StdEncoding.EncodeToString(readFile(wasm)),
	)
	dir := filepath.Join(out, t.slug)
	must(os.MkdirAll(dir, 0o755))
	dst := filepath.Join(dir, "index.html")
	must(os.WriteFile(dst, []byte(html), 0o644))
	println("wrote", dst, len(html)/1024, "KB")
}

// compile builds pkg to WASM and returns the matching wasm_exec.js. It prefers
// TinyGo (much smaller output) unless it is absent or TAMPER_WASM=go is set.
func compile(out, pkg string) string {
	if os.Getenv("TAMPER_WASM") != "go" {
		if tinygo, err := exec.LookPath("tinygo"); err == nil {
			run(exec.Command(tinygo, "build", "-o", out, "-target", "wasm", "-no-debug", "-opt=z", pkg))
			println("tinygo:", sizeKB(out), "KB wasm", pkg)
			return filepath.Join(toolEnv(tinygo, "TINYGOROOT"), "targets", "wasm_exec.js")
		}
		println("tinygo not found; using standard Go (larger bundle)")
	}
	c := exec.Command("go", "build", "-o", out, pkg)
	c.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	run(c)
	println("go:", sizeKB(out), "KB wasm", pkg)
	return filepath.Join(toolEnv("go", "GOROOT"), "lib", "wasm", "wasm_exec.js")
}

func fontFace(family, file, weights string) string {
	b64 := base64.StdEncoding.EncodeToString(embedBytes(file))
	return "@font-face{font-family:\"" + family + "\";src:url(data:font/woff2;base64," + b64 +
		") format(\"woff2\");font-weight:" + weights + ";font-style:normal;font-display:swap;}\n"
}

func toolEnv(bin, key string) string {
	out, err := exec.Command(bin, "env", key).Output()
	must(err)
	return strings.TrimSpace(string(out))
}

func run(c *exec.Cmd) {
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	must(c.Run())
}

func sizeKB(p string) int {
	fi, err := os.Stat(p)
	must(err)
	return int(fi.Size()) / 1024
}

func replace(s string, pairs ...string) string {
	for i := 0; i < len(pairs); i += 2 {
		s = strings.Replace(s, pairs[i], pairs[i+1], 1)
	}
	return s
}

func embedStr(name string) string { return string(embedBytes(name)) }

func embedBytes(name string) []byte {
	b, err := tools.Assets.ReadFile(name)
	must(err)
	return b
}

func readFile(p string) []byte {
	b, err := os.ReadFile(p)
	must(err)
	return b
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
