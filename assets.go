// Package tools embeds the theme and per-tool UI assets so builders can produce
// self-contained bundles without any runtime file dependencies.
package tools

import "embed"

//go:embed theme hex/ui
var Assets embed.FS
