// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Tamper-Commercial

// Package tools embeds the theme and per-tool UI assets so builders can produce
// self-contained bundles without any runtime file dependencies.
package tools

import "embed"

//go:embed theme hex/ui recipe/ui
var Assets embed.FS
