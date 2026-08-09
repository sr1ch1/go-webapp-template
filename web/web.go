// Package web exposes the embedded templates and static assets. The files
// live outside internal/ so the Go code stays separate from the web assets;
// embed patterns cannot cross package directories, hence this bridge.
package web

import "embed"

//go:embed templates static
var FS embed.FS
