// Package web embeds the dashboard UI (DESIGN.md §16.1).
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// index.html is the single-page dashboard; timeline.js is the swim-lane
// timeline and session-flow module (adapted from CC-Monitor, see NOTICE).
//
//go:embed index.html timeline.js
var files embed.FS

// Handler serves the embedded dashboard.
func Handler() http.Handler {
	sub, _ := fs.Sub(files, ".")
	return http.FileServer(http.FS(sub))
}
