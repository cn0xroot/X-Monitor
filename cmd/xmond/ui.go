package main

import (
	"net/http"

	"xmonitor/web"
)

// uiHandler returns the embedded dashboard handler (DESIGN.md §16.1).
func uiHandler() http.Handler { return web.Handler() }
