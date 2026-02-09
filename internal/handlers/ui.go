package handlers

import (
	"embed"
	"net/http"
)

//go:embed static/index.html
var staticFS embed.FS

// ServeUI serves the embedded browser UI.
func (h *Handler) ServeUI(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "ui not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}
