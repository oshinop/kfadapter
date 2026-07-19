package web

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// staticFiles is the frontend's production build. Assets are packaged with the
// binary; the service never fetches fonts, scripts, images, telemetry, or updates
// from the network.
//
//go:embed all:static
var staticFiles embed.FS

func (a *API) serveAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		a.writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method Not Allowed", "")
		return
	}
	setNoStore(w.Header())
	name, spaFallback := staticAssetName(r.URL.Path)
	content, err := fs.ReadFile(staticFiles, "static/"+name)
	if err != nil && spaFallback {
		name = "index.html"
		content, err = fs.ReadFile(staticFiles, "static/"+name)
	}
	if err != nil {
		a.writeProblem(w, http.StatusNotFound, "not_found", "Not Found", "")
		return
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(content))
}

func staticAssetName(requestPath string) (name string, spaFallback bool) {
	clean := path.Clean("/" + requestPath)
	name = strings.TrimPrefix(clean, "/")
	if name == "" || name == "." {
		return "index.html", true
	}
	if strings.Contains(name, "\\") || strings.HasPrefix(name, "../") {
		return "", false
	}
	return name, !strings.Contains(path.Base(name), ".")
}
