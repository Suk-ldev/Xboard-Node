// Admin panel HTTP mounting: secret base path + password gate. The path is
// the primary gate (fanout-style); the password protects state changes.
// Requests outside the secret path get a plain 404.
//
// The base path is read from the panel's state on EVERY request, so a path
// change made in the panel takes effect immediately (the old URL starts
// 404ing right away).
package admin

import (
	"net/http"
	"strings"
)

// Mount builds the top-level handler that only exposes the panel under its
// secret base path. The path itself lives in the panel state and may be
// changed at runtime (panel → 安全 → 访问路径).
func Mount(panel *Panel) http.Handler {
	return &mounted{panel: panel}
}

type mounted struct {
	panel *Panel
}

func (m *mounted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	base := m.panel.BasePath()
	if !strings.HasPrefix(base, "/") || base == "" {
		base = "/admin"
	}
	// Exact-prefix gate: /<secret>/anything. Anything else → 404.
	if !strings.HasPrefix(r.URL.Path, base+"/") && r.URL.Path != base {
		http.NotFound(w, r)
		return
	}
	// Strip the base path first, then apply the API gate on the inner path.
	inner := strings.TrimPrefix(r.URL.Path, base)
	// The secret path is the primary gate (fanout-style); mutating API calls
	// additionally need the password header.
	if isAuthedAPI(r, inner) {
		if got := r.Header.Get("X-Panel-Password"); !m.panel.checkPassword(got) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="panel"`)
			apiErr(w, 401, "bad password")
			return
		}
	}
	http.StripPrefix(base, m.panel.Handler()).ServeHTTP(w, r)
}

// isAuthedAPI reports whether the request touches state or credentials.
// GETs are read-only and pass with the path alone; every other method needs
// the password header.
func isAuthedAPI(r *http.Request, innerPath string) bool {
	if !strings.HasPrefix(innerPath, "/api/") {
		return false // index page
	}
	return r.Method != http.MethodGet
}
