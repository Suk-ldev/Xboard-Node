// Admin panel HTTP mounting: secret base path + password gate. The path is
// the primary gate (fanout-style); the password protects state changes.
// Requests outside the secret path get a plain 404.
package admin

import (
	"net/http"
	"strings"
)

// Mount builds the top-level handler that only exposes the panel under its
// secret base path. basePath must start with "/" and not end with "/".
// Mutating API calls need the X-Panel-Password header (checked against the
// hash stored in egress.json via the panel itself).
func Mount(basePath string, panel *Panel) http.Handler {
	base := strings.TrimSuffix(basePath, "/")
	if !strings.HasPrefix(base, "/") || base == "" {
		base = "/admin"
	}
	return &mounted{base: base, panel: panel}
}

type mounted struct {
	base  string
	panel *Panel
}

func (m *mounted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Exact-prefix gate: /<secret>/anything. Anything else → 404.
	if !strings.HasPrefix(r.URL.Path, m.base+"/") && r.URL.Path != m.base {
		http.NotFound(w, r)
		return
	}
	// Strip the base path first, then apply the API gate on the inner path.
	inner := strings.TrimPrefix(r.URL.Path, m.base)
	// The secret path is the primary gate (fanout-style); mutating API calls
	// additionally need the password header.
	if isAuthedAPI(r, inner) {
		if got := r.Header.Get("X-Panel-Password"); !m.panel.checkPassword(got) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="panel"`)
			apiErr(w, 401, "bad password")
			return
		}
	}
	http.StripPrefix(m.base, m.panel.Handler()).ServeHTTP(w, r)
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
