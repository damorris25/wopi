package middleware

import (
	"net/http"
	"strings"
)

// CSRFProtect returns middleware that requires a custom X-Requested-With header
// on mutation requests (POST, PUT, DELETE) to /api/ paths. This prevents
// cross-site request forgery because browsers will not send custom headers on
// cross-origin requests without a CORS preflight, and the server does not set
// CORS headers that would allow it.
func CSRFProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && isMutationMethod(r.Method) {
			if r.Header.Get("X-Requested-With") == "" {
				http.Error(w, "missing CSRF header", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isMutationMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete || method == http.MethodPatch
}
