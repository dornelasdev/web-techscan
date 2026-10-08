package cli_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"webscan/internal/cli"
)

func TestRedirectFailuresHaveSafeDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, location, reason string
		status                 int
		flags                  []string
	}{
		{"credentials", "http://private-user:private-password@HOST/target", "embedded credentials are not supported", 302, nil},
		{"malformed-credentials", "http://private-user:private-password@HOST/%zz?token=private-query", "network error or invalid HTTP response", 307, nil},
		{"malformed-relative", "/%zz?token=private-query", "network error or invalid HTTP response", 303, nil},
		{"invalid-scheme", "ftp://HOST/target?token=private-query", "include an http:// or https:// scheme", 301, nil},
		{"redirect-limit", "/target?token=private-query", "redirect limit exceeded (maximum 0)", 308, []string{"--max-redirects=0"}},
	} {
		for _, json := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", tc.name, json), func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					w.Header().Set("Server", "nginx")
					w.Header().Set("Location", strings.ReplaceAll(tc.location, "HOST", r.Host))
					w.WriteHeader(tc.status)
					fmt.Fprint(w, "private-body")
				}))
				defer server.Close()
				args := append([]string{"--no-color"}, tc.flags...)
				if json {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				code := cli.Run(append(args, server.URL+"/start?token=private-start"), &stdout, &stderr, "dev")
				if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.reason) {
					t.Fatalf("exit=%d stdout=%q stderr=%q; want execution error, no partial report", code, &stdout, &stderr)
				}
				for _, raw := range []string{"private-user", "private-password", "private-query", "private-start", "private-body", server.URL, "%zz", "\x1b", "Run 'webscan --help'"} {
					if strings.Contains(stderr.String(), raw) {
						t.Errorf("unexpected diagnostic content %q", raw)
					}
				}
				if requests.Load() != 1 {
					t.Errorf("unexpected requests: %d", requests.Load())
				}
			})
		}
	}
}
