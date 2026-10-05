package cli_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"webscan/internal/cli"
)

func TestBundledCoverageThroughCLI(t *testing.T) {
	const nextHTML = `<script src="/_next/static/chunks/main.js"></script><script id="__NEXT_DATA__" type="application/json">{}</script>`
	for _, tc := range []struct {
		name, contentType, body string
		headers                 http.Header
		cookies                 []string
		status                  int
		want, absent            []string
	}{
		{
			name: "laravel stack", contentType: "text/html", body: "<html></html>", status: 200,
			headers: http.Header{"Server": {"nginx/1.26.2"}}, cookies: []string{"laravel_session", "XSRF-TOKEN"},
			want:   []string{"✓ nginx [web server]", "? Laravel [framework]", "? PHP [language]", "Inferred from Laravel"},
			absent: []string{"do-not-print-cookie-values", "No technologies detected"},
		},
		{
			name: "next html", contentType: "text/html; charset=utf-8", body: nextHTML, status: 200,
			want: []string{"? Next.js [framework]", "__NEXT_DATA__"}, absent: []string{"[language]"},
		},
		{
			name: "html in plain text", contentType: "text/plain", body: nextHTML, status: 200,
			want: []string{"No technologies detected."}, absent: []string{"Next.js ["},
		},
		{
			name: "identified error page", contentType: "text/html", body: "<html>Forbidden</html>", status: 403,
			headers: http.Header{"X-Powered-By": {"Express"}},
			want:    []string{"HTTP status: 403", "✓ Express [framework]", "Findings describe the returned HTTP error page."},
			absent:  []string{"[language]"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				for name, values := range tc.headers {
					for _, value := range values {
						w.Header().Add(name, value)
					}
				}
				for _, name := range tc.cookies {
					http.SetCookie(w, &http.Cookie{Name: name, Value: "do-not-print-cookie-values"})
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			var stdout, stderr bytes.Buffer
			if code := cli.Run([]string{server.URL}, &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
				t.Fatalf("exit=%d, stderr=%q", code, stderr.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout=%q, missing %q", stdout.String(), want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(stdout.String(), absent) {
					t.Errorf("stdout=%q, unexpected %q", stdout.String(), absent)
				}
			}
		})
	}
}

func TestRedirectTechnologyDoesNotLeakIntoFinalStack(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Server", "nginx")
			w.Header().Set("X-Powered-By", "Express")
			http.SetCookie(w, &http.Cookie{Name: "laravel_session", Value: "secret"})
			http.SetCookie(w, &http.Cookie{Name: "XSRF-TOKEN", Value: "secret"})
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.Header().Set("Server", "Apache/2.4.62")
		fmt.Fprint(w, "final page")
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{server.URL + "/start"}, &stdout, &stderr, "dev"); code != 0 {
		t.Fatalf("exit=%d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "✓ Apache HTTP Server [web server]") {
		t.Fatalf("missing final server: %s", &stdout)
	}
	for _, absent := range []string{"nginx", "Express", "Laravel", "PHP"} {
		if strings.Contains(stdout.String(), absent) {
			t.Errorf("redirect technology %s leaked into results: %s", absent, &stdout)
		}
	}
}
