package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestRailsThroughCLI(t *testing.T) {
	fixture, err := os.ReadFile("../detect/testdata/coverage/rails-csrf.html")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	const param = `<meta name="csrf-param" content="authenticity_token">`
	const token = `<meta name="csrf-token" content="private-rails-token">`
	for _, tc := range []struct {
		name, contentType, body, hopBody string
		status                           int
		want                             bool
	}{
		{"paired", "text/html", string(fixture), "", 200, true},
		{"xhtml", "application/xhtml+xml", string(fixture), "", 200, true},
		{"duplicate-pairs", "text/html", string(fixture) + param + token, "", 200, true},
		{"param-only", "text/html", param, "", 200, false},
		{"token-only", "text/html", token, "", 200, false},
		{"empty-token", "text/html", param + `<meta name="csrf-token" content="">`, "", 200, false},
		{"custom-param", "text/html", strings.Replace(string(fixture), `content="authenticity_token"`, `content="custom_token"`, 1), "", 200, false},
		{"non-html", "text/plain", string(fixture), "", 200, false},
		{"error-page", "text/html", string(fixture), "", 403, true},
		{"generic-error", "text/html", "Forbidden", "", 403, false},
		{"redirect-to-paired", "text/html", string(fixture), "<html></html>", 200, true},
		{"redirect-only", "text/html", "<html></html>", string(fixture), 200, false},
		{"param-on-redirect", "text/html", token, param, 200, false},
		{"token-on-redirect", "text/html", param, token, 200, false},
	} {
		for _, format := range []string{"terminal", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				var mu sync.Mutex
				var requests []string
				replayed := false
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					requests = append(requests, r.Method+" "+r.URL.Path)
					replayed = replayed || r.Header.Get("Cookie") != ""
					mu.Unlock()
					// These generic signals must not turn partial HTML into a Rails match.
					http.SetCookie(w, &http.Cookie{Name: "_app_session", Value: "private-session-value", Path: "/"})
					w.Header().Set("X-Request-ID", "private-request-id")
					w.Header().Set("X-Runtime", "0.123")
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Location", "/final")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, tc.hopBody)
					case "/final":
						w.Header().Set("Content-Type", tc.contentType)
						w.WriteHeader(tc.status)
						fmt.Fprint(w, tc.body)
					default:
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				url := server.URL + "/final"
				wantRequests := []string{"GET /final"}
				if tc.hopBody != "" {
					url = server.URL + "/start"
					wantRequests = []string{"GET /start", "GET /final"}
				}
				args := []string{"--no-color"}
				if format == "json" {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, url), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, &stderr)
				}
				mu.Lock()
				visited, hadCookies := append([]string(nil), requests...), replayed
				mu.Unlock()
				if !reflect.DeepEqual(visited, wantRequests) || hadCookies {
					t.Errorf("unexpected requests/replayed cookies: %v cookies=%v", visited, hadCookies)
				}
				for _, raw := range []string{"private-rails-token", "private-form-token", "private-session-value", "private-request-id", "fixture.js", "\x1b"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("unexpected raw value/style %q", raw)
					}
				}
				if format == "terminal" {
					wantLines, gotLines := []string{}, []string{}
					if tc.want {
						wantLines = append(wantLines, "? Ruby on Rails [framework]")
					}
					for _, line := range strings.Split(stdout.String(), "\n") {
						if (strings.HasPrefix(line, "✓ ") || strings.HasPrefix(line, "? ")) && strings.Contains(line, " [") {
							gotLines = append(gotLines, line)
						}
					}
					if !reflect.DeepEqual(gotLines, wantLines) {
						t.Errorf("findings=%v want=%v", gotLines, wantLines)
					}
					if strings.Contains(stdout.String(), "No technologies detected.") != !tc.want || strings.Contains(stdout.String(), "Paired csrf-param authenticity_token and csrf-token meta tags") != tc.want {
						t.Errorf("incorrect evidence/empty-result message: %s", &stdout)
					}
					if strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") != (tc.status >= 400) {
						t.Error("incorrect response scope")
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				scope := "final_response"
				if tc.status >= 400 {
					scope = "http_error_response"
				}
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.URL != url || report.FinalURL != server.URL+"/final" || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(tc.body) || len(report.Redirects) != len(wantRequests)-1 {
					t.Errorf("unexpected metadata: %+v", report)
				}
				if !tc.want {
					if report.Findings == nil || len(report.Findings) != 0 {
						t.Fatalf("want empty findings, got %+v", report.Findings)
					}
					return
				}
				if len(report.Findings) != 1 {
					t.Fatalf("want only Rails without language guesses, got %+v", report.Findings)
				}
				finding := report.Findings[0]
				if finding.ID != "rails" || finding.Name != "Ruby on Rails" || finding.Category != "framework" || finding.State != "inferred" || len(finding.Evidence) != 1 {
					t.Fatalf("unexpected finding: %+v", finding)
				}
				e := finding.Evidence[0]
				if e.RuleID != "csrf-meta-pair" || e.Description == "" || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []output.Signal{{Source: "html"}, {Source: "html"}}) {
					t.Errorf("unexpected evidence: %+v", e)
				}
			})
		}
	}
}
