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

func TestDjangoThroughCLI(t *testing.T) {
	fixture, err := os.ReadFile("../detect/testdata/coverage/django-csrf.html")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, contentType, body string
		cookies                 []string
		status                  int
		redirect, want          bool
	}{
		{"paired", "text/html", string(fixture), []string{"csrftoken"}, 200, false, true},
		{"xhtml", "application/xhtml+xml", string(fixture), []string{"csrftoken"}, 200, false, true},
		{"duplicate-cookies", "text/html", string(fixture), []string{"csrftoken", "sessionid", "csrftoken"}, 200, false, true},
		{"html-only", "text/html", string(fixture), nil, 200, false, false},
		{"cookies-only", "text/html", "<html></html>", []string{"sessionid", "csrftoken"}, 200, false, false},
		{"value-decoy", "text/html", string(fixture), []string{"other"}, 200, false, false},
		{"wrong-cookie-case", "text/html", string(fixture), []string{"CSRFTOKEN"}, 200, false, false},
		{"non-html", "text/plain", string(fixture), []string{"csrftoken"}, 200, false, false},
		{"error-page", "text/html", string(fixture), []string{"csrftoken"}, 403, false, true},
		{"generic-error", "text/html", "Forbidden", nil, 403, false, false},
		{"redirect-to-paired", "text/html", string(fixture), []string{"csrftoken"}, 200, true, true},
		{"cookie-only-on-redirect", "text/html", string(fixture), nil, 200, true, false},
		{"html-only-on-redirect", "text/html", "<html></html>", []string{"csrftoken"}, 200, true, false},
		{"redirect-only", "text/html", "<html></html>", nil, 200, true, false},
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
					setCookies := func(names []string) {
						for _, name := range names {
							http.SetCookie(w, &http.Cookie{Name: name, Value: "csrftoken-private-cookie-value", Path: "/"})
						}
					}
					switch r.URL.Path {
					case "/start":
						setCookies([]string{"csrftoken"})
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Location", "/final")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, string(fixture))
					case "/final":
						setCookies(tc.cookies)
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
				if tc.redirect {
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
				for _, raw := range []string{"csrftoken-private-cookie-value", "private-csrf-value", "fixture.js", "\x1b"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("unexpected raw value/style %q", raw)
					}
				}
				if format == "terminal" {
					wantLines, gotLines := []string{}, []string{}
					if tc.want {
						wantLines = append(wantLines, "? Django [framework]")
					}
					for _, line := range strings.Split(stdout.String(), "\n") {
						if (strings.HasPrefix(line, "✓ ") || strings.HasPrefix(line, "? ")) && strings.Contains(line, " [") {
							gotLines = append(gotLines, line)
						}
					}
					if !reflect.DeepEqual(gotLines, wantLines) {
						t.Errorf("findings=%v want=%v", gotLines, wantLines)
					}
					if strings.Contains(stdout.String(), "No technologies detected.") != !tc.want || strings.Contains(stdout.String(), "csrftoken cookie name and a hidden csrfmiddlewaretoken input") != tc.want {
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
					t.Fatalf("want only Django without language guesses, got %+v", report.Findings)
				}
				finding := report.Findings[0]
				if finding.ID != "django" || finding.Name != "Django" || finding.Category != "framework" || finding.State != "inferred" || len(finding.Evidence) != 1 {
					t.Fatalf("unexpected finding: %+v", finding)
				}
				evidence := finding.Evidence[0]
				if evidence.RuleID != "csrf-cookie-and-input" || evidence.Description == "" || evidence.InferredFrom != "" || !reflect.DeepEqual(evidence.Signals, []output.Signal{{Source: "cookie"}, {Source: "html"}}) {
					t.Errorf("unexpected evidence: %+v", evidence)
				}
			})
		}
	}
}
