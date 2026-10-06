package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/output"
)

func TestCMSCoverageThroughCLI(t *testing.T) {
	for _, tc := range []struct{ id, name string }{{"wordpress", "WordPress"}, {"drupal", "Drupal"}, {"joomla", "Joomla"}} {
		t.Run(tc.id, func(t *testing.T) {
			body, err := os.ReadFile("../detect/testdata/coverage/" + tc.id + ".html")
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Write(body)
			}))
			defer server.Close()
			for _, format := range []string{"terminal", "json"} {
				args := []string{"--no-color"}
				if format == "json" {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, stderr.String())
				}
				if format == "terminal" {
					if !strings.Contains(stdout.String(), "? "+tc.name+" [CMS]") || strings.Contains(stdout.String(), "[language]") {
						t.Errorf("unexpected CMS output: %s", &stdout)
					}
					continue
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				if report.CatalogSize != 10 || len(report.Findings) != 1 || report.Findings[0].ID != tc.id || report.Findings[0].Category != "cms" || report.Findings[0].State != "inferred" {
					t.Fatalf("unexpected CMS report: %+v", report)
				}
			}
		})
	}
}

func TestCMSContentTypeAndRedirectIsolation(t *testing.T) {
	for _, header := range []bool{false, true} {
		t.Run(fmt.Sprint(header), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					w.Header().Set("X-Generator", "Drupal 11")
					http.Redirect(w, r, "/final", http.StatusFound)
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				if header {
					w.Header().Set("X-Generator", "Drupal 11")
				}
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `<meta name="generator" content="WordPress 6.8.3">`)
			}))
			defer server.Close()
			var stdout, stderr bytes.Buffer
			if code := cli.Run([]string{"--json", server.URL + "/start"}, &stdout, &stderr, "dev"); code != 0 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			var report output.Report
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.ResponseScope != "http_error_response" || len(report.Redirects) != 1 {
				t.Errorf("unexpected response metadata: %+v", report)
			}
			if header {
				if len(report.Findings) != 1 || report.Findings[0].ID != "drupal" || report.Findings[0].State != "detected" {
					t.Errorf("expected only final Drupal header: %+v", report.Findings)
				}
			} else if len(report.Findings) != 0 {
				t.Errorf("redirect header or non-HTML content leaked into results: %+v", report.Findings)
			}
		})
	}
}
