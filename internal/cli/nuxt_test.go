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

func TestNuxtThroughCLI(t *testing.T) {
	fixture, err := os.ReadFile("../detect/testdata/coverage/nuxt-payload.html")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, contentType, header, body, state string
		status                                 int
		redirect, html                         bool
	}{
		{"html", "text/html", "", string(fixture), "inferred", 200, false, true},
		{"xhtml", "application/xhtml+xml", "", string(fixture), "inferred", 200, false, true},
		{"direct-upgrade", "text/html", "Nuxt", string(fixture), "detected", 200, false, true},
		{"non-html", "text/plain", "", string(fixture), "", 200, false, false},
		{"non-html-header", "application/json", "Nuxt", string(fixture), "detected", 200, false, false},
		{"header-near-miss", "text/html", "Nuxt-compatible", "<html></html>", "", 200, false, false},
		{"html-error", "text/html", "", string(fixture), "inferred", 403, false, true},
		{"header-error", "text/plain", "Nuxt", "Forbidden", "detected", 403, false, false},
		{"redirect-to-html", "text/html", "", string(fixture), "inferred", 200, true, true},
		{"redirect-only", "text/html", "", "<html></html>", "", 200, true, false},
		{"split-markers", "text/html", "", `<script src="/_nuxt/entry.js"></script>`, "", 200, true, false},
	} {
		for _, format := range []string{"terminal", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				var mu sync.Mutex
				var paths []string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					paths = append(paths, r.URL.Path)
					mu.Unlock()
					switch r.URL.Path {
					case "/start":
						w.Header().Set("X-Powered-By", "Nuxt")
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Location", "/final")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, string(fixture))
					case "/final":
						w.Header().Set("Content-Type", tc.contentType)
						if tc.header != "" {
							w.Header().Add("X-Powered-By", tc.header)
							w.Header().Add("X-Powered-By", tc.header)
						}
						w.WriteHeader(tc.status)
						fmt.Fprint(w, tc.body)
					default:
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				url := server.URL + "/final"
				wantPaths := []string{"/final"}
				if tc.redirect {
					url = server.URL + "/start"
					wantPaths = []string{"/start", "/final"}
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
				visited := append([]string(nil), paths...)
				mu.Unlock()
				if !reflect.DeepEqual(visited, wantPaths) {
					t.Errorf("unexpected page/asset requests: %v", visited)
				}
				for _, raw := range []string{"private-payload-value", "entry.fixture.js", "\x1b"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("unexpected raw payload/style: %q", raw)
					}
				}
				if format == "terminal" {
					wantLines, gotLines := []string{}, []string{}
					if tc.state != "" {
						marker := "?"
						if tc.state == "detected" {
							marker = "✓"
						}
						wantLines = append(wantLines, marker+" Nuxt [framework]")
					}
					for _, line := range strings.Split(stdout.String(), "\n") {
						if (strings.HasPrefix(line, "✓ ") || strings.HasPrefix(line, "? ")) && strings.Contains(line, " [") {
							gotLines = append(gotLines, line)
						}
					}
					if !reflect.DeepEqual(gotLines, wantLines) {
						t.Errorf("findings=%v want=%v", gotLines, wantLines)
					}
					if strings.Contains(stdout.String(), "No technologies detected.") != (tc.state == "") || strings.Contains(stdout.String(), "__NUXT_DATA__") != tc.html || strings.Contains(stdout.String(), "X-Powered-By header reports Nuxt") != (tc.state == "detected") {
						t.Errorf("incorrect evidence/empty-result message: %s", &stdout)
					}
					if strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") != (tc.status >= 400) {
						t.Error("incorrect error-response scope")
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
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.URL != url || report.FinalURL != server.URL+"/final" || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(tc.body) || len(report.Redirects) != len(wantPaths)-1 {
					t.Errorf("unexpected metadata: %+v", report)
				}
				if tc.state == "" {
					if report.Findings == nil || len(report.Findings) != 0 {
						t.Fatalf("want empty findings, got %+v", report.Findings)
					}
					return
				}
				if len(report.Findings) != 1 {
					t.Fatalf("want only Nuxt, got %+v", report.Findings)
				}
				finding := report.Findings[0]
				wantRules := []string{}
				if tc.html {
					wantRules = append(wantRules, "payload-html-markers")
				}
				if tc.state == "detected" {
					wantRules = append(wantRules, "powered-by-header")
				}
				if finding.ID != "nuxt" || finding.Name != "Nuxt" || finding.Category != "framework" || finding.State != tc.state || len(finding.Evidence) != len(wantRules) {
					t.Fatalf("unexpected finding: %+v", finding)
				}
				for i, evidence := range finding.Evidence {
					signals := []output.Signal{{Source: "html"}, {Source: "html"}}
					if wantRules[i] == "powered-by-header" {
						signals = []output.Signal{{Source: "header", Name: "X-Powered-By"}}
					}
					if evidence.RuleID != wantRules[i] || evidence.Description == "" || evidence.InferredFrom != "" || !reflect.DeepEqual(evidence.Signals, signals) {
						t.Errorf("unexpected evidence: %+v", evidence)
					}
				}
			})
		}
	}
}
