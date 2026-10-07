package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestCDNCoverageThroughCLI(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, id, display, header, value, rule string
		status                                 int
		redirect                               bool
	}{
		{"cloudflare", "cloudflare", "Cloudflare", "CF-Ray", "230b030023ae2822-SJC", "ray-header", 200, false},
		{"cloudfront-error", "cloudfront", "Amazon CloudFront", "Via", "1.1 fixture123.cloudfront.net (CloudFront)", "via-header", 403, false},
		{"redirect-to-cloudfront", "cloudfront", "Amazon CloudFront", "Via", "1.1 fixture123.cloudfront.net (CloudFront)", "via-header", 200, true},
		{"redirect-without-final-evidence", "", "", "", "", "", 200, true},
		{"generic-forbidden", "", "", "", "", "", 403, false},
	} {
		for _, format := range []string{"terminal", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.URL.Path == "/start" {
						w.Header().Set("CF-Ray", "abcdef0123456789-LIS")
						http.Redirect(w, r, "/final", http.StatusFound)
						return
					}
					// Header evidence must work independently of HTML filtering.
					w.Header().Set("Content-Type", "text/plain")
					if tc.header != "" {
						w.Header().Set(tc.header, tc.value)
					}
					w.WriteHeader(tc.status)
					fmt.Fprint(w, `<script src="/asset.js"></script><a href="/other">fixture</a>`)
				}))
				defer server.Close()
				url := server.URL + "/final"
				wantRequests := int32(1)
				if tc.redirect {
					url = server.URL + "/start"
					wantRequests++
				}
				args := []string{"--no-color"}
				if format == "json" {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, url), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, stderr.String())
				}
				if requests.Load() != wantRequests {
					t.Errorf("requests=%d, want only %d page/redirect requests", requests.Load(), wantRequests)
				}
				for _, raw := range []string{"230b030023ae2822-SJC", "abcdef0123456789-LIS", "fixture123.cloudfront.net"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw header value exposed: %s", raw)
					}
				}
				if format == "terminal" {
					if tc.id == "" {
						if !strings.Contains(stdout.String(), "No technologies detected.") {
							t.Fatalf("unexpected finding: %s", &stdout)
						}
					} else if !strings.Contains(stdout.String(), "✓ "+tc.display+" [CDN/edge]") || strings.Count(stdout.String(), "[CDN/edge]") != 1 {
						t.Fatalf("unexpected CDN output: %s", &stdout)
					}
					if tc.status == 403 && !strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") {
						t.Error("missing error-response scope")
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				wantScope := "final_response"
				if tc.status >= 400 {
					wantScope = "http_error_response"
				}
				if report.CatalogSize != engine.Len() || report.SchemaVersion != 1 || report.HTTPStatus != tc.status || report.ResponseScope != wantScope || len(report.Redirects) != int(wantRequests-1) {
					t.Errorf("unexpected report metadata: %+v", report)
				}
				if tc.id == "" {
					if report.Findings == nil || len(report.Findings) != 0 {
						t.Fatalf("want empty findings array, got %+v", report.Findings)
					}
					return
				}
				if len(report.Findings) != 1 || report.Findings[0].ID != tc.id || report.Findings[0].Category != "cdn" || report.Findings[0].State != "detected" {
					t.Fatalf("unexpected findings or capability inference: %+v", report.Findings)
				}
				evidence := report.Findings[0].Evidence
				// Report evidence preserves the loader's canonical header name.
				wantHeader := http.CanonicalHeaderKey(tc.header)
				if len(evidence) != 1 || evidence[0].RuleID != tc.rule || evidence[0].InferredFrom != "" || len(evidence[0].Signals) != 1 || evidence[0].Signals[0].Source != "header" || evidence[0].Signals[0].Name != wantHeader {
					t.Errorf("unexpected evidence: %+v", evidence)
				}
			})
		}
	}
}
