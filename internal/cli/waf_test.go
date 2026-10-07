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

func TestAWSWAFThroughCLI(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, action, contentType string
		status                    int
		redirect, want            bool
	}{
		{"challenge", "challenge", "text/html", 202, false, true},
		{"captcha", "captcha", "text/html", 405, false, true},
		{"non-html-header", "challenge", "text/plain", 202, false, true},
		// The direct header rule does not require a particular HTTP status.
		{"status-rewritten", "captcha", "text/plain", 200, false, true},
		{"generic-202", "", "text/html", 202, false, false},
		{"generic-403", "", "text/html", 403, false, false},
		{"generic-405", "", "text/html", 405, false, false},
		{"unknown-action", "block", "text/html", 403, false, false},
		{"near-miss", "challenge-private-suffix", "text/html", 202, false, false},
		{"redirect-only", "", "text/html", 200, true, false},
		{"final-captcha", "captcha", "text/html", 405, true, true},
	} {
		for _, format := range []string{"terminal", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.URL.Path == "/start" {
						w.Header().Set("X-Amzn-Waf-Action", "challenge")
						http.Redirect(w, r, "/final", http.StatusFound)
						return
					}
					w.Header().Set("Content-Type", tc.contentType)
					w.Header().Set("X-Request-ID", "private-request-id")
					if tc.action != "" {
						w.Header().Set("X-Amzn-Waf-Action", tc.action)
					}
					w.WriteHeader(tc.status)
					fmt.Fprint(w, `<html>AWS WAF X-Amzn-Waf-Action: challenge captcha<script src="/challenge.js"></script><form action="/verify"></form></html>`)
				}))
				defer server.Close()
				url, wantRequests := server.URL+"/final", int32(1)
				if tc.redirect {
					url, wantRequests = server.URL+"/start", 2
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
					t.Errorf("requests=%d want=%d; no challenge/asset requests allowed", requests.Load(), wantRequests)
				}
				for _, raw := range []string{"private-request-id", "challenge-private-suffix", "/challenge.js", "/verify"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw response data exposed: %s", raw)
					}
				}
				if format == "terminal" {
					want := "No technologies detected."
					if tc.want {
						want = "✓ AWS WAF [WAF]"
					}
					if !strings.Contains(stdout.String(), want) {
						t.Fatalf("missing %q in %s", want, &stdout)
					}
					if tc.status >= 400 && !strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") {
						t.Error("missing HTTP error scope")
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
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.HTTPStatus != tc.status || report.ResponseScope != wantScope || len(report.Redirects) != int(wantRequests-1) {
					t.Errorf("unexpected metadata: %+v", report)
				}
				if !tc.want {
					if report.Findings == nil || len(report.Findings) != 0 {
						t.Fatalf("unexpected findings: %+v", report.Findings)
					}
					return
				}
				if len(report.Findings) != 1 || report.Findings[0].ID != "aws-waf" || report.Findings[0].Category != "waf" || report.Findings[0].State != "detected" {
					t.Fatalf("unexpected findings: %+v", report.Findings)
				}
				evidence := report.Findings[0].Evidence
				if len(evidence) != 1 || evidence[0].RuleID != "action-header" || evidence[0].InferredFrom != "" || len(evidence[0].Signals) != 1 || evidence[0].Signals[0].Source != "header" || evidence[0].Signals[0].Name != "X-Amzn-Waf-Action" {
					t.Errorf("unexpected evidence: %+v", evidence)
				}
			})
		}
	}
}
