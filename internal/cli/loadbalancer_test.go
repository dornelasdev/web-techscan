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

func TestLoadBalancerCookiesThroughCLI(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, tech := range []struct{ id, name, base, cors string }{
		{"aws-alb", "AWS Application Load Balancer", "AWSALB", "AWSALBCORS"},
		{"aws-clb", "AWS Classic Load Balancer", "AWSELB", "AWSELBCORS"},
	} {
		for _, tc := range []struct {
			name         string
			start, final []string
			status       int
			want         bool
		}{
			{"pair", nil, []string{tech.base, tech.cors}, 200, true},
			{"error-pair", nil, []string{tech.base, tech.cors}, 403, true},
			{"duplicate-pair", nil, []string{tech.base, tech.cors, tech.base}, 200, true},
			{"redirect-only", []string{tech.base, tech.cors}, nil, 200, false},
			{"split-across-redirect", []string{tech.base}, []string{tech.cors}, 200, false},
			{"cookie-values-only", nil, []string{"example"}, 200, false},
		} {
			for _, format := range []string{"terminal", "json"} {
				t.Run(tech.id+"/"+tc.name+"/"+format, func(t *testing.T) {
					var requests, replayed atomic.Int32
					// These deliberately contain marker names. Values must never
					// become detection inputs, report evidence, or replayed cookies.
					secret := "private-value-" + tech.base + "-" + tech.cors
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if r.Header.Get("Cookie") != "" {
							replayed.Add(1)
						}
						names := tc.final
						if r.URL.Path == "/start" {
							names = tc.start
						}
						for _, name := range names {
							http.SetCookie(w, &http.Cookie{Name: name, Value: secret, Path: "/"})
						}
						if r.URL.Path == "/start" {
							http.Redirect(w, r, "/final", http.StatusFound)
							return
						}
						w.Header().Set("Content-Type", "text/plain")
						w.WriteHeader(tc.status)
						fmt.Fprint(w, tech.base+" "+tech.cors)
					}))
					defer server.Close()
					url, wantRequests := server.URL+"/final", int32(1)
					if tc.start != nil {
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
					if requests.Load() != wantRequests || replayed.Load() != 0 {
						t.Errorf("requests=%d want=%d replayed=%d", requests.Load(), wantRequests, replayed.Load())
					}
					if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
						t.Error("cookie value exposed")
					}
					if format == "terminal" {
						want := "No technologies detected."
						if tc.want {
							want = "? " + tech.name + " [load balancer]"
						}
						if !strings.Contains(stdout.String(), want) {
							t.Fatalf("missing %q in %s", want, &stdout)
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
						t.Errorf("unexpected metadata: %+v", report)
					}
					if !tc.want {
						if report.Findings == nil || len(report.Findings) != 0 {
							t.Fatalf("unexpected findings: %+v", report.Findings)
						}
						return
					}
					if len(report.Findings) != 1 || report.Findings[0].ID != tech.id || report.Findings[0].State != "inferred" || report.Findings[0].Category != "load_balancer" {
						t.Fatalf("unexpected findings: %+v", report.Findings)
					}
					evidence := report.Findings[0].Evidence
					if len(evidence) != 1 || evidence[0].RuleID != "stickiness-cookie-pair" || evidence[0].InferredFrom != "" || len(evidence[0].Signals) != 2 {
						t.Fatalf("unexpected evidence: %+v", evidence)
					}
					for _, signal := range evidence[0].Signals {
						if signal.Source != "cookie" || signal.Name != "" {
							t.Errorf("unexpected cookie signal: %+v", signal)
						}
					}
				})
			}
		}
	}
}
