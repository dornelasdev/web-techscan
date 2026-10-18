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
	"webscan/internal/output"
)

func TestHTMLPreferenceThroughCLI(t *testing.T) {
	fixture, err := os.ReadFile("../detect/testdata/coverage/spring-boot-reactive-error.html")
	if err != nil {
		t.Fatal(err)
	}
	const accept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
	const jsonBody = `{"status":404,"error":"Not Found","private":"private-response"}`
	for _, tc := range []struct {
		name, mode                      string
		flags                           []string
		prefer, redirect, assets, found bool
		status                          int
	}{
		{name: "default-json", status: 404},
		{name: "explicit-false", flags: []string{"--prefer-html=false"}, status: 404},
		{name: "preferred-html", flags: []string{"--prefer-html"}, prefer: true, found: true, status: 404},
		{name: "explicit-true", flags: []string{"--prefer-html=true"}, prefer: true, found: true, status: 404},
		{name: "server-ignores-preference", mode: "json", flags: []string{"--prefer-html"}, prefer: true, status: 404},
		{name: "server-rejects-preference", mode: "reject", flags: []string{"--prefer-html"}, prefer: true, status: 406},
		{name: "successful-html-still-status-gated", mode: "success", flags: []string{"--prefer-html"}, prefer: true, status: 200},
		{name: "plain-markers-still-mime-gated", mode: "plain", flags: []string{"--prefer-html"}, prefer: true, status: 404},
		{name: "xhtml-response", mode: "xhtml", flags: []string{"--prefer-html"}, prefer: true, found: true, status: 404},
		{name: "redirect-preserves-preference", flags: []string{"--prefer-html"}, prefer: true, redirect: true, found: true, status: 404},
		{name: "redirect-default-unchanged", redirect: true, status: 404},
		{name: "assets-have-no-html-preference", flags: []string{"--prefer-html"}, prefer: true, redirect: true, assets: true, found: true, status: 404},
		{name: "json-does-not-trigger-assets", mode: "json", flags: []string{"--prefer-html"}, prefer: true, assets: true, status: 404},
	} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				htmlBody := string(fixture)
				if tc.assets {
					htmlBody += `<script src="/app.js?token=private-query"></script><link rel="stylesheet" href="/app.css?token=private-query">`
				}
				var mu sync.Mutex
				visited := []string{}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					visited = append(visited, r.URL.Path)
					mu.Unlock()
					wantAccept := ""
					page := r.URL.Path == "/start" || r.URL.Path == "/page"
					if page && tc.prefer {
						wantAccept = accept
					}
					if r.Header.Get("Accept") != wantAccept || r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.URL.Query().Get("token") != "private-query" {
						t.Errorf("unexpected request policy: %s %s %v", r.Method, r.URL, r.Header)
					}
					switch r.URL.Path {
					case "/start":
						w.Header().Set("X-Powered-By", "Express") // Never final-page evidence.
						http.SetCookie(w, &http.Cookie{Name: "session", Value: "private-cookie"})
						w.Header().Set("Location", "/page?token=private-query")
						w.WriteHeader(302)
					case "/page":
						contentType, body := "application/json", jsonBody
						if (tc.mode == "" && strings.Contains(r.Header.Get("Accept"), "text/html")) || tc.mode == "success" || tc.mode == "plain" || tc.mode == "xhtml" {
							contentType, body = "text/html; charset=utf-8", htmlBody
						}
						if tc.mode == "plain" {
							contentType = "text/plain"
						}
						if tc.mode == "xhtml" {
							contentType = "application/xhtml+xml"
						}
						w.Header().Set("Content-Type", contentType)
						w.Header().Set("Vary", "Accept")
						http.SetCookie(w, &http.Cookie{Name: "session", Value: "private-cookie"})
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/app.js", "/app.css":
						if r.Referer() != "" {
							t.Errorf("asset forwarded Referer: %q", r.Referer())
						}
						contentType := "text/javascript"
						if r.URL.Path == "/app.css" {
							contentType = "text/css"
						}
						w.Header().Set("Content-Type", contentType)
						fmt.Fprint(w, "/* private-asset */")
					default:
						t.Errorf("unexpected request path: %q", r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				path, wantPaths := "/page", []string{"/page"}
				if tc.redirect {
					path, wantPaths = "/start", []string{"/start", "/page"}
				}
				if tc.assets && tc.found {
					wantPaths = append(wantPaths, "/app.js", "/app.css")
				}
				args := append([]string{"--redact-query", "--color=always"}, tc.flags...)
				if format == "plain" {
					args = append(args, "--no-color")
				}
				if format == "json" {
					args = append(args, "--json")
				}
				if tc.assets {
					args = append(args, "--assets")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL+path+"?token=private-query"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, &stderr)
				}
				mu.Lock()
				paths := append([]string(nil), visited...)
				mu.Unlock()
				if !reflect.DeepEqual(paths, wantPaths) {
					t.Errorf("requests=%v want=%v (no fallback or guessed paths)", paths, wantPaths)
				}
				for _, raw := range []string{"private-", "Synthetic timestamp", "Whitelabel Error Page", "Express"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("unexpected response/redirect data in report: %q", raw)
					}
				}
				if strings.Contains(stdout.String(), "\x1b") != (format == "color" && tc.found) {
					t.Error("incorrect color handling")
				}
				if format != "json" {
					marker := "?"
					if format == "color" {
						marker = "\x1b[33m?\x1b[0m"
					}
					if strings.Contains(stdout.String(), marker+" Spring Boot [framework]") != tc.found || strings.Contains(stdout.String(), "No technologies detected.") == tc.found || !strings.Contains(stdout.String(), fmt.Sprintf("HTTP status: %d", tc.status)) {
						t.Errorf("unexpected terminal report: %s", &stdout)
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				wantBody := jsonBody
				if tc.found || tc.mode == "success" || tc.mode == "plain" {
					wantBody = htmlBody
				}
				scope := "http_error_response"
				if tc.status == 200 {
					scope = "final_response"
				}
				redirects := 0
				if tc.redirect {
					redirects = 1
				}
				if report.SchemaVersion != 1 || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(wantBody) || !report.QueryRedacted || report.URL != server.URL+path+"?[redacted]" || report.FinalURL != server.URL+"/page?[redacted]" || len(report.Redirects) != redirects || (report.Assets != nil) != tc.assets || report.Findings == nil {
					t.Fatalf("unexpected metadata: %+v", report)
				}
				if !tc.found {
					if len(report.Findings) != 0 {
						t.Errorf("unexpected findings: %+v", report.Findings)
					}
				} else {
					if len(report.Findings) != 1 {
						t.Fatalf("unexpected findings: %+v", report.Findings)
					}
					f := report.Findings[0]
					if f.ID != "spring-boot" || f.Name != "Spring Boot" || f.Category != "framework" || f.State != "inferred" || len(f.Evidence) != 1 {
						t.Fatalf("unexpected finding: %+v", f)
					}
					e := f.Evidence[0]
					if e.RuleID != "whitelabel-error-html" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []output.Signal{{Source: "html"}, {Source: "html"}, {Source: "html"}}) {
						t.Errorf("unexpected evidence: %+v", e)
					}
				}
				if tc.assets {
					if tc.found {
						if report.Assets.Status != "complete" || report.Assets.Attempted != 2 || report.Assets.Collected != 2 {
							t.Errorf("unexpected asset report: %+v", report.Assets)
						}
					} else if report.Assets.Status != "skipped" || report.Assets.Reason != "unsupported_page_type" || report.Assets.Attempted != 0 {
						t.Errorf("unexpected asset skip: %+v", report.Assets)
					}
				}
			})
		}
	}
}
