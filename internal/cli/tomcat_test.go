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

func TestTomcatThroughCLI(t *testing.T) {
	fixture, err := os.ReadFile("../detect/testdata/coverage/tomcat-error.html")
	if err != nil {
		t.Fatal(err)
	}
	const title = `<title>HTTP Status 404 – Not Found</title>`
	const heading = `<h1>HTTP Status 404 – Not Found</h1>`
	const footer = `<h3>Apache Tomcat/11.0.27</h3>`
	const serverBanner = "Apache Tomcat/11.0.27"
	const powered = "Servlet/6.1 JSP/4.0 (Apache Tomcat/11.0.27 Java/Private Vendor/21.0.8+9-LTS)"
	for _, tc := range []struct {
		name, body, contentType, server, powered, hopBody string
		status, assetStatus                               int
		rules                                             []string
		detected, apache, redirect, assets                bool
	}{
		{name: "error-404", body: string(fixture), status: 404, rules: []string{"error-report-html"}},
		{name: "error-500", body: string(fixture), status: 500, rules: []string{"error-report-html"}},
		{name: "successful-copy", body: string(fixture), status: 200},
		{name: "footer-only", body: footer, status: 404},
		{name: "title-heading-only", body: title + heading, status: 404},
		{name: "generic-error", body: "Not Found", status: 404},
		{name: "non-html", body: string(fixture), contentType: "text/plain", status: 404},
		{name: "server", server: serverBanner, status: 200, detected: true, rules: []string{"server-header"}},
		{name: "powered", powered: powered, status: 200, detected: true, rules: []string{"powered-by-header"}},
		{name: "both-headers", server: serverBanner, powered: powered, status: 200, detected: true, rules: []string{"powered-by-header", "server-header"}},
		{name: "all-evidence", body: string(fixture), server: serverBanner, powered: powered, status: 404, detected: true, rules: []string{"error-report-html", "powered-by-header", "server-header"}},
		{name: "apache-and-tomcat", body: string(fixture), server: "Apache/2.4.62 (Unix) PHP/8.3", status: 404, apache: true, rules: []string{"error-report-html"}},
		{name: "malformed-server", server: "Apache Tomcat/11..27", status: 200},
		{name: "ambiguous-bare-apache-module", server: "Apache PHP/8.3", status: 200},
		{name: "generic-servlet", powered: "Servlet/6.1 JSP/4.0", status: 200},
		{name: "header-on-non-html-error", server: serverBanner, contentType: "application/json", status: 403, detected: true, rules: []string{"server-header"}},
		{name: "redirect-only", redirect: true, hopBody: string(fixture), status: 404},
		{name: "redirect-to-error", redirect: true, body: string(fixture), status: 404, rules: []string{"error-report-html"}},
		{name: "split-across-redirect", redirect: true, hopBody: title + heading, body: footer, status: 404},
		{name: "redirect-to-successful-copy", redirect: true, body: string(fixture), status: 200},
		{name: "asset-error-not-page-error", body: string(fixture), status: 200, assets: true, assetStatus: 404},
		{name: "asset-html-not-page-html", body: footer, status: 404, assets: true, assetStatus: 200},
	} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				var mu sync.Mutex
				var paths []string
				unexpected := false
				body := tc.body
				if tc.assets {
					body += `<script src="/app.js?token=private-query"></script>`
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					paths = append(paths, r.Method+" "+r.URL.Path)
					unexpected = unexpected || r.Method != "GET" || r.Header.Get("Cookie") != "" || r.URL.Query().Get("token") != "private-query"
					mu.Unlock()
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Server", serverBanner)
						w.Header().Set("X-Powered-By", powered)
						http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "private-hop-cookie", Path: "/"})
						w.Header().Set("Location", "/final?token=private-query")
						w.Header().Set("Content-Type", "text/html")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, tc.hopBody)
					case "/final":
						contentType := tc.contentType
						if contentType == "" {
							contentType = "text/html"
						}
						w.Header().Set("Content-Type", contentType)
						w.Header().Set("X-Example", powered)
						http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "private-cookie", Path: "/"})
						for name, value := range map[string]string{"Server": tc.server, "X-Powered-By": tc.powered} {
							if value != "" {
								w.Header().Add(name, value)
								w.Header().Add(name, value)
							}
						}
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/app.js":
						w.Header().Set("Content-Type", "application/javascript")
						w.WriteHeader(tc.assetStatus)
						fmt.Fprint(w, string(fixture))
					default:
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				path := "/final"
				wantRedirects := 0
				wantPaths := []string{"GET /final"}
				if tc.redirect {
					path = "/start"
					wantRedirects = 1
					wantPaths = []string{"GET /start", "GET /final"}
				}
				args := []string{"--redact-query", "--color=always"}
				if format == "plain" {
					args = append(args, "--no-color")
				} else if format == "json" {
					args = append(args, "--json")
				}
				if tc.assets {
					args = append(args, "--assets")
					wantPaths = append(wantPaths, "GET /app.js")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL+path+"?token=private-query"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, &stderr)
				}
				mu.Lock()
				visited, hadUnexpected := append([]string(nil), paths...), unexpected
				mu.Unlock()
				if !reflect.DeepEqual(visited, wantPaths) || hadUnexpected {
					t.Errorf("unexpected requests: %v (invalid request=%t), want %v", visited, hadUnexpected, wantPaths)
				}
				for _, raw := range []string{"11.0.27", "Private Vendor", "21.0.8", "private-error-message", "private-cookie", "private-hop-cookie", "private-query"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw response/query value leaked: %q", raw)
					}
				}
				if strings.Contains(stdout.String(), "\x1b") != (format == "color" && (tc.apache || len(tc.rules) > 0)) {
					t.Error("incorrect color handling")
				}
				wantIDs := []string{}
				wantLines := []string{}
				marker := func(symbol string) string {
					if format == "color" {
						code := "33"
						if symbol == "✓" {
							code = "32"
						}
						return "\x1b[" + code + "m" + symbol + "\x1b[0m"
					}
					return symbol
				}
				if tc.apache {
					wantIDs = append(wantIDs, "apache")
					wantLines = append(wantLines, marker("✓")+" Apache HTTP Server [web server]")
				}
				if len(tc.rules) > 0 {
					wantIDs = append(wantIDs, "tomcat")
					symbol := "?"
					if tc.detected {
						symbol = "✓"
					}
					wantLines = append(wantLines, marker(symbol)+" Apache Tomcat [web server]")
				}
				if format != "json" {
					gotLines := []string{}
					stripColor := strings.NewReplacer("\x1b[32m", "", "\x1b[33m", "", "\x1b[0m", "")
					for _, line := range strings.Split(stdout.String(), "\n") {
						plain := stripColor.Replace(line)
						if (strings.HasPrefix(plain, "✓ ") || strings.HasPrefix(plain, "? ")) && strings.Contains(plain, " [") {
							gotLines = append(gotLines, line)
						}
					}
					if !reflect.DeepEqual(gotLines, wantLines) || strings.Contains(stdout.String(), "No technologies detected.") != (len(wantIDs) == 0) {
						t.Errorf("findings=%v want=%v; output=%s", gotLines, wantLines, &stdout)
					}
					if strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") != (tc.status >= 400) {
						t.Error("incorrect error response scope")
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
				if report.SchemaVersion != 1 || report.HTTPStatus != tc.status || report.ResponseScope != scope || !report.QueryRedacted || report.URL != server.URL+path+"?[redacted]" || report.FinalURL != server.URL+"/final?[redacted]" || report.BodyBytes != len(body) || len(report.Redirects) != wantRedirects || (report.Assets != nil) != tc.assets {
					t.Errorf("unexpected metadata: %+v", report)
				}
				ids := []string{}
				for _, finding := range report.Findings {
					ids = append(ids, finding.ID)
					rules, state, name := tc.rules, "inferred", "Apache Tomcat"
					if tc.detected {
						state = "detected"
					}
					if finding.ID == "apache" {
						rules, state, name = []string{"server-header"}, "detected", "Apache HTTP Server"
					}
					if finding.Name != name || finding.Category != "web_server" || finding.State != state || len(finding.Evidence) != len(rules) {
						t.Fatalf("unexpected finding: %+v", finding)
					}
					for i, e := range finding.Evidence {
						signals := []output.Signal{{Source: "header", Name: "Server"}}
						if rules[i] == "powered-by-header" {
							signals[0].Name = "X-Powered-By"
						}
						if rules[i] == "error-report-html" {
							signals = []output.Signal{{Source: "html"}, {Source: "html"}, {Source: "html"}}
						}
						if e.RuleID != rules[i] || e.InferredFrom != "" || e.AssetURL != "" || !strings.Contains(e.Description, "may be an intermediary") || !reflect.DeepEqual(e.Signals, signals) {
							t.Errorf("unexpected evidence: %+v", e)
						}
					}
				}
				if report.Findings == nil || !reflect.DeepEqual(ids, wantIDs) {
					t.Errorf("IDs=%v want=%v", ids, wantIDs)
				}
				if tc.assets {
					wantCollected := 0
					if tc.assetStatus == 200 {
						wantCollected = 1
					}
					if report.Assets == nil || report.Assets.Attempted != 1 || report.Assets.Collected != wantCollected {
						t.Errorf("unexpected asset collection: %+v", report.Assets)
					}
				}
			})
		}
	}
}
