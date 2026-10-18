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

func TestSpringBootThroughCLI(t *testing.T) {
	servlet, err := os.ReadFile("../detect/testdata/coverage/spring-boot-servlet-error.html")
	if err != nil {
		t.Fatal(err)
	}
	reactive, err := os.ReadFile("../detect/testdata/coverage/spring-boot-reactive-error.html")
	if err != nil {
		t.Fatal(err)
	}
	const mediaType = "application/vnd.spring-boot.actuator.v3+json"
	const heading = `<h1>Whitelabel Error Page</h1>`
	const fallback = `<p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>`
	const details = `<div>There was an unexpected error (type=Not Found, status=404).</div>`
	const tomcatBanner = "Apache Tomcat/11.0.27"
	for _, tc := range []struct {
		name, body, contentType, rule, hopBody string
		status, assetStatus                    int
		tomcat, redirect, assets               bool
	}{
		{name: "servlet", body: string(servlet), status: 404, rule: "whitelabel-error-html"},
		{name: "reactive", body: string(reactive), status: 500, rule: "whitelabel-error-html"},
		{name: "successful-copy", body: string(servlet), status: 200},
		{name: "heading-only", body: heading, status: 404},
		{name: "missing-details", body: heading + fallback, status: 404},
		{name: "wrong-body-status", body: strings.ReplaceAll(string(servlet), "status=404", "status=200"), status: 404},
		{name: "plain-error", body: string(servlet), contentType: "text/plain", status: 404},
		{name: "generic-json", body: `{"status":404,"error":"Not Found","path":"/error"}`, contentType: "application/json", status: 404},
		{name: "actuator-v3", body: `{"private":"private-spring-message"}`, contentType: mediaType, status: 200, rule: "actuator-media-type"},
		{name: "actuator-v2-charset", body: `{}`, contentType: "application/vnd.spring-boot.actuator.v2+json;charset=UTF-8", status: 200, rule: "actuator-media-type"},
		{name: "unsupported-api-version", body: `{}`, contentType: "application/vnd.spring-boot.actuator.v4+json", status: 200},
		{name: "json-mime-excludes-html", body: string(servlet), contentType: mediaType, status: 404, rule: "actuator-media-type"},
		{name: "tomcat-and-whitelabel", body: string(servlet), status: 404, rule: "whitelabel-error-html", tomcat: true},
		{name: "tomcat-and-actuator", body: `{}`, contentType: mediaType, status: 200, rule: "actuator-media-type", tomcat: true},
		{name: "redirect-only", redirect: true, hopBody: string(servlet), status: 404},
		{name: "redirect-to-error", redirect: true, body: string(servlet), status: 404, rule: "whitelabel-error-html"},
		{name: "split-across-redirect", redirect: true, hopBody: heading + fallback, body: details, status: 404},
		{name: "asset-markers-not-page-markers", body: heading, status: 404, assets: true, assetStatus: 200},
		{name: "asset-error-not-page-error", body: string(servlet), status: 200, assets: true, assetStatus: 404},
	} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				var mu sync.Mutex
				paths := []string{}
				unexpected := false
				body := tc.body
				if tc.assets {
					body += `<script src="/app.js?token=private-query"></script>`
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					paths = append(paths, r.Method+" "+r.URL.Path)
					unexpected = unexpected || r.Method != "GET" || r.Header.Get("Accept") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("User-Agent") != "webscan" || r.URL.Query().Get("token") != "private-query"
					mu.Unlock()
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Content-Type", mediaType)
						w.Header().Set("Server", tomcatBanner)
						http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "private-cookie", Path: "/"})
						w.Header().Set("Location", "/page?token=private-query")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, tc.hopBody)
					case "/page":
						contentType := tc.contentType
						if contentType == "" {
							contentType = "text/html"
						}
						w.Header().Set("Content-Type", contentType)
						w.Header().Set("X-Application-Context", "private-context:8080")
						http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "private-cookie", Path: "/"})
						if tc.tomcat {
							w.Header().Set("Server", tomcatBanner)
						}
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/app.js":
						w.Header().Set("Content-Type", "application/javascript")
						w.WriteHeader(tc.assetStatus)
						fmt.Fprint(w, string(reactive))
					default:
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				path, redirects := "/page", 0
				wantPaths := []string{"GET /page"}
				if tc.redirect {
					path, redirects, wantPaths = "/start", 1, []string{"GET /start", "GET /page"}
				}
				args := []string{"--redact-query", "--color=always"}
				if format == "plain" {
					args = append(args, "--no-color")
				}
				if format == "json" {
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
					t.Errorf("unexpected requests: %v invalid=%t, want %v", visited, hadUnexpected, wantPaths)
				}
				for _, raw := range []string{"private-query", "private-cookie", "private-spring-message", "private-request-id", "private-context", "Synthetic timestamp", mediaType, "11.0.27"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw response value leaked: %q", raw)
					}
				}
				wantIDs := []string{}
				if tc.rule != "" {
					wantIDs = append(wantIDs, "spring-boot")
				}
				if tc.tomcat {
					wantIDs = append(wantIDs, "tomcat")
				}
				if strings.Contains(stdout.String(), "\x1b") != (format == "color" && len(wantIDs) != 0) {
					t.Error("incorrect color handling")
				}
				state, symbol := "inferred", "?"
				if tc.rule == "actuator-media-type" {
					state, symbol = "detected", "✓"
				}
				if format != "json" {
					marker := func(symbol string) string {
						if format != "color" {
							return symbol
						}
						code := "33"
						if symbol == "✓" {
							code = "32"
						}
						return "\x1b[" + code + "m" + symbol + "\x1b[0m"
					}
					wantLines, gotLines := []string{}, []string{}
					if tc.rule != "" {
						wantLines = append(wantLines, marker(symbol)+" Spring Boot [framework]")
					}
					if tc.tomcat {
						wantLines = append(wantLines, marker("✓")+" Apache Tomcat [web server]")
					}
					strip := strings.NewReplacer("\x1b[32m", "", "\x1b[33m", "", "\x1b[0m", "")
					for _, line := range strings.Split(stdout.String(), "\n") {
						plain := strip.Replace(line)
						if (strings.HasPrefix(plain, "✓ ") || strings.HasPrefix(plain, "? ")) && strings.Contains(plain, " [") {
							gotLines = append(gotLines, line)
						}
					}
					if !reflect.DeepEqual(gotLines, wantLines) || strings.Contains(stdout.String(), "No technologies detected.") != (len(wantIDs) == 0) {
						t.Errorf("findings=%v want=%v", gotLines, wantLines)
					}
					if strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") != (tc.status >= 400) {
						t.Error("incorrect error-page scope")
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
				if report.SchemaVersion != 1 || report.HTTPStatus != tc.status || report.ResponseScope != scope || !report.QueryRedacted || report.URL != server.URL+path+"?[redacted]" || report.FinalURL != server.URL+"/page?[redacted]" || report.BodyBytes != len(body) || len(report.Redirects) != redirects || (report.Assets != nil) != tc.assets {
					t.Errorf("unexpected metadata: %+v", report)
				}
				ids := []string{}
				for _, f := range report.Findings {
					ids = append(ids, f.ID)
					wantName, wantCategory, wantState, wantRule := "Spring Boot", "framework", state, tc.rule
					signals := []output.Signal{{Source: "header", Name: "Content-Type"}}
					if f.ID == "tomcat" {
						wantName, wantCategory, wantState, wantRule = "Apache Tomcat", "web_server", "detected", "server-header"
						signals[0].Name = "Server"
					}
					if wantRule == "whitelabel-error-html" {
						signals = []output.Signal{{Source: "html"}, {Source: "html"}, {Source: "html"}}
					}
					if f.Name != wantName || f.Category != wantCategory || f.State != wantState || len(f.Evidence) != 1 {
						t.Fatalf("unexpected finding: %+v", f)
					}
					e := f.Evidence[0]
					if e.RuleID != wantRule || e.InferredFrom != "" || e.AssetURL != "" || !strings.Contains(e.Description, "may be an intermediary") || !reflect.DeepEqual(e.Signals, signals) {
						t.Errorf("unexpected evidence: %+v", e)
					}
				}
				if report.Findings == nil || !reflect.DeepEqual(ids, wantIDs) {
					t.Errorf("IDs=%v want=%v", ids, wantIDs)
				}
				if tc.assets {
					collected := 0
					if tc.assetStatus == 200 {
						collected = 1
					}
					if report.Assets == nil || report.Assets.Attempted != 1 || report.Assets.Collected != collected {
						t.Errorf("unexpected asset metadata: %+v", report.Assets)
					}
				}
			})
		}
	}
}
