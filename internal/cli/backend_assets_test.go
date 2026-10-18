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

func TestCLIBackendAndNegotiatedAssetEvidence(t *testing.T) {
	fixtures := make(map[string]string)
	for _, name := range []string{"spring-boot-reactive-error.html", "react-19-client.min.js", "bootstrap-5.3.min.css", "tomcat-error.html"} {
		body, err := os.ReadFile("../detect/testdata/coverage/" + name)
		if err != nil {
			t.Fatal(err)
		}
		fixtures[name] = string(body)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	const django = `<input type="hidden" name="csrfmiddlewaretoken" value="private-django-token">`
	const railsParam = `<meta name="csrf-param" content="authenticity_token">`
	const railsToken = `<meta name="csrf-token" content="private-rails-token">`
	const jsonBody = `{"status":404,"private":"private-response"}`
	const allIDs = "bootstrap django laravel php python rails react ruby spring-boot tomcat"
	completeBackend := fixtures["spring-boot-reactive-error.html"] + django + railsParam + railsToken
	// These complete backend markers occur only in asset bodies in partial-page
	// cases. Asset headers also expose other identities, never page evidence.
	assetDecoys := "\n/* " + completeBackend + fixtures["tomcat-error.html"] + " */"
	js, css := fixtures["react-19-client.min.js"], fixtures["bootstrap-5.3.min.css"]
	for _, tc := range []struct {
		name, mode, ids                                string
		flags                                          []string
		html, assets, wrongKind, jsFailed, noDirectPHP bool
		status                                         int
	}{
		{name: "preferred-html-and-assets", flags: []string{"--prefer-html"}, html: true, assets: true, status: 404, ids: allIDs},
		{name: "preferred-html-page-only", flags: []string{"--prefer-html"}, html: true, status: 404, ids: "django laravel php python rails ruby spring-boot tomcat"},
		{name: "default-json-skips-assets", assets: true, status: 404, ids: "laravel php tomcat"},
		{name: "explicit-false-skips-assets", flags: []string{"--prefer-html=false"}, assets: true, status: 404, ids: "laravel php tomcat"},
		{name: "default-request-can-still-receive-html", mode: "always-html", html: true, assets: true, status: 404, ids: allIDs},
		{name: "asset-markers-do-not-complete-page-pairs", mode: "partial", flags: []string{"--prefer-html"}, html: true, assets: true, status: 404, ids: "bootstrap laravel php react tomcat"},
		{name: "wrong-kind-bodies-are-not-cross-matched", flags: []string{"--prefer-html"}, html: true, assets: true, wrongKind: true, status: 404, ids: "django laravel php python rails ruby spring-boot tomcat"},
		{name: "failed-js-keeps-css-and-page-findings", flags: []string{"--prefer-html"}, html: true, assets: true, jsFailed: true, status: 404, ids: "bootstrap django laravel php python rails ruby spring-boot tomcat"},
		{name: "successful-page-excludes-error-rule", flags: []string{"--prefer-html"}, html: true, assets: true, status: 200, ids: "bootstrap django laravel php python rails react ruby tomcat"},
		{name: "php-inference-keeps-laravel-provenance", flags: []string{"--prefer-html"}, html: true, assets: true, noDirectPHP: true, status: 404, ids: allIDs},
	} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				htmlBody := completeBackend
				if tc.mode == "partial" {
					for _, marker := range []string{django, railsToken, "<h1>Whitelabel Error Page</h1>"} {
						htmlBody = strings.ReplaceAll(htmlBody, marker, "")
					}
				}
				// Inline JS/CSS text is insufficient for asset-only rules, even
				// on an HTML page selected by content negotiation.
				htmlBody += "<script>" + js + "</script><style>" + css + "</style>"
				htmlBody += `<script src="/app.js?token=private-query"></script><link rel="stylesheet" href="/app.css?token=private-query">`
				jsBody, cssBody := js+assetDecoys, css+assetDecoys
				if tc.wrongKind {
					jsBody, cssBody = cssBody, jsBody
				}
				var mu sync.Mutex
				visited := []string{}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					visited = append(visited, r.URL.Path)
					mu.Unlock()
					page := r.URL.Path == "/start" || r.URL.Path == "/page"
					wantAccept := ""
					if page && len(tc.flags) == 1 && tc.flags[0] == "--prefer-html" {
						wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
					}
					if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept") != wantAccept || r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.URL.Query().Get("token") != "private-query" || (!page && r.Referer() != "") {
						t.Errorf("unexpected request policy: %s %s %v", r.Method, r.URL, r.Header)
					}
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Server", "Jetty(12.0.16)")
						w.Header().Set("X-Powered-By", "Express")
						w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
						http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "private-hop-cookie"})
						w.Header().Set("Location", "/page?token=private-query")
						w.WriteHeader(302)
						fmt.Fprint(w, completeBackend)
					case "/page":
						contentType, body := "application/json", jsonBody
						if strings.Contains(r.Header.Get("Accept"), "text/html") || tc.mode == "always-html" {
							contentType, body = "text/html; charset=utf-8", htmlBody
						}
						w.Header().Set("Content-Type", contentType)
						w.Header().Set("Vary", "Accept")
						w.Header().Set("Server", "Apache Tomcat/11.0.27")
						if !tc.noDirectPHP {
							w.Header().Add("X-Powered-By", "PHP/8.3.12")
							w.Header().Add("X-Powered-By", "PHP/8.3.12")
						}
						for _, name := range []string{"csrftoken", "laravel_session", "XSRF-TOKEN"} {
							http.SetCookie(w, &http.Cookie{Name: name, Value: "private-cookie", Path: "/"})
						}
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/app.js", "/app.css":
						w.Header().Set("Server", "Jetty(12.0.16)")
						w.Header().Set("X-Powered-By", "Express")
						contentType, body, status := "text/javascript", jsBody, 200
						if r.URL.Path == "/app.css" {
							contentType, body = "text/css", cssBody
						} else if tc.jsFailed {
							status = 403
						}
						w.Header().Set("Content-Type", contentType)
						w.WriteHeader(status)
						fmt.Fprint(w, body)
					default:
						t.Errorf("unexpected request path: %q", r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				args := append([]string{"--redact-query", "--color=always"}, tc.flags...)
				if format == "plain" {
					args = append(args, "--no-color")
				} else if format == "json" {
					args = append(args, "--json")
				}
				if tc.assets {
					args = append(args, "--assets")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL+"/start?token=private-query"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, &stderr)
				}
				wantPaths := []string{"/start", "/page"}
				if tc.html && tc.assets {
					wantPaths = append(wantPaths, "/app.js", "/app.css")
				}
				mu.Lock()
				paths := append([]string(nil), visited...)
				mu.Unlock()
				if !reflect.DeepEqual(paths, wantPaths) {
					t.Errorf("requests=%v want=%v", paths, wantPaths)
				}
				for _, raw := range []string{"private-", "Synthetic timestamp", "Whitelabel Error Page", "11.0.27", "Jetty", "Express"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw value or non-page identity leaked: %q", raw)
					}
				}
				if strings.Contains(stdout.String(), "\x1b") != (format == "color") {
					t.Error("incorrect color handling")
				}
				// Reuse only expectation data types, not detector-derived results.
				cookies := []output.Signal{{Source: "cookie"}, {Source: "cookie"}}
				htmlSignals := []output.Signal{{Source: "html"}, {Source: "html"}}
				want := map[string]mixedFinding{
					"bootstrap":   {"bootstrap", "Bootstrap", "ui_framework", "UI framework", "inferred", []mixedEvidence{{rule: "asset-css-banner-and-buttons", signals: []output.Signal{{Source: "asset_css"}, {Source: "asset_css"}}}}},
					"django":      {"django", "Django", "framework", "framework", "inferred", []mixedEvidence{{rule: "csrf-cookie-and-input", signals: []output.Signal{{Source: "cookie"}, {Source: "html"}}}}},
					"laravel":     {"laravel", "Laravel", "framework", "framework", "inferred", []mixedEvidence{{rule: "default-cookie-pair", signals: cookies}}},
					"php":         {"php", "PHP", "language", "language", "inferred", []mixedEvidence{{from: "laravel", signals: []output.Signal{}}}},
					"python":      {"python", "Python", "language", "language", "inferred", []mixedEvidence{{from: "django", signals: []output.Signal{}}}},
					"rails":       {"rails", "Ruby on Rails", "framework", "framework", "inferred", []mixedEvidence{{rule: "csrf-meta-pair", signals: htmlSignals}}},
					"react":       {"react", "React", "javascript_framework", "JavaScript framework", "inferred", []mixedEvidence{{rule: "asset-client-runtime", signals: []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}}}},
					"ruby":        {"ruby", "Ruby", "language", "language", "inferred", []mixedEvidence{{from: "rails", signals: []output.Signal{}}}},
					"spring-boot": {"spring-boot", "Spring Boot", "framework", "framework", "inferred", []mixedEvidence{{rule: "whitelabel-error-html", signals: []output.Signal{{Source: "html"}, {Source: "html"}, {Source: "html"}}}}},
					"tomcat":      {"tomcat", "Apache Tomcat", "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
				}
				if !tc.noDirectPHP {
					php := want["php"]
					php.state = "detected"
					php.evidence = append([]mixedEvidence{mixedHeader("powered-by-header", "X-Powered-By")}, php.evidence...)
					want["php"] = php
				}
				ids := strings.Fields(tc.ids)
				if format != "json" {
					gotLines, wantLines := []string{}, []string{}
					strip := strings.NewReplacer("\x1b[32m", "", "\x1b[33m", "", "\x1b[0m", "")
					for _, line := range strings.Split(stdout.String(), "\n") {
						plain := strip.Replace(line)
						if (strings.HasPrefix(plain, "✓ ") || strings.HasPrefix(plain, "? ")) && strings.Contains(plain, " [") {
							gotLines = append(gotLines, line)
						}
					}
					for _, id := range ids {
						f := want[id]
						marker, color := "?", "33"
						if f.state == "detected" {
							marker, color = "✓", "32"
						}
						if format == "color" {
							marker = "\x1b[" + color + "m" + marker + "\x1b[0m"
						}
						wantLines = append(wantLines, marker+" "+f.name+" ["+f.label+"]")
						if id == "react" || id == "bootstrap" {
							ext := map[string]string{"react": "js", "bootstrap": "css"}[id]
							if !strings.Contains(stdout.String(), "Asset: "+server.URL+"/app."+ext+"?[redacted]") {
								t.Errorf("missing redacted asset evidence for %s", id)
							}
						}
					}
					if !reflect.DeepEqual(gotLines, wantLines) || strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") != (tc.status >= 400) {
						t.Errorf("findings=%v want=%v", gotLines, wantLines)
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				body, scope := jsonBody, "http_error_response"
				if tc.html {
					body = htmlBody
				}
				if tc.status == 200 {
					scope = "final_response"
				}
				redirects := []output.Redirect{{FromURL: server.URL + "/start?[redacted]", ToURL: server.URL + "/page?[redacted]", StatusCode: 302}}
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.URL != server.URL+"/start?[redacted]" || report.FinalURL != server.URL+"/page?[redacted]" || !report.QueryRedacted || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(body) || !reflect.DeepEqual(report.Redirects, redirects) || (report.Assets != nil) != tc.assets {
					t.Fatalf("unexpected metadata: %+v", report)
				}
				if report.Findings == nil || len(report.Findings) != len(ids) {
					t.Fatalf("findings=%+v want IDs=%v", report.Findings, ids)
				}
				for i, id := range ids {
					f, expected := report.Findings[i], want[id]
					if f.ID != id || f.Name != expected.name || f.Category != expected.category || f.State != expected.state || len(f.Evidence) != len(expected.evidence) {
						t.Fatalf("finding=%+v want=%+v", f, expected)
					}
					for j, e := range f.Evidence {
						wantEvidence, assetURL := expected.evidence[j], ""
						if id == "react" || id == "bootstrap" {
							ext := map[string]string{"react": "js", "bootstrap": "css"}[id]
							assetURL = server.URL + "/app." + ext + "?[redacted]"
						}
						if e.Description == "" || e.RuleID != wantEvidence.rule || e.InferredFrom != wantEvidence.from || e.AssetURL != assetURL || !reflect.DeepEqual(e.Signals, wantEvidence.signals) {
							t.Errorf("%s evidence=%+v want=%+v URL=%q", id, e, wantEvidence, assetURL)
						}
					}
					if id == "python" || id == "ruby" || (id == "php" && tc.noDirectPHP) {
						requireLanguageReport(t, f, id, map[string]string{"python": "django", "ruby": "rails", "php": "laravel"}[id])
					}
				}
				if tc.assets {
					a := report.Assets
					if !tc.html {
						if a.Status != "skipped" || a.Reason != "unsupported_page_type" || a.Attempted != 0 || a.Collected != 0 || a.Items == nil || len(a.Items) != 0 {
							t.Errorf("unexpected skipped assets: %+v", a)
						}
					} else {
						status, collected := "complete", 2
						if tc.jsFailed {
							status, collected = "incomplete", 1
						}
						if a.Status != status || a.Attempted != 2 || a.Collected != collected || len(a.Items) != 2 {
							t.Fatalf("unexpected assets: %+v", a)
						}
						for i, ext := range []string{"js", "css"} {
							item, status, reason, httpStatus := a.Items[i], "collected", "", 200
							if i == 0 && tc.jsFailed {
								status, reason, httpStatus = "failed", "unsuccessful_status", 403
							}
							if item.URL != server.URL+"/app."+ext+"?[redacted]" || item.Status != status || item.Reason != reason || item.HTTPStatus != httpStatus {
								t.Errorf("unexpected asset item: %+v", item)
							}
						}
					}
				}
			})
		}
	}
}
