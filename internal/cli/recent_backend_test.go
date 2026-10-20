package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

func TestRecentBackendFailedAssetsAndSplitEvidenceThroughCLI(t *testing.T) {
	fixtures := make(map[string]string)
	for _, name := range []string{"fastapi-swagger.html", "fastapi-redoc.html", "react-19-client.min.js", "bootstrap-5.3.min.css"} {
		data, err := os.ReadFile("../detect/testdata/coverage/" + name)
		if err != nil {
			t.Fatal(err)
		}
		fixtures[name] = string(data)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	const icon = `<link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">`
	const django = `<input type="hidden" name="csrfmiddlewaretoken" value="private-token">`
	swagger, redoc := fixtures["fastapi-swagger.html"], fixtures["fastapi-redoc.html"]
	fullDocs := swagger + redoc
	pages := map[string]string{
		"both": fullDocs, "swagger": swagger, "icon": icon,
		"viewer": strings.ReplaceAll(swagger, icon, ""), "empty": "<p>fixture</p>",
	}
	for _, tc := range []struct {
		name, page, server, jsReason, cssReason, ids string
		upgrade, noPageHeaders, nonHTML, prefer      bool
	}{
		{name: "failed-js-keeps-upgraded-caddy-and-both-doc-rules", page: "both", server: "uvicorn", upgrade: true, prefer: true, jsReason: "unsuccessful_status", ids: "bootstrap caddy fastapi fiber uvicorn"},
		{name: "late-css-failure-keeps-page-and-react", page: "swagger", server: "gunicorn", cssReason: "unsuccessful_status", ids: "caddy fastapi fiber gunicorn react"},
		{name: "wrong-js-mime-keeps-page-and-css", page: "swagger", server: "uvicorn", prefer: true, jsReason: "unsuitable_content_type", ids: "bootstrap caddy fastapi fiber uvicorn"},
		{name: "viewer-cannot-borrow-icon-from-hop-or-assets", page: "viewer", server: "gunicorn", cssReason: "unsuccessful_status", ids: "caddy fiber gunicorn react"},
		{name: "icon-cannot-borrow-viewer-from-hop-or-assets", page: "icon", server: "uvicorn", jsReason: "unsuccessful_status", ids: "bootstrap caddy fiber uvicorn"},
		{name: "hop-and-asset-identities-do-not-become-page-findings", page: "empty", noPageHeaders: true, ids: "bootstrap react"},
		{name: "non-html-page-keeps-headers-without-docs-or-assets", page: "both", server: "uvicorn", nonHTML: true, ids: "caddy fiber uvicorn"},
		{name: "hop-and-asset-server-cannot-upgrade-final-via", page: "both", server: "gunicorn", prefer: true, ids: "bootstrap caddy fastapi fiber gunicorn react"},
	} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				// The final page has a Django input but no matching cookie. Cookies
				// on redirects/assets cannot complete it or imply Python.
				body := pages[tc.page] + django + `<script src="/runtime.js?token=private-query"></script><link rel="stylesheet" href="/styles.css?token=private-query">`
				var mu sync.Mutex
				paths := []string{}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					paths = append(paths, r.URL.Path)
					mu.Unlock()
					page := r.URL.Path == "/start" || r.URL.Path == "/page"
					wantAccept := ""
					if page && tc.prefer {
						wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
					}
					if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept") != wantAccept || r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || (!page && r.Referer() != "") || r.URL.Query().Get("token") != "private-query" {
						t.Errorf("unexpected request policy: %s %s %v", r.Method, r.URL, r.Header)
					}
					switch r.URL.Path {
					case "/start":
						for _, banner := range []string{"cAdDy", "fIbEr", "gUnIcOrN", "uViCoRn"} {
							w.Header().Add("Server", banner)
						}
						w.Header().Set("Via", "1.1 cAdDy")
						w.Header().Set("Content-Type", "text/html")
						http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "private-hop-cookie"})
						w.Header().Set("Location", "/page?token=private-query")
						w.WriteHeader(302)
						fmt.Fprint(w, fullDocs+django)
					case "/page":
						contentType := "text/html"
						if tc.nonHTML {
							contentType = "application/json"
						}
						w.Header().Set("Content-Type", contentType)
						w.Header().Set("X-Powered-By", "FastAPI")
						http.SetCookie(w, &http.Cookie{Name: "session", Value: "private-page-cookie"})
						if !tc.noPageHeaders {
							w.Header().Set("Via", "1.1 cAdDy")
							for _, banner := range []string{"fIbEr", "fIbEr", map[string]string{"gunicorn": "gUnIcOrN", "uvicorn": "uViCoRn"}[tc.server]} {
								w.Header().Add("Server", banner)
							}
							if tc.upgrade {
								w.Header().Add("Server", "cAdDy")
							}
						}
						w.WriteHeader(403)
						fmt.Fprint(w, body)
					case "/runtime.js", "/styles.css":
						for _, banner := range []string{"cAdDy", "fIbEr", "gUnIcOrN", "uViCoRn"} {
							w.Header().Add("Server", banner)
						}
						w.Header().Set("Via", "1.1 cAdDy")
						http.SetCookie(w, &http.Cookie{Name: "csrftoken", Value: "private-asset-cookie"})
						payload, contentType, reason := fixtures["react-19-client.min.js"], "text/javascript", tc.jsReason
						if r.URL.Path == "/styles.css" {
							payload, contentType, reason = fixtures["bootstrap-5.3.min.css"], "text/css", tc.cssReason
						}
						if reason == "unsuitable_content_type" {
							contentType = "text/plain"
						}
						w.Header().Set("Content-Type", contentType)
						if reason == "unsuccessful_status" {
							w.WriteHeader(403)
						}
						fmt.Fprint(w, payload+"\n/* "+fullDocs+django+" */")
					default:
						t.Errorf("unexpected request or probe: %s", r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				// Documentation fixtures reference external viewers. Even if asset
				// selection regresses, no connection may leave the local fixture.
				original := http.DefaultTransport
				transport := original.(*http.Transport).Clone()
				transport.Proxy = nil
				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					if addr != server.Listener.Addr().String() {
						t.Errorf("unexpected outbound connection: %s", addr)
						return nil, errors.New("only local fixture connections are permitted")
					}
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}
				http.DefaultTransport = transport
				defer func() { http.DefaultTransport = original; transport.CloseIdleConnections() }()
				args := []string{"--assets", "--redact-query", "--color=always"}
				if tc.prefer {
					args = append(args, "--prefer-html")
				}
				if format == "plain" {
					args = append(args, "--no-color")
				} else if format == "json" {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL+"/start?token=private-query"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q; optional failures must preserve the page report", code, &stderr)
				}
				mu.Lock()
				visited := append([]string(nil), paths...)
				mu.Unlock()
				wantPaths := []string{"/start", "/page"}
				if !tc.nonHTML {
					wantPaths = append(wantPaths, "/runtime.js", "/styles.css")
				}
				if !reflect.DeepEqual(visited, wantPaths) {
					t.Errorf("requests=%v want=%v; no schema/viewer/favicon/path discovery", visited, wantPaths)
				}
				for _, raw := range []string{"private-", "cAdDy", "fIbEr", "gUnIcOrN", "uViCoRn", "csrftoken", "csrfmiddlewaretoken", "SwaggerUIBundle", "fastapi.tiangolo.com", "cdn.jsdelivr.net"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw response data leaked: %q", raw)
					}
				}
				caddyRules, caddyState := []mixedEvidence{mixedHeader("via-header", "Via")}, "inferred"
				if tc.upgrade {
					caddyRules, caddyState = append([]mixedEvidence{mixedHeader("server-header", "Server")}, caddyRules...), "detected"
				}
				docRules := []mixedEvidence{}
				if tc.page == "both" {
					docRules = append(docRules, mixedEvidence{rule: "redoc-html", signals: []output.Signal{{Source: "html"}, {Source: "html"}, {Source: "html"}}})
				}
				docRules = append(docRules, mixedEvidence{rule: "swagger-ui-html", signals: []output.Signal{{Source: "html"}, {Source: "html"}, {Source: "html"}}})
				want := map[string]mixedFinding{
					"caddy":     {"caddy", "Caddy", "web_server", "web server", caddyState, caddyRules},
					"fiber":     {"fiber", "Fiber", "framework", "framework", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
					"fastapi":   {"fastapi", "FastAPI", "framework", "framework", "inferred", docRules},
					"gunicorn":  {"gunicorn", "Gunicorn", "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
					"uvicorn":   {"uvicorn", "Uvicorn", "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
					"react":     {"react", "React", "javascript_framework", "JavaScript framework", "inferred", []mixedEvidence{{rule: "asset-client-runtime", signals: []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}}}},
					"bootstrap": {"bootstrap", "Bootstrap", "ui_framework", "UI framework", "inferred", []mixedEvidence{{rule: "asset-css-banner-and-buttons", signals: []output.Signal{{Source: "asset_css"}, {Source: "asset_css"}}}}},
				}
				ids := strings.Fields(tc.ids)
				status, reason, collected := "complete", "", 2
				if tc.jsReason != "" {
					status, reason, collected = "incomplete", "asset_failures_or_skips", collected-1
				}
				if tc.cssReason != "" {
					status, reason, collected = "incomplete", "asset_failures_or_skips", collected-1
				}
				if tc.nonHTML {
					status, reason, collected = "skipped", "unsupported_page_type", 0
				}
				if strings.Contains(stdout.String(), "\x1b") != (format == "color") {
					t.Error("incorrect color handling")
				}
				if format != "json" {
					strip := strings.NewReplacer("\x1b[32m", "", "\x1b[33m", "", "\x1b[0m", "")
					gotLines, wantLines := []string{}, []string{}
					for _, line := range strings.Split(stdout.String(), "\n") {
						plain := strip.Replace(line)
						if (strings.HasPrefix(plain, "✓ ") || strings.HasPrefix(plain, "? ")) && strings.Contains(plain, " [") {
							gotLines = append(gotLines, line)
						}
					}
					for _, id := range ids {
						f, marker, color := want[id], "?", "33"
						if f.state == "detected" {
							marker, color = "✓", "32"
						}
						if format == "color" {
							marker = "\x1b[" + color + "m" + marker + "\x1b[0m"
						}
						wantLines = append(wantLines, marker+" "+f.name+" ["+f.label+"]")
					}
					if !reflect.DeepEqual(gotLines, wantLines) || !strings.Contains(stdout.String(), "Assets: "+status) || (reason != "" && !strings.Contains(stdout.String(), "Reason: "+reason)) || !strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") {
						t.Errorf("unexpected terminal findings/scope: %s", &stdout)
					}
					for _, asset := range []struct{ id, path string }{{"react", "/runtime.js"}, {"bootstrap", "/styles.css"}} {
						found := false
						for _, id := range ids {
							found = found || id == asset.id
						}
						if strings.Contains(stdout.String(), "Asset: "+server.URL+asset.path+"?[redacted]") != found {
							t.Errorf("incorrect asset evidence for %s", asset.id)
						}
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || !report.QueryRedacted || report.URL != server.URL+"/start?[redacted]" || report.FinalURL != server.URL+"/page?[redacted]" || report.HTTPStatus != 403 || report.ResponseScope != "http_error_response" || report.BodyBytes != len(body) || !reflect.DeepEqual(report.Redirects, []output.Redirect{{FromURL: server.URL + "/start?[redacted]", ToURL: server.URL + "/page?[redacted]", StatusCode: 302}}) || len(report.Findings) != len(ids) {
					t.Fatalf("unexpected report: %+v", report)
				}
				for i, id := range ids {
					f, expected := report.Findings[i], want[id]
					if f.ID != id || f.Name != expected.name || f.Category != expected.category || f.State != expected.state || len(f.Evidence) != len(expected.evidence) {
						t.Fatalf("unexpected finding: %+v", f)
					}
					for j, e := range f.Evidence {
						url := ""
						if id == "react" {
							url = server.URL + "/runtime.js?[redacted]"
						}
						if id == "bootstrap" {
							url = server.URL + "/styles.css?[redacted]"
						}
						if e.RuleID != expected.evidence[j].rule || e.Description == "" || e.InferredFrom != "" || e.AssetURL != url || !reflect.DeepEqual(e.Signals, expected.evidence[j].signals) {
							t.Errorf("unexpected evidence: %+v", e)
						}
					}
				}
				a := report.Assets
				if a == nil {
					t.Fatal("missing asset metadata")
				}
				attempted := len(wantPaths) - 2
				if a.Mode != "fingerprint_inspection" || a.Status != status || a.Reason != reason || a.Attempted != attempted || a.Collected != collected || a.Items == nil || len(a.Items) != attempted {
					t.Fatalf("unexpected collection metadata: %+v", a)
				}
				for i, item := range a.Items {
					path, kind, itemReason := "/runtime.js", "javascript", tc.jsReason
					if i == 1 {
						path, kind, itemReason = "/styles.css", "stylesheet", tc.cssReason
					}
					itemStatus, code := "collected", 200
					if itemReason != "" {
						itemStatus = "failed"
					}
					if itemReason == "unsuccessful_status" {
						code = 403
					}
					if item.URL != server.URL+path+"?[redacted]" || item.Kind != kind || item.Status != itemStatus || item.Reason != itemReason || item.HTTPStatus != code {
						t.Errorf("unexpected asset item: %+v", item)
					}
				}
			})
		}
	}
}
