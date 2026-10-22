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
	"webscan/internal/output"
)

func TestFastAPIDocumentationThroughCLI(t *testing.T) {
	fixtures := make(map[string]string)
	for _, name := range []string{"fastapi-swagger.html", "fastapi-redoc.html", "react-19-client.min.js"} {
		data, err := os.ReadFile("../detect/testdata/coverage/" + name)
		if err != nil {
			t.Fatal(err)
		}
		fixtures[name] = string(data)
	}
	const favicon = `<link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">`
	const empty = `<a href="/docs">Documentation</a>`
	swagger, redoc := fixtures["fastapi-swagger.html"], fixtures["fastapi-redoc.html"]
	swaggerViewer, redocViewer := strings.ReplaceAll(swagger, favicon, ""), strings.ReplaceAll(redoc, favicon, "")
	for _, tc := range []struct {
		name, body, contentType, hop string
		status                       int
		assets, prefer, nginx        bool
		rules                        []string
	}{
		{name: "swagger", body: swagger, status: 200, rules: []string{"swagger-ui-html"}},
		{name: "redoc", body: redoc, status: 200, rules: []string{"redoc-html"}},
		{name: "both-and-duplicates", body: swagger + redoc + swagger, status: 200, rules: []string{"redoc-html", "swagger-ui-html"}},
		{name: "generic-swagger", body: swaggerViewer, status: 200},
		{name: "generic-redoc", body: redocViewer, status: 200},
		{name: "favicon-only", body: favicon, status: 200},
		{name: "lookalike-favicon", body: strings.ReplaceAll(swagger, "fastapi.tiangolo.com", "fastapi.tiangolo.com.evil.test"), status: 200},
		{name: "plain-html-decoy", body: swagger, contentType: "text/plain", status: 200},
		{name: "json-html-decoy", body: redoc, contentType: "application/json", status: 200},
		{name: "generic-api-error", body: `{"detail":"Not Found"}`, contentType: "application/json", status: 404},
		{name: "xhtml", body: redoc, contentType: "application/xhtml+xml", status: 200, rules: []string{"redoc-html"}},
		{name: "error-response", body: swagger, status: 403, rules: []string{"swagger-ui-html"}},
		{name: "link-is-not-discovery", body: empty, status: 200},
		{name: "redirect-only", body: empty, hop: swagger + redoc, status: 200},
		{name: "redirect-icon-cannot-complete-page", body: swaggerViewer, hop: favicon, status: 200},
		{name: "redirect-viewer-cannot-complete-page", body: favicon, hop: swaggerViewer, status: 200},
		{name: "redirect-to-redoc", body: redoc, hop: empty, status: 200, prefer: true, rules: []string{"redoc-html"}},
		{name: "asset-only-docs", body: empty, status: 200, assets: true},
		{name: "asset-viewer-cannot-complete-page", body: favicon, status: 200, assets: true},
		{name: "asset-icon-cannot-complete-page", body: swaggerViewer, status: 200, assets: true},
		{name: "page-docs-and-assets", body: redoc, status: 403, assets: true, prefer: true, nginx: true, rules: []string{"redoc-html"}},
	} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				body := tc.body
				if tc.assets {
					body += `<script src="/runtime.js?token=private-query"></script><link rel="stylesheet" href="/styles.css?token=private-query">`
				}
				var mu sync.Mutex
				paths := []string{}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					paths = append(paths, r.URL.Path)
					mu.Unlock()
					page := r.URL.Path == "/start" || r.URL.Path == "/reference"
					wantAccept := ""
					if page && tc.prefer {
						wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
					}
					if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept") != wantAccept || r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.URL.Query().Get("token") != "private-query" || (!page && r.Referer() != "") {
						t.Errorf("unexpected request policy: %s %s %v", r.Method, r.URL, r.Header)
					}
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Server", "Fiber")
						w.Header().Set("Location", "/reference?token=private-query")
						w.WriteHeader(302)
						fmt.Fprint(w, tc.hop)
					case "/reference":
						contentType := tc.contentType
						if contentType == "" {
							contentType = "text/html"
						}
						w.Header().Set("Content-Type", contentType)
						// Distinguish the raw banner from the legitimate JSON ID.
						w.Header().Set("Server", "uViCoRn")
						if tc.nginx {
							w.Header().Add("Server", "nginx")
						}
						w.Header().Set("X-Powered-By", "FastAPI")
						http.SetCookie(w, &http.Cookie{Name: "session", Value: "private-cookie"})
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/runtime.js":
						w.Header().Set("Content-Type", "text/javascript")
						w.Header().Set("Server", "Fiber")
						fmt.Fprint(w, fixtures["react-19-client.min.js"]+"\n/* "+swagger+redoc+" */")
					case "/styles.css":
						w.Header().Set("Content-Type", "text/css")
						fmt.Fprint(w, "/* "+swagger+redoc+" */")
					default:
						t.Errorf("unexpected path or probe: %s", r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				// Keep the test entirely local even if off-origin asset policy regresses.
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
				path, wantPaths := "/reference", []string{"/reference"}
				if tc.hop != "" {
					path, wantPaths = "/start", []string{"/start", "/reference"}
				}
				if tc.assets {
					wantPaths = append(wantPaths, "/runtime.js", "/styles.css")
				}
				args := []string{"--redact-query", "--color=always"}
				if tc.assets {
					args = append(args, "--assets")
				}
				if tc.prefer {
					args = append(args, "--prefer-html")
				}
				if format == "plain" {
					args = append(args, "--no-color")
				} else if format == "json" {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL+path+"?token=private-query"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, &stderr)
				}
				mu.Lock()
				visited := append([]string(nil), paths...)
				mu.Unlock()
				if !reflect.DeepEqual(visited, wantPaths) {
					t.Errorf("requests=%v want=%v; no schema, favicon, viewer or docs probes", visited, wantPaths)
				}
				for _, raw := range []string{"private-", "uViCoRn", "Fiber", "Example API", "fastapi.tiangolo.com", "cdn.jsdelivr.net", "SwaggerUIBundle"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw body/header value leaked: %q", raw)
					}
				}
				ids := []string{}
				if len(tc.rules) != 0 {
					ids = append(ids, "fastapi")
				}
				if tc.nginx {
					ids = append(ids, "nginx")
				}
				if tc.assets {
					ids = append(ids, "react")
				}
				// Every final response declares Uvicorn independently of the
				// page's complete, partial or absent documentation markers.
				ids = append(ids, "uvicorn")
				fastAPIEvidence := []mixedEvidence{}
				for _, rule := range tc.rules {
					fastAPIEvidence = append(fastAPIEvidence, mixedEvidence{rule: rule, signals: []output.Signal{{Source: "html"}, {Source: "html"}, {Source: "html"}}})
				}
				want := map[string]mixedFinding{
					"fastapi": {"fastapi", "FastAPI", "framework", "framework", "inferred", fastAPIEvidence},
					"nginx":   {"nginx", "nginx", "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
					"react":   {"react", "React", "javascript_framework", "JavaScript framework", "inferred", []mixedEvidence{{rule: "asset-client-runtime", signals: []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}}}},
					"uvicorn": {"uvicorn", "Uvicorn", "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
				}
				assetURL := server.URL + "/runtime.js?[redacted]"
				if strings.Contains(stdout.String(), "\x1b") != (format == "color" && len(ids) != 0) {
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
						f := want[id]
						marker, color := "?", "33"
						if f.state == "detected" {
							marker, color = "✓", "32"
						}
						if format == "color" {
							marker = "\x1b[" + color + "m" + marker + "\x1b[0m"
						}
						wantLines = append(wantLines, marker+" "+f.name+" ["+f.label+"]")
					}
					if !reflect.DeepEqual(gotLines, wantLines) || strings.Contains(stdout.String(), "No technologies detected.") != (len(ids) == 0) || strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") != (tc.status >= 400) {
						t.Errorf("unexpected findings/scope: %s", &stdout)
					}
					if tc.assets && !strings.Contains(stdout.String(), "Asset: "+assetURL) {
						t.Error("missing redacted React asset evidence")
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
				redirects := []output.Redirect{}
				if tc.hop != "" {
					redirects = append(redirects, output.Redirect{FromURL: server.URL + "/start?[redacted]", ToURL: server.URL + "/reference?[redacted]", StatusCode: 302})
				}
				if report.SchemaVersion != 1 || report.CatalogSize != 39 || !report.QueryRedacted || report.URL != server.URL+path+"?[redacted]" || report.FinalURL != server.URL+"/reference?[redacted]" || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(body) || !reflect.DeepEqual(report.Redirects, redirects) || report.Findings == nil || len(report.Findings) != len(ids) || (report.Assets != nil) != tc.assets {
					t.Fatalf("unexpected metadata: %+v", report)
				}
				for i, id := range ids {
					f, expected := report.Findings[i], want[id]
					if f.ID != id || f.Name != expected.name || f.Category != expected.category || f.State != expected.state || len(f.Evidence) != len(expected.evidence) {
						t.Fatalf("unexpected finding: %+v", f)
					}
					for j, e := range f.Evidence {
						expectedURL := ""
						if id == "react" {
							expectedURL = assetURL
						}
						if e.RuleID != expected.evidence[j].rule || e.Description == "" || e.InferredFrom != "" || e.AssetURL != expectedURL || !reflect.DeepEqual(e.Signals, expected.evidence[j].signals) {
							t.Errorf("unexpected evidence: %+v", e)
						}
					}
				}
				if tc.assets {
					a := report.Assets
					if a.Status != "complete" || a.Attempted != 2 || a.Collected != 2 || len(a.Items) != 2 {
						t.Fatalf("unexpected asset scope: %+v", a)
					}
					for i, path := range []string{"/runtime.js", "/styles.css"} {
						if a.Items[i].URL != server.URL+path+"?[redacted]" || a.Items[i].HTTPStatus != 200 || a.Items[i].Status != "collected" {
							t.Errorf("unexpected asset metadata: %+v", a.Items[i])
						}
					}
				}
			})
		}
	}
}
