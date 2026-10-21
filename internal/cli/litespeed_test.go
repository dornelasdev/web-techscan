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

func TestLiteSpeedThroughCLI(t *testing.T) {
	js, err := os.ReadFile("../detect/testdata/coverage/react-19-client.min.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, contentType, body  string
		servers                  []string
		status                   int
		redirect, assets, prefer bool
		wantLiteSpeed, caddy     bool
	}{
		{name: "header", servers: []string{"lItEsPeEd"}, status: 200, wantLiteSpeed: true},
		{name: "reviewed-open-banner", servers: []string{"lItEsPeEd/1.9.3 oPeN"}, status: 200, wantLiteSpeed: true},
		{name: "both-banner-forms", servers: []string{"lItEsPeEd", "lItEsPeEd/1.8.4 oPeN", "lItEsPeEd/1.9.3 oPeN"}, status: 200, wantLiteSpeed: true},
		{name: "duplicates", servers: []string{"unrelated", "lItEsPeEd", "lItEsPeEd"}, status: 200, wantLiteSpeed: true},
		{name: "plain-error-header", contentType: "text/plain", servers: []string{"lItEsPeEd"}, status: 403, wantLiteSpeed: true},
		{name: "json-header", contentType: "application/json", body: `{"message":"Not Found"}`, servers: []string{"lItEsPeEd"}, status: 404, wantLiteSpeed: true},
		{name: "version-not-supported", servers: []string{"LiteSpeed/1.9.3"}, status: 200},
		{name: "combined-banner", servers: []string{"LiteSpeed, nginx"}, status: 200},
		{name: "branded-error-without-header", contentType: "text/plain", body: "Powered By LiteSpeed", status: 404},
		{name: "generic-error", contentType: "text/plain", body: "404 page not found", status: 404},
		{name: "generic-json-error", contentType: "application/json", body: `{"message":"Not Found"}`, status: 404},
		{name: "redirect-only", status: 200, redirect: true},
		{name: "redirect-to-header", servers: []string{"lItEsPeEd"}, status: 200, redirect: true, wantLiteSpeed: true},
		{name: "redirect-to-malformed", servers: []string{"LiteSpeed-compatible"}, status: 200, redirect: true},
		{name: "asset-header-only", status: 200, assets: true},
		{name: "header-with-react-and-html-preference", servers: []string{"lItEsPeEd"}, status: 403, assets: true, prefer: true, wantLiteSpeed: true},
		{name: "caddy-does-not-imply-litespeed", status: 200, caddy: true},
		{name: "independent-caddy-and-litespeed", servers: []string{"lItEsPeEd"}, status: 200, caddy: true, wantLiteSpeed: true},
	} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				body := tc.body
				if body == "" {
					body = `<p>Powered By LiteSpeed. PHP LSCache OpenLiteSpeed</p>`
				}
				if tc.assets {
					body += `<script src="/runtime.js?token=private-query"></script>`
				}
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
					if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept") != wantAccept || r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.URL.Query().Get("token") != "private-query" || (!page && r.Referer() != "") {
						t.Errorf("unexpected request policy: %s %s %v", r.Method, r.URL, r.Header)
					}
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Server", "LiteSpeed/1.9.3 Open")
						w.Header().Set("Location", "/page?token=private-query")
						w.WriteHeader(302)
					case "/page":
						contentType := tc.contentType
						if contentType == "" {
							contentType = "text/html"
						}
						w.Header().Set("Content-Type", contentType)
						w.Header().Set("X-Server", "LiteSpeed")
						w.Header().Set("X-Powered-By", "LiteSpeed")
						w.Header().Set("X-Turbo-Charged-By", "LiteSpeed/1.9.3 Open")
						w.Header().Set("X-LiteSpeed-Cache", "hit")
						http.SetCookie(w, &http.Cookie{Name: "LiteSpeed", Value: "private-cookie"})
						for _, value := range tc.servers {
							w.Header().Add("Server", value)
						}
						if tc.caddy {
							w.Header().Set("Via", "1.1 Caddy")
						}
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/runtime.js":
						w.Header().Set("Content-Type", "text/javascript")
						w.Header().Set("Server", "LiteSpeed")
						w.Header().Add("Server", "LiteSpeed/1.9.3 Open")
						fmt.Fprint(w, string(js)+"\n/* Powered By LiteSpeed. PHP LSCache */")
					default:
						t.Errorf("unexpected request: %s", r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				path, wantPaths := "/page", []string{"/page"}
				if tc.redirect {
					path, wantPaths = "/start", []string{"/start", "/page"}
				}
				if tc.assets {
					wantPaths = append(wantPaths, "/runtime.js")
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
					t.Errorf("requests=%v want=%v; no probes or extra requests", visited, wantPaths)
				}
				for _, raw := range []string{"private-", "lItEsPeEd", "LiteSpeed/1.9.3", "LiteSpeed-compatible", "1.1 Caddy", "lItEsPeEd/1.9.3 oPeN", "lItEsPeEd/1.8.4 oPeN", "1.9.3", "LSCache", "OpenLiteSpeed"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw response value leaked: %q", raw)
					}
				}
				ids := []string{}
				if tc.caddy {
					ids = append(ids, "caddy")
				}
				if tc.wantLiteSpeed {
					ids = append(ids, "litespeed")
				}
				if tc.assets {
					ids = append(ids, "react")
				}
				want := map[string]mixedFinding{
					"caddy":     {"caddy", "Caddy", "web_server", "web server", "inferred", []mixedEvidence{mixedHeader("via-header", "Via")}},
					"litespeed": {"litespeed", "LiteSpeed", "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
					"react":     {"react", "React", "javascript_framework", "JavaScript framework", "inferred", []mixedEvidence{{rule: "asset-client-runtime", signals: []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}}}},
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
				if tc.redirect {
					redirects = append(redirects, output.Redirect{FromURL: server.URL + "/start?[redacted]", ToURL: server.URL + "/page?[redacted]", StatusCode: 302})
				}
				if report.SchemaVersion != 1 || report.CatalogSize != 36 || !report.QueryRedacted || report.URL != server.URL+path+"?[redacted]" || report.FinalURL != server.URL+"/page?[redacted]" || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(body) || !reflect.DeepEqual(report.Redirects, redirects) || report.Findings == nil || len(report.Findings) != len(ids) || (report.Assets != nil) != tc.assets {
					t.Fatalf("unexpected metadata: %+v", report)
				}
				for i, id := range ids {
					f, expected := report.Findings[i], want[id]
					if f.ID != id || f.Name != expected.name || f.Category != expected.category || f.State != expected.state || len(f.Evidence) != 1 {
						t.Fatalf("unexpected finding: %+v", f)
					}
					e, expectedURL := f.Evidence[0], ""
					if id == "react" {
						expectedURL = assetURL
					}
					if e.RuleID != expected.evidence[0].rule || e.Description == "" || e.InferredFrom != "" || e.AssetURL != expectedURL || !reflect.DeepEqual(e.Signals, expected.evidence[0].signals) {
						t.Errorf("unexpected evidence: %+v", e)
					}
				}
				if tc.assets {
					a := report.Assets
					if a.Status != "complete" || a.Attempted != 1 || a.Collected != 1 || len(a.Items) != 1 || a.Items[0].URL != assetURL || a.Items[0].HTTPStatus != 200 || a.Items[0].Status != "collected" {
						t.Errorf("unexpected asset metadata: %+v", a)
					}
				}
			})
		}
	}
}
