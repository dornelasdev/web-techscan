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

func TestCaddyThroughCLI(t *testing.T) {
	js, err := os.ReadFile("../detect/testdata/coverage/react-19-client.min.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, contentType              string
		servers, vias                  []string
		status                         int
		redirect, assets, prefer       bool
		wantServer, wantVia, wantNginx bool
	}{
		{name: "server", servers: []string{"cAdDy"}, status: 200, wantServer: true},
		{name: "via", vias: []string{"1.1 cAdDy"}, status: 200, wantVia: true},
		{name: "both-and-duplicates", servers: []string{"cAdDy", "cAdDy"}, vias: []string{"1.1 cAdDy", "2.0 cAdDy", "1.1 cAdDy"}, status: 200, wantServer: true, wantVia: true},
		{name: "non-html-error", contentType: "text/plain", vias: []string{"2.0 cAdDy"}, status: 403, wantVia: true},
		{name: "malformed", servers: []string{"Caddy/2.11.7"}, vias: []string{"1.1 Caddy-compatible"}, status: 200},
		{name: "combined-via", vias: []string{"1.1 other, 1.1 Caddy"}, status: 200},
		{name: "comment-only", vias: []string{"1.1 other (Caddy)"}, status: 200},
		{name: "independent-server", servers: []string{"nginx"}, vias: []string{"1.1 cAdDy"}, status: 200, wantVia: true, wantNginx: true},
		{name: "redirect-only", status: 200, redirect: true},
		{name: "redirect-to-server", servers: []string{"cAdDy"}, status: 200, redirect: true, wantServer: true},
		{name: "redirect-server-cannot-upgrade-final-via", vias: []string{"1.1 cAdDy"}, status: 200, redirect: true, wantVia: true},
		{name: "asset-headers-only", status: 200, assets: true},
		{name: "asset-server-cannot-upgrade-page-via", vias: []string{"3.0 cAdDy"}, status: 403, assets: true, prefer: true, wantVia: true},
		{name: "asset-via-cannot-add-page-evidence", servers: []string{"cAdDy"}, status: 200, assets: true, wantServer: true},
		{name: "both-with-assets-and-html-preference", servers: []string{"cAdDy"}, vias: []string{"1.0 cAdDy"}, status: 200, assets: true, prefer: true, wantServer: true, wantVia: true},
	} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				body := `<p>Caddy Go Golang</p>`
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
						w.Header().Set("Server", "Caddy")
						w.Header().Set("Via", "1.1 Caddy")
						w.Header().Set("Location", "/page?token=private-query")
						w.WriteHeader(302)
					case "/page":
						contentType := tc.contentType
						if contentType == "" {
							contentType = "text/html"
						}
						w.Header().Set("Content-Type", contentType)
						w.Header().Set("X-Server", "Caddy")
						w.Header().Set("X-Via", "1.1 Caddy")
						http.SetCookie(w, &http.Cookie{Name: "Caddy", Value: "private-cookie"})
						for _, v := range tc.servers {
							w.Header().Add("Server", v)
						}
						for _, v := range tc.vias {
							w.Header().Add("Via", v)
						}
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/runtime.js":
						w.Header().Set("Content-Type", "text/javascript")
						w.Header().Set("Server", "Caddy")
						w.Header().Set("Via", "1.1 Caddy")
						fmt.Fprint(w, string(js)+"\n/* Caddy 1.1 Caddy Go Golang */")
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
				for _, raw := range []string{"private-", "cAdDy", "1.1 Caddy", "2.0 cAdDy", "3.0 cAdDy", "2.11.7", "Golang"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw response value leaked: %q", raw)
					}
				}
				caddyState := "inferred"
				rules := []mixedEvidence{}
				if tc.wantServer {
					caddyState = "detected"
					rules = append(rules, mixedHeader("server-header", "Server"))
				}
				if tc.wantVia {
					rules = append(rules, mixedHeader("via-header", "Via"))
				}
				ids := []string{}
				if len(rules) != 0 {
					ids = append(ids, "caddy")
				}
				if tc.wantNginx {
					ids = append(ids, "nginx")
				}
				if tc.assets {
					ids = append(ids, "react")
				}
				want := map[string]mixedFinding{
					"caddy": {"caddy", "Caddy", "web_server", "web server", caddyState, rules},
					"nginx": {"nginx", "nginx", "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
					"react": {"react", "React", "javascript_framework", "JavaScript framework", "inferred", []mixedEvidence{{rule: "asset-client-runtime", signals: []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}}}},
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
					if a.Status != "complete" || a.Attempted != 1 || a.Collected != 1 || len(a.Items) != 1 || a.Items[0].URL != assetURL || a.Items[0].HTTPStatus != 200 || a.Items[0].Status != "collected" {
						t.Errorf("unexpected asset metadata: %+v", a)
					}
				}
			})
		}
	}
}
