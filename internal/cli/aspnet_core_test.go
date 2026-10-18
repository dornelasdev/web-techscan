package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestASPNetCoreThroughCLI(t *testing.T) {
	fixture, err := os.ReadFile("../detect/testdata/coverage/aspnet-core-antiforgery.html")
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile("../detect/testdata/coverage/react-19-client.min.js")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	const cookie = ".AspNetCore.Antiforgery.AbCdEf012_A"
	const emptyHTML = "<html><body>No identifying input</body></html>"
	for _, tc := range []struct {
		name, body, contentType, server string
		cookies                         []string
		status                          int
		redirect, assets, prefer, want  bool
	}{
		{name: "paired-and-duplicate-cookies", body: string(fixture), cookies: []string{cookie, cookie, "unrelated"}, status: 200, want: true},
		{name: "xhtml", body: string(fixture), contentType: "application/xhtml+xml", cookies: []string{cookie}, status: 200, want: true},
		{name: "html-only", body: string(fixture), status: 200},
		{name: "cookie-only", body: emptyHTML, cookies: []string{cookie}, status: 200},
		{name: "classic-cookie-is-not-core", body: string(fixture), cookies: []string{"__RequestVerificationToken"}, status: 200},
		{name: "non-html", body: string(fixture), contentType: "text/plain", cookies: []string{cookie}, status: 403},
		{name: "error-page-pair", body: string(fixture), cookies: []string{cookie}, status: 403, want: true},
		{name: "redirect-to-pair", body: string(fixture), cookies: []string{cookie}, status: 200, redirect: true, want: true},
		{name: "cookie-only-on-redirect", body: string(fixture), status: 200, redirect: true},
		{name: "html-only-on-redirect", body: emptyHTML, cookies: []string{cookie}, status: 200, redirect: true},
		{name: "redirect-only", body: emptyHTML, status: 200, redirect: true},
		{name: "independent-kestrel-and-core", body: string(fixture), cookies: []string{cookie}, server: "Kestrel", status: 200, want: true},
		{name: "independent-iis-and-core", body: string(fixture), cookies: []string{cookie}, server: "Microsoft-IIS/10.0", status: 200, want: true},
		{name: "kestrel-does-not-complete-pair", body: string(fixture), server: "Kestrel", status: 200},
		{name: "iis-does-not-complete-pair", body: emptyHTML, cookies: []string{cookie}, server: "Microsoft-IIS/10.0", status: 200},
		{name: "asset-input-cannot-complete-page-pair", body: emptyHTML, cookies: []string{cookie}, status: 200, assets: true},
		{name: "asset-cookie-cannot-complete-page-pair", body: string(fixture), status: 200, assets: true},
		{name: "paired-with-react-and-html-preference", body: string(fixture), cookies: []string{cookie}, status: 403, assets: true, prefer: true, want: true},
	} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				body := tc.body
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
					setCookie := func(name string) {
						// The identifying name also appears in values, which must
						// never substitute for a missing identifying cookie name.
						http.SetCookie(w, &http.Cookie{Name: name, Value: cookie + "-private-cookie", Path: "/"})
					}
					switch r.URL.Path {
					case "/start":
						setCookie(cookie)
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Server", "Kestrel")
						w.Header().Set("Location", "/page?token=private-query")
						w.WriteHeader(302)
						fmt.Fprint(w, string(fixture))
					case "/page":
						contentType := tc.contentType
						if contentType == "" {
							contentType = "text/html"
						}
						w.Header().Set("Content-Type", contentType)
						w.Header().Set("X-Powered-By", "ASP.NET")
						if tc.server != "" {
							w.Header().Set("Server", tc.server)
						}
						for _, name := range tc.cookies {
							setCookie(name)
						}
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/runtime.js":
						w.Header().Set("Content-Type", "text/javascript")
						w.Header().Set("Server", "Kestrel")
						setCookie(cookie)
						fmt.Fprint(w, string(js)+"\n/* "+string(fixture)+" */")
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
				if tc.assets {
					wantPaths = append(wantPaths, "/runtime.js")
				}
				args := []string{"--redact-query", "--color=always"}
				if format == "plain" {
					args = append(args, "--no-color")
				} else if format == "json" {
					args = append(args, "--json")
				}
				if tc.assets {
					args = append(args, "--assets")
				}
				if tc.prefer {
					args = append(args, "--prefer-html")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL+path+"?token=private-query"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, &stderr)
				}
				mu.Lock()
				visited := append([]string(nil), paths...)
				mu.Unlock()
				if !reflect.DeepEqual(visited, wantPaths) {
					t.Errorf("requests=%v want=%v; no probes, submits or extra requests", visited, wantPaths)
				}
				for _, raw := range []string{"private-", cookie, "10.0", "C#", "X-AspNet-Version"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw value or unsupported inference leaked: %q", raw)
					}
				}
				ids := []string{}
				if tc.want {
					ids = append(ids, "aspnet-core")
				}
				if tc.server != "" {
					ids = append(ids, map[string]string{"Kestrel": "kestrel", "Microsoft-IIS/10.0": "iis"}[tc.server])
				}
				if tc.assets {
					ids = append(ids, "react")
				}
				sort.Strings(ids)
				if strings.Contains(stdout.String(), "\x1b") != (format == "color" && len(ids) != 0) {
					t.Error("incorrect color handling")
				}
				assetURL := server.URL + "/runtime.js?[redacted]"
				want := map[string]mixedFinding{
					"aspnet-core": {"aspnet-core", "ASP.NET Core", "framework", "framework", "inferred", []mixedEvidence{{rule: "antiforgery-cookie-and-input", signals: []output.Signal{{Source: "cookie"}, {Source: "html"}}}}},
					"iis":         {"iis", "Microsoft IIS", "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
					"kestrel":     {"kestrel", "Kestrel", "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
					"react":       {"react", "React", "javascript_framework", "JavaScript framework", "inferred", []mixedEvidence{{rule: "asset-client-runtime", signals: []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}}}},
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
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || !report.QueryRedacted || report.URL != server.URL+path+"?[redacted]" || report.FinalURL != server.URL+"/page?[redacted]" || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(body) || !reflect.DeepEqual(report.Redirects, redirects) || report.Findings == nil || len(report.Findings) != len(ids) || (report.Assets != nil) != tc.assets {
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
