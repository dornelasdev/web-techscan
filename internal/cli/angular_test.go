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

func TestAngularThroughCLI(t *testing.T) {
	fixture, err := os.ReadFile("../detect/testdata/coverage/angular-server.html")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	const versionOnly = `<app-shell ng-version="20.3.0"><script src="/fixture.js"></script>`
	const contextOnly = `<app-shell ng-server-context="private-context">`
	for _, tc := range []struct {
		name, mime, body, hop           string
		status                          int
		want, assets, failScript, mixed bool
	}{
		{"paired", "text/html", string(fixture), "", 200, true, false, false, false},
		{"reversed-custom-host", "text/html", `<section ng-server-context='private-context' ng-version='20.3.0'>`, "", 200, true, false, false, false},
		{"xhtml", "application/xhtml+xml", string(fixture), "", 200, true, false, false, false},
		{"duplicate-pairs", "text/html", string(fixture) + string(fixture), "", 200, true, false, false, false},
		{"version-only", "text/html", versionOnly, "", 200, false, false, false, false},
		{"context-only", "text/html", contextOnly, "", 200, false, false, false, false},
		{"split-tags", "text/html", versionOnly + contextOnly, "", 200, false, false, false, false},
		{"client-shell", "text/html", `<app-root></app-root><script src="/fixture.js"></script>`, "", 200, false, false, false, false},
		{"angularjs-decoy", "text/html", `<body ng-app='app' ng-controller='Main'>`, "", 200, false, false, false, false},
		{"non-html", "text/plain", string(fixture), "", 200, false, false, false, false},
		{"error-page", "text/html", string(fixture), "", 403, true, false, false, false},
		{"generic-error", "text/html", "Forbidden", "", 403, false, false, false, false},
		{"redirect-to-paired", "text/html", string(fixture), "<html></html>", 200, true, false, false, false},
		{"redirect-only", "text/html", "<html></html>", string(fixture), 200, false, false, false, false},
		{"version-on-redirect", "text/html", contextOnly, versionOnly, 200, false, false, false, false},
		{"context-on-redirect", "text/html", versionOnly, contextOnly, 200, false, false, false, false},
		{"independent-stack", "text/html", string(fixture), "", 200, true, false, false, true},
		{"asset-body-not-html", "text/html", versionOnly, "", 200, false, true, false, false},
		{"paired-with-assets", "text/html", string(fixture), "", 200, true, true, false, false},
		{"paired-survives-asset-failure", "text/html", string(fixture), "", 200, true, true, true, false},
	} {
		for _, format := range []string{"json", "plain", "color"} {
			for _, redact := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/redact=%t", tc.name, format, redact), func(t *testing.T) {
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
							t.Errorf("unexpected request policy: %s %s", r.Method, r.RequestURI)
						}
						switch r.URL.Path {
						case "/start", "/page":
							// Header/cookie values must never supply the HTML pair.
							w.Header().Set("Ng-Version", "20.3.0")
							w.Header().Set("Ng-Server-Context", "private-context")
							w.Header().Set("X-Powered-By", "Angular")
							w.Header().Set("Set-Cookie", "ng-version=private-cookie-value; Path=/")
							if r.URL.Path == "/start" {
								w.Header().Set("Content-Type", "text/html")
								w.Header().Set("X-Powered-By", "Express")
								w.Header().Set("Location", "/page?private-page=1")
								w.WriteHeader(http.StatusFound)
								fmt.Fprint(w, tc.hop)
								return
							}
							if tc.mixed {
								w.Header().Set("Server", "nginx/1.26.2")
								w.Header().Set("X-Powered-By", "Next.js")
							}
							w.Header().Set("Content-Type", tc.mime)
							w.WriteHeader(tc.status)
							fmt.Fprint(w, tc.body)
						case "/fixture.js", "/fixture.css":
							if !tc.assets {
								t.Error("asset fetched without opt-in")
							}
							if r.Header.Get("Referer") != "" {
								t.Error("asset referrer forwarded")
							}
							w.Header().Set("X-Powered-By", "Express")
							if r.URL.Path == "/fixture.js" {
								w.Header().Set("Content-Type", "application/javascript")
								if tc.failScript {
									w.WriteHeader(http.StatusForbidden)
								}
								fmt.Fprint(w, `const example = '<app-shell ng-version="20.3.0" ng-server-context="private-context">';`)
							} else {
								w.Header().Set("Content-Type", "text/css")
								fmt.Fprint(w, `/* <app-shell ng-version="20.3.0" ng-server-context="private-context"> */`)
							}
						default:
							t.Errorf("unexpected request: %s", r.RequestURI)
							http.NotFound(w, r)
						}
					}))
					defer server.Close()
					start := "/page?private-page=1"
					wantRequests := []string{start}
					if tc.hop != "" {
						start = "/start?private-start=1"
						wantRequests = []string{start, "/page?private-page=1"}
					}
					if tc.assets {
						if strings.Contains(tc.body, "/fixture.css") {
							wantRequests = append(wantRequests, "/fixture.css")
						}
						wantRequests = append(wantRequests, "/fixture.js")
					}
					args := []string{}
					if tc.assets {
						args = append(args, "--assets")
					}
					if redact {
						args = append(args, "--redact-query")
					}
					switch format {
					case "json":
						args = append(args, "--json")
					case "color":
						args = append(args, "--color=always")
					default:
						args = append(args, "--no-color")
					}
					var stdout, stderr bytes.Buffer
					if code := cli.Run(append(args, server.URL+start), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
						t.Fatalf("code=%d stderr=%s", code, &stderr)
					}
					mu.Lock()
					visited := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(visited, wantRequests) {
						t.Errorf("requests=%v want=%v", visited, wantRequests)
					}
					for _, raw := range []string{"20.3.0", "private-context", "private-cookie-value", "private-page-content", "Express", "AngularJS", "TypeScript"} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("unexpected raw/unsupported output: %s", raw)
						}
					}
					if redact && (strings.Contains(stdout.String(), "private-page") || strings.Contains(stdout.String(), "private-start")) {
						t.Error("query leaked")
					}
					if format != "json" {
						marker := "?"
						if format == "color" {
							marker = "\x1b[33m?\x1b[0m"
						}
						count := 0
						if tc.want {
							count = 1
						}
						if strings.Count(stdout.String(), marker+" Angular [framework]") != count {
							t.Errorf("terminal=%s", &stdout)
						}
						if strings.Contains(stdout.String(), "Paired ng-version and ng-server-context attributes on one tag") != tc.want {
							t.Error("incorrect evidence")
						}
						return
					}
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					url := func(path string) string {
						if redact && strings.Contains(path, "?") {
							path = strings.SplitN(path, "?", 2)[0] + "?[redacted]"
						}
						return server.URL + path
					}
					scope := "final_response"
					if tc.status >= 400 {
						scope = "http_error_response"
					}
					if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.URL != url(start) || report.FinalURL != url("/page?private-page=1") || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.QueryRedacted != redact || report.BodyBytes != len(tc.body) {
						t.Fatalf("metadata=%+v", report)
					}
					wantRedirects := []output.Redirect{}
					if tc.hop != "" {
						wantRedirects = append(wantRedirects, output.Redirect{FromURL: url(start), ToURL: url("/page?private-page=1"), StatusCode: 302})
					}
					if !reflect.DeepEqual(report.Redirects, wantRedirects) {
						t.Errorf("redirects=%+v", report.Redirects)
					}
					wantIDs := []string{}
					if tc.want {
						wantIDs = append(wantIDs, "angular")
					}
					if tc.mixed {
						wantIDs = append(wantIDs, "nextjs", "nginx")
					}
					gotIDs := []string{}
					for _, finding := range report.Findings {
						gotIDs = append(gotIDs, finding.ID)
					}
					if !reflect.DeepEqual(gotIDs, wantIDs) {
						t.Fatalf("findings=%+v", report.Findings)
					}
					if tc.want {
						f := report.Findings[0]
						if f.Name != "Angular" || f.Category != "framework" || f.State != "inferred" || len(f.Evidence) != 1 {
							t.Fatalf("finding=%+v", f)
						}
						e := f.Evidence[0]
						if e.RuleID != "server-host-attributes" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []output.Signal{{Source: "html"}}) {
							t.Fatalf("evidence=%+v", e)
						}
					}
					if tc.mixed && (report.Findings[1].State != "detected" || report.Findings[2].State != "detected") {
						t.Error("independent direct states changed")
					}
					if !tc.assets {
						if report.Assets != nil {
							t.Error("asset metadata without opt-in")
						}
						return
					}
					status, collected := "complete", len(wantRequests)-1
					if tc.failScript {
						status, collected = "incomplete", collected-1
					}
					if report.Assets == nil || report.Assets.Status != status || report.Assets.Attempted != len(wantRequests)-1 || report.Assets.Collected != collected {
						t.Fatalf("assets=%+v", report.Assets)
					}
				})
			}
		}
	}
}
