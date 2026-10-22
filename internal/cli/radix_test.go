package cli_test

import (
	"bytes"
	"compress/gzip"
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

func TestCLIRadixAssets(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	read := func(file string) string {
		t.Helper()
		body, err := os.ReadFile("../detect/testdata/coverage/" + file)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	popover, tooltip, tailwind := read("radix-popover.js"), read("radix-tooltip.min.js"), read("tailwind-3.4.css")
	for _, fixture := range []struct{ family, body string }{{"popover", popover}, {"tooltip", tooltip}} {
		body := fixture.body + "\n/* private-js-body */"
		cut := strings.Index(body, "var(--radix-popper-transform-origin)") + len("var(--radix-popper-transform-origin)") + 1
		if cut < len("var(--radix-popper-transform-origin)")+1 || cut >= len(body) || body[cut] != ',' {
			t.Fatal("invalid fixture split")
		}
		left, right := body[:cut]+"};", "const other={"+body[cut+1:]
		for _, format := range []string{"json", "plain", "color"} {
			for _, tc := range []struct {
				name, reason                                      string
				enabled, finding, redact, gzip, prefer, both, css bool
			}{
				{name: "default-off"},
				{name: "accepted", enabled: true, finding: true},
				{name: "gzip-redacted", enabled: true, finding: true, redact: true, gzip: true, prefer: true},
				{name: "both-rules", enabled: true, finding: true, both: true},
				{name: "independent-tailwind", enabled: true, finding: true, css: true},
				{name: "failed-status", enabled: true, reason: "unsuccessful_status"},
				{name: "wrong-mime", enabled: true, reason: "unsuitable_content_type"},
				{name: "split-files", enabled: true},
				{name: "split-objects", enabled: true},
				{name: "css-kind", enabled: true},
				{name: "later-failure", enabled: true, finding: true},
				{name: "oversized-prefix", enabled: true, reason: "decoded_body_limit"},
				{name: "incomplete-prefix", enabled: true, reason: "request_or_body_error"},
				{name: "redirect-only", enabled: true},
			} {
				t.Run(fixture.family+"/"+format+"/"+tc.name, func(t *testing.T) {
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						wantAccept := ""
						if tc.prefer && (r.URL.Path == "/start" || r.URL.Path == "/page") {
							wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
						}
						if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept") != wantAccept || (r.URL.Path != "/page" && r.Header.Get("Referer") != "") {
							t.Errorf("request=%s %+v", r.Method, r.Header)
						}
						switch r.URL.Path {
						case "/start":
							w.Header().Set("Location", "/page?private-page=1")
							w.Header().Set("X-Powered-By", "Express")
							w.Header().Set("Set-Cookie", "hop=private-hop-cookie; Path=/")
							w.WriteHeader(http.StatusFound)
							fmt.Fprintf(w, `<script>%s</script><script src="/hop-only"></script>`, body)
						case "/page":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("Server", "nginx")
							w.Header().Set("Set-Cookie", "page=private-page-cookie; Path=/")
							w.WriteHeader(http.StatusForbidden)
							if tc.name == "redirect-only" {
								fmt.Fprint(w, "<p>empty</p>")
								return
							}
							fmt.Fprintf(w, `<script>%s</script>`, body)
							if tc.name == "css-kind" {
								fmt.Fprint(w, `<link rel="stylesheet" href="/renamed?private-asset=1">`)
							} else {
								fmt.Fprint(w, `<script src="/renamed?private-asset=1"></script><script src="/renamed?private-asset=1#duplicate"></script>`)
							}
							if tc.name == "split-files" {
								fmt.Fprint(w, `<script src="/part"></script>`)
							}
							if tc.name == "later-failure" {
								fmt.Fprint(w, `<script src="/fail"></script>`)
							}
							if tc.css {
								fmt.Fprint(w, `<link rel="stylesheet" href="/styles?private-css=1">`)
							}
						case "/renamed", "/part":
							w.Header().Set("Content-Type", "text/javascript")
							w.Header().Set("X-Powered-By", "Express")
							w.Header().Set("Set-Cookie", "asset=private-asset-cookie; Path=/")
							if tc.name == "css-kind" {
								w.Header().Set("Content-Type", "text/css")
							}
							if tc.name == "wrong-mime" {
								w.Header().Set("Content-Type", "text/plain")
							}
							content := body
							if tc.both {
								content = tooltip + popover
							}
							if tc.name == "split-files" {
								if r.URL.Path == "/part" {
									content = right
								} else {
									content = left
								}
							}
							if tc.name == "split-objects" {
								content = left + right
							}
							if tc.name == "oversized-prefix" {
								content += "/*" + strings.Repeat("0", 512*1024) + "*/"
							}
							if tc.name == "incomplete-prefix" {
								w.Header().Set("Content-Length", fmt.Sprint(len(content)+100))
							}
							if tc.gzip {
								w.Header().Set("Content-Encoding", "gzip")
							}
							if tc.name == "failed-status" {
								w.WriteHeader(http.StatusForbidden)
							}
							if tc.gzip {
								writer := gzip.NewWriter(w)
								if _, err := writer.Write([]byte(content)); err != nil {
									t.Error(err)
								}
								if err := writer.Close(); err != nil {
									t.Error(err)
								}
							} else {
								fmt.Fprint(w, content)
							}
						case "/styles":
							w.Header().Set("Content-Type", "text/css")
							fmt.Fprint(w, tailwind)
						case "/fail":
							w.WriteHeader(http.StatusForbidden)
							fmt.Fprint(w, "private-failed-body")
						default:
							t.Errorf("unexpected request: %s", r.RequestURI)
							w.WriteHeader(http.StatusNotFound)
						}
					}))
					defer server.Close()
					var args []string
					if tc.enabled {
						args = append(args, "--assets")
					}
					if tc.redact {
						args = append(args, "--redact-query")
					}
					if tc.prefer {
						args = append(args, "--prefer-html")
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
					if code := cli.Run(append(args, server.URL+"/start?private-start=1"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
						t.Fatalf("code=%d stderr=%s", code, &stderr)
					}
					wantRequests := []string{"/start?private-start=1", "/page?private-page=1"}
					if tc.enabled && tc.name != "redirect-only" {
						wantRequests = append(wantRequests, "/renamed?private-asset=1")
						if tc.name == "split-files" {
							wantRequests = append(wantRequests, "/part")
						}
						if tc.name == "later-failure" {
							wantRequests = append(wantRequests, "/fail")
						}
						if tc.css {
							wantRequests = append(wantRequests, "/styles?private-css=1")
						}
					}
					mu.Lock()
					gotRequests := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(gotRequests, wantRequests) {
						t.Errorf("requests=%v want=%v", gotRequests, wantRequests)
					}
					assetURL, cssURL := server.URL+"/renamed?private-asset=1", server.URL+"/styles?private-css=1"
					if tc.redact {
						assetURL, cssURL = server.URL+"/renamed?[redacted]", server.URL+"/styles?[redacted]"
						for _, raw := range []string{"private-start", "private-page", "private-asset", "private-css"} {
							if strings.Contains(stdout.String(), raw) {
								t.Errorf("query leaked: %s", raw)
							}
						}
					}
					for _, raw := range []string{"private-js-body", "private-hop-cookie", "private-page-cookie", "private-asset-cookie", "private-failed-body", "--radix-", "1.1.14", "1.1.15", "1.2.8", "Express", "shadcn", "React ["} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("unexpected raw data/implication: %s", raw)
						}
					}
					if format != "json" {
						marker := "?"
						if format == "color" {
							marker = "\x1b[33m?\x1b[0m"
						}
						count := 0
						if tc.finding {
							count = 1
						}
						if strings.Contains(stdout.String(), marker+" Radix UI [UI framework]") != tc.finding || strings.Count(stdout.String(), " Radix UI [UI framework]") != count || !strings.Contains(stdout.String(), "nginx [web server]") || strings.Contains(stdout.String(), " Tailwind CSS [UI framework]") != tc.css {
							t.Errorf("findings=%s", &stdout)
						}
						if tc.finding && !strings.Contains(stdout.String(), "Asset: "+assetURL) {
							t.Error("missing asset provenance")
						}
						return
					}
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					ids := []string{"nginx"}
					if tc.finding {
						ids = append(ids, "radix-ui")
					}
					if tc.css {
						ids = append(ids, "tailwindcss")
					}
					var gotIDs []string
					for _, f := range report.Findings {
						gotIDs = append(gotIDs, f.ID)
					}
					if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.QueryRedacted != tc.redact || report.HTTPStatus != 403 || report.ResponseScope != "http_error_response" || !reflect.DeepEqual(gotIDs, ids) || report.Findings[0].State != "detected" || len(report.Redirects) != 1 {
						t.Fatalf("report=%+v", report)
					}
					if tc.finding {
						f := report.Findings[1]
						rules := []string{"asset-" + fixture.family + "-style-mappings"}
						if tc.both {
							rules = []string{"asset-popover-style-mappings", "asset-tooltip-style-mappings"}
						}
						if f.Name != "Radix UI" || f.Category != "ui_framework" || f.State != "inferred" || len(f.Evidence) != len(rules) {
							t.Fatalf("finding=%+v", f)
						}
						for i, e := range f.Evidence {
							if e.RuleID != rules[i] || e.AssetURL != assetURL || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []output.Signal{{Source: "asset_javascript"}}) {
								t.Errorf("evidence=%+v", e)
							}
						}
					}
					if tc.css {
						f := report.Findings[2]
						if f.State != "inferred" || len(f.Evidence) != 1 || f.Evidence[0].RuleID != "asset-css-v3-banner-and-preflight" || f.Evidence[0].AssetURL != cssURL {
							t.Errorf("independent CSS=%+v", f)
						}
					}
					if !tc.enabled {
						if report.Assets != nil {
							t.Error("default scan collected assets")
						}
						return
					}
					status, collected := "complete", len(wantRequests)-2
					if tc.reason != "" {
						status, collected = "incomplete", 0
					}
					if tc.name == "later-failure" {
						status, collected = "incomplete", 1
					}
					if report.Assets == nil || report.Assets.Status != status || report.Assets.Mode != "fingerprint_inspection" || report.Assets.Attempted != len(wantRequests)-2 || report.Assets.Collected != collected || len(report.Assets.Items) != len(wantRequests)-2 || report.Assets.Budget.Profile != "standard" {
						t.Fatalf("collection=%+v", report.Assets)
					}
					if len(report.Assets.Items) > 0 && (report.Assets.Items[0].URL != assetURL || report.Assets.Items[0].Reason != tc.reason) {
						t.Errorf("collection item=%+v", report.Assets.Items[0])
					}
				})
			}
		}
	}
}
