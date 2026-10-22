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

func TestCLITailwindCSS(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		file, rule, splitMarker string
		signals                 int
	}{
		{"tailwind-3.4.css", "asset-css-v3-banner-and-preflight", "::before", 2},
		{"tailwind-4.1.min.css", "asset-css-v4-banner-and-translate", ".sample", 3},
	} {
		data, err := os.ReadFile("../detect/testdata/coverage/" + fixture.file)
		if err != nil {
			t.Fatal(err)
		}
		body := string(data) + "\n/* private-css-body */"
		cut := strings.Index(body, fixture.splitMarker)
		if cut < 0 {
			t.Fatal("missing fixture split marker")
		}
		for _, format := range []string{"json", "plain", "color"} {
			for _, tc := range []struct {
				name, reason                                 string
				enabled, finding, redact, compressed, prefer bool
			}{
				{name: "default-off"},
				{name: "accepted", enabled: true, finding: true},
				{name: "redacted-gzip", enabled: true, finding: true, redact: true, compressed: true, prefer: true},
				{name: "failed-status", enabled: true, reason: "unsuccessful_status"},
				{name: "wrong-mime", enabled: true, reason: "unsuitable_content_type"},
				{name: "split-files", enabled: true},
				{name: "later-failure", enabled: true, finding: true},
				{name: "oversized-prefix", enabled: true, reason: "decoded_body_limit"},
				{name: "incomplete-prefix", enabled: true, reason: "request_or_body_error"},
				{name: "javascript-kind", enabled: true},
				{name: "redirect-only", enabled: true},
				{name: "inline-only", enabled: true},
			} {
				t.Run(fixture.file+"/"+format+"/"+tc.name, func(t *testing.T) {
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
							t.Errorf("unexpected request: %s %+v", r.Method, r.Header)
						}
						switch r.URL.Path {
						case "/start":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("X-Powered-By", "Express")
							w.Header().Set("Set-Cookie", "hop=private-hop-cookie; Path=/")
							w.Header().Set("Location", "/page?private-page=1")
							w.WriteHeader(http.StatusFound)
							fmt.Fprintf(w, `<style>%s</style><link rel="stylesheet" href="/hop-only.css">`, body)
						case "/page":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("Server", "nginx")
							w.Header().Set("Set-Cookie", "page=private-page-cookie; Path=/")
							// Asset inference is not gated by the final page's error status.
							w.WriteHeader(http.StatusForbidden)
							if tc.name == "redirect-only" {
								fmt.Fprint(w, "<p>empty</p>")
								return
							}
							fmt.Fprintf(w, `<style>%s</style>`, body)
							if tc.name == "inline-only" {
								return
							}
							if tc.name == "javascript-kind" {
								fmt.Fprint(w, `<script src="/renamed?private-asset=1"></script>`)
							} else {
								fmt.Fprint(w, `<link rel="stylesheet" href="/renamed?private-asset=1"><link rel="stylesheet" href="/renamed?private-asset=1#duplicate">`)
							}
							if tc.name == "split-files" {
								fmt.Fprint(w, `<link rel="stylesheet" href="/part">`)
							}
							if tc.name == "later-failure" {
								fmt.Fprint(w, `<link rel="stylesheet" href="/fail">`)
							}
						case "/renamed", "/part":
							w.Header().Set("Content-Type", "text/css; charset=utf-8")
							w.Header().Set("X-Powered-By", "Express")
							w.Header().Set("Set-Cookie", "asset=private-asset-cookie; Path=/")
							if tc.name == "wrong-mime" {
								w.Header().Set("Content-Type", "text/plain")
							}
							if tc.name == "javascript-kind" {
								w.Header().Set("Content-Type", "text/javascript")
							}
							content := body
							if tc.name == "split-files" {
								if r.URL.Path == "/part" {
									content = body[cut:]
								} else {
									content = body[:cut]
								}
							}
							if tc.name == "oversized-prefix" {
								content += "/*" + strings.Repeat("0", 512*1024) + "*/"
							}
							if tc.name == "incomplete-prefix" {
								w.Header().Set("Content-Length", fmt.Sprint(len(content)+100))
							}
							if tc.compressed {
								w.Header().Set("Content-Encoding", "gzip")
							}
							if tc.name == "failed-status" {
								w.WriteHeader(http.StatusForbidden)
							}
							if tc.compressed {
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
					if tc.enabled && tc.name != "inline-only" && tc.name != "redirect-only" {
						wantRequests = append(wantRequests, "/renamed?private-asset=1")
						if tc.name == "split-files" {
							wantRequests = append(wantRequests, "/part")
						}
						if tc.name == "later-failure" {
							wantRequests = append(wantRequests, "/fail")
						}
					}
					mu.Lock()
					gotRequests := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(gotRequests, wantRequests) {
						t.Errorf("requests=%v want=%v", gotRequests, wantRequests)
					}
					assetURL := server.URL + "/renamed?private-asset=1"
					if tc.redact {
						assetURL = server.URL + "/renamed?[redacted]"
						for _, raw := range []string{"private-start", "private-page", "private-asset"} {
							if strings.Contains(stdout.String(), raw) {
								t.Errorf("query leaked: %s", raw)
							}
						}
					}
					for _, raw := range []string{"private-css-body", "private-hop-cookie", "private-page-cookie", "private-asset-cookie", "private-failed-body", "--tw-", "tailwindcss.com", "3.4.17", "4.1.0", "Express", "Radix", "shadcn"} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("unexpected response/version/implication data: %s", raw)
						}
					}
					if format != "json" {
						marker := "?"
						if format == "color" {
							marker = "\x1b[33m?\x1b[0m"
						}
						wantCount := 0
						if tc.finding {
							wantCount = 1
						}
						if strings.Contains(stdout.String(), marker+" Tailwind CSS [UI framework]") != tc.finding || strings.Count(stdout.String(), " Tailwind CSS [UI framework]") != wantCount || !strings.Contains(stdout.String(), "nginx [web server]") {
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
					wantCount := 1
					if tc.finding {
						wantCount++
					}
					if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.QueryRedacted != tc.redact || report.HTTPStatus != 403 || report.ResponseScope != "http_error_response" || report.Findings == nil || len(report.Findings) != wantCount || report.Findings[0].ID != "nginx" || report.Findings[0].State != "detected" || len(report.Redirects) != 1 {
						t.Fatalf("report=%+v", report)
					}
					if tc.finding {
						f := report.Findings[1]
						if f.ID != "tailwindcss" || f.Name != "Tailwind CSS" || f.Category != "ui_framework" || f.State != "inferred" || len(f.Evidence) != 1 {
							t.Fatalf("finding=%+v", f)
						}
						e := f.Evidence[0]
						signals := make([]output.Signal, fixture.signals)
						for i := range signals {
							signals[i].Source = "asset_css"
						}
						if e.RuleID != fixture.rule || e.AssetURL != assetURL || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, signals) {
							t.Fatalf("evidence=%+v", e)
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
