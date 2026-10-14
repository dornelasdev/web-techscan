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
	"sync/atomic"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestCLIJQueryCoreAssets(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"jquery-core.js", "jquery-core.min.js"} {
		data, err := os.ReadFile("../detect/testdata/coverage/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		body := string(data) + "\n/* private-jquery-body */"
		for _, format := range []string{"json", "plain", "color"} {
			for _, tc := range []struct {
				name                                                                             string
				enabled, redact, compressed, split, lateFailure, offOrigin, oversized, truncated bool
				wantFinding                                                                      bool
				mime, reason                                                                     string
				status                                                                           int
			}{
				{name: "default-off"},
				{name: "accepted", enabled: true, wantFinding: true},
				{name: "redacted", enabled: true, redact: true, wantFinding: true, mime: "application/javascript"},
				{name: "gzip-legacy-mime", enabled: true, compressed: true, wantFinding: true, mime: "application/x-javascript"},
				{name: "failed-status", enabled: true, status: 403, reason: "unsuccessful_status"},
				{name: "wrong-mime", enabled: true, mime: "text/css", reason: "unsuitable_content_type"},
				{name: "split-indicators", enabled: true, split: true},
				{name: "later-failure", enabled: true, wantFinding: true, lateFailure: true},
				{name: "off-origin", enabled: true, offOrigin: true},
				{name: "oversized-valid-prefix", enabled: true, oversized: true, reason: "decoded_body_limit"},
				{name: "incomplete-valid-prefix", enabled: true, truncated: true, reason: "request_or_body_error"},
			} {
				t.Run(fixture+"/"+format+"/"+tc.name, func(t *testing.T) {
					if tc.mime == "" {
						tc.mime = "text/javascript"
					}
					if tc.status == 0 {
						tc.status = http.StatusOK
					}
					var offOriginRequests atomic.Int32
					externalURL := ""
					if tc.offOrigin {
						external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							offOriginRequests.Add(1)
							w.Header().Set("Content-Type", "text/javascript")
							fmt.Fprint(w, body)
						}))
						defer external.Close()
						externalURL = external.URL
					}
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Referer") != "" {
							t.Errorf("unexpected request method/headers: %s %+v", r.Method, r.Header)
						}
						switch r.URL.Path {
						case "/":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("Server", "nginx")
							w.Header().Add("Set-Cookie", "fixture=private-cookie-value; Path=/")
							ref := externalURL + "/renamed?private-token=1"
							fmt.Fprintf(w, `<script>%s</script><script src="%s"></script><script src="%s#duplicate"></script>`, body, ref, ref)
							if tc.split {
								fmt.Fprint(w, `<script src="/part"></script>`)
							}
							if tc.lateFailure {
								fmt.Fprint(w, `<script src="/fail"></script>`)
							}
						case "/renamed":
							w.Header().Set("Content-Type", tc.mime)
							w.Header().Set("X-Powered-By", "Express") // Not a page signal.
							content := body
							if tc.split {
								content = strings.ReplaceAll(content, "expando:", "missingExpando:")
							}
							if tc.oversized {
								content += "/*" + strings.Repeat("0", 512*1024) + "*/"
							}
							if tc.truncated {
								w.Header().Set("Content-Length", fmt.Sprint(len(content)+100))
							}
							if tc.compressed {
								w.Header().Set("Content-Encoding", "gzip")
							}
							w.WriteHeader(tc.status)
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
						case "/part":
							w.Header().Set("Content-Type", "text/javascript")
							fmt.Fprint(w, `q.extend({expando:"jQuery"+(v+Math.random()).replace(/\D/g,"")});`)
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
					switch format {
					case "json":
						args = append(args, "--json")
					case "color":
						args = append(args, "--color=always")
					default:
						args = append(args, "--no-color")
					}
					var stdout, stderr bytes.Buffer
					if code := cli.Run(append(args, server.URL), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
						t.Fatalf("exit=%d stderr=%s", code, &stderr)
					}
					wantRequests := []string{"/"}
					if tc.enabled && !tc.offOrigin {
						wantRequests = append(wantRequests, "/renamed?private-token=1")
						if tc.split {
							wantRequests = append(wantRequests, "/part")
						}
						if tc.lateFailure {
							wantRequests = append(wantRequests, "/fail")
						}
					}
					mu.Lock()
					gotRequests := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(gotRequests, wantRequests) || offOriginRequests.Load() != 0 {
						t.Errorf("requests=%v want=%v off-origin=%d", gotRequests, wantRequests, offOriginRequests.Load())
					}
					assetURL := server.URL + "/renamed?private-token=1"
					if tc.redact {
						assetURL = server.URL + "/renamed?[redacted]"
						if strings.Contains(stdout.String(), "private-token") {
							t.Error("query leaked in redacted output")
						}
					}
					for _, raw := range []string{"private-jquery-body", "private-cookie-value", "private-failed-body", "Math.random", "3.7.1", "4.0.0", "Express"} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("raw response/version data leaked: %s", raw)
						}
					}
					if format != "json" {
						marker := "?"
						wantCount := 0
						if tc.wantFinding {
							wantCount = 1
						}
						if format == "color" {
							marker = "\x1b[33m?\x1b[0m"
						}
						if strings.Contains(stdout.String(), marker+" jQuery [JavaScript library]") != tc.wantFinding || strings.Count(stdout.String(), " jQuery [JavaScript library]") != wantCount || !strings.Contains(stdout.String(), "nginx [web server]") {
							t.Errorf("unexpected findings: %s", &stdout)
						}
						if tc.wantFinding && !strings.Contains(stdout.String(), "Asset: "+assetURL) {
							t.Errorf("missing evidence URL: %s", &stdout)
						}
						return
					}
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.QueryRedacted != tc.redact {
						t.Errorf("report metadata=%+v", report)
					}
					wantCount := 1
					if tc.wantFinding {
						wantCount++
					}
					if len(report.Findings) != wantCount || report.Findings[wantCount-1].ID != "nginx" || report.Findings[wantCount-1].State != "detected" {
						t.Fatalf("page finding was lost or asset headers became findings: %+v", report.Findings)
					}
					if tc.wantFinding {
						f := report.Findings[0]
						if f.ID != "jquery" || f.Category != "javascript_library" || f.State != "inferred" || len(f.Evidence) != 1 || f.Evidence[0].RuleID != "asset-core-runtime" || f.Evidence[0].AssetURL != assetURL || f.Evidence[0].InferredFrom != "" || !reflect.DeepEqual(f.Evidence[0].Signals, []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}) {
							t.Fatalf("finding=%+v", f)
						}
					}
					if !tc.enabled {
						if report.Assets != nil {
							t.Error("default scan must omit asset collection")
						}
						return
					}
					status, collected := "complete", 1
					if tc.reason != "" {
						status, collected = "incomplete", 0
					} else if tc.offOrigin {
						collected = 0
					} else if tc.split {
						collected = 2
					} else if tc.lateFailure {
						status = "incomplete"
					}
					if report.Assets == nil || report.Assets.Status != status || report.Assets.Attempted != len(wantRequests)-1 || report.Assets.Collected != collected || len(report.Assets.Items) != len(wantRequests)-1 || report.Assets.Budget.Profile != "standard" {
						t.Fatalf("collection=%+v", report.Assets)
					}
					if !tc.offOrigin && (report.Assets.Items[0].URL != assetURL || report.Assets.Items[0].Reason != tc.reason || report.Assets.Duplicates != 1) {
						t.Errorf("collection item/provenance=%+v", report.Assets)
					}
					if tc.offOrigin && report.Assets.SkippedDeclarations != 2 {
						t.Errorf("off-origin references were not excluded: %+v", report.Assets)
					}
				})
			}
		}
	}
}
