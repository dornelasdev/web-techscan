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

func TestCLIVueRendererAssets(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"vue-3-renderer.js", "vue-3-renderer.min.js"} {
		body, err := os.ReadFile("../detect/testdata/coverage/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		for _, format := range []string{"json", "plain", "color"} {
			for _, tc := range []struct {
				name                                             string
				enabled, redact, wantFinding, split, lateFailure bool
				status                                           int
				mime                                             string
			}{
				{name: "default-off"},
				{name: "accepted", enabled: true, wantFinding: true},
				{name: "redacted", enabled: true, redact: true, wantFinding: true, mime: "application/javascript"},
				{name: "failed-status", enabled: true, status: 403},
				{name: "wrong-mime", enabled: true, mime: "text/css"},
				{name: "split-markers", enabled: true, split: true},
				{name: "later-failure", enabled: true, wantFinding: true, lateFailure: true},
			} {
				t.Run(fixture+"/"+format+"/"+tc.name, func(t *testing.T) {
					if tc.status == 0 {
						tc.status = http.StatusOK
					}
					if tc.mime == "" {
						tc.mime = "text/javascript"
					}
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "webscan" {
							t.Errorf("request method=%s UA=%q", r.Method, r.Header.Get("User-Agent"))
						}
						if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Referer") != "" {
							t.Errorf("unexpected request credentials/referrer: %+v", r.Header)
						}
						switch r.URL.Path {
						case "/":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Add("Set-Cookie", "fixture=private-cookie-value; Path=/")
							scriptType := ""
							if fixture == "vue-3-renderer.js" {
								scriptType = ` type="module"`
							}
							fmt.Fprintf(w, `<script%s>%s</script><script%s src="/renamed?private-token=1"></script><script%s src="/renamed?private-token=1#duplicate"></script>`, scriptType, body, scriptType, scriptType)
							if tc.split {
								fmt.Fprint(w, `<script src="/part"></script>`)
							}
							if tc.lateFailure {
								fmt.Fprint(w, `<script src="/fail"></script>`)
							}
						case "/renamed":
							w.Header().Set("Content-Type", tc.mime)
							w.Header().Set("X-Powered-By", "Nuxt") // Not a page signal.
							w.WriteHeader(tc.status)
							content := string(body)
							if tc.split {
								content = strings.ReplaceAll(content, "__vue_app__", "__fixture_app__")
							}
							fmt.Fprint(w, content)
						case "/part":
							w.Header().Set("Content-Type", "text/javascript")
							fmt.Fprint(w, `r.__vue_app__=a;`)
						case "/fail":
							w.WriteHeader(http.StatusForbidden)
							fmt.Fprint(w, "private-failed-body")
						default:
							t.Errorf("unexpected request=%s", r.RequestURI)
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
						t.Fatalf("code=%d stderr=%s", code, &stderr)
					}
					wantRequests := []string{"/"}
					if tc.enabled {
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
					if !reflect.DeepEqual(gotRequests, wantRequests) {
						t.Errorf("requests=%v want=%v", gotRequests, wantRequests)
					}
					assetURL := server.URL + "/renamed?private-token=1"
					if tc.redact {
						assetURL = server.URL + "/renamed?[redacted]"
						if strings.Contains(stdout.String(), "private-token") {
							t.Error("query leaked in output")
						}
					}
					for _, raw := range []string{"private-vue-body", "private-failed-body", "private-cookie-value", "__vue_app__", "__VUE__", "v-fgt", "Nuxt"} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("raw asset/body/header leaked: %s", raw)
						}
					}
					if format == "json" {
						var report output.Report
						if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
							t.Fatal(err)
						}
						if report.CatalogSize != engine.Len() || report.QueryRedacted != tc.redact {
							t.Errorf("report metadata=%+v", report)
						}
						if !tc.enabled {
							if len(report.Findings) != 0 || report.Assets != nil {
								t.Fatalf("default scan=%+v", report)
							}
							return
						}
						status, collected := "complete", 1
						if tc.status != http.StatusOK || tc.mime == "text/css" {
							status, collected = "incomplete", 0
						} else if tc.split {
							collected = 2
						} else if tc.lateFailure {
							status = "incomplete"
						}
						if report.Assets == nil || report.Assets.Status != status || report.Assets.Collected != collected || len(report.Assets.Items) != len(wantRequests)-1 || report.Assets.Items[0].URL != assetURL {
							t.Fatalf("assets=%+v", report.Assets)
						}
						if !tc.wantFinding {
							if len(report.Findings) != 0 {
								t.Fatalf("findings=%+v", report.Findings)
							}
							return
						}
						if len(report.Findings) != 1 {
							t.Fatalf("findings=%+v", report.Findings)
						}
						f := report.Findings[0]
						if f.ID != "vue" || f.Category != "framework" || f.State != "inferred" || len(f.Evidence) != 1 || f.Evidence[0].RuleID != "asset-renderer-runtime" || f.Evidence[0].AssetURL != assetURL || f.Evidence[0].InferredFrom != "" || !reflect.DeepEqual(f.Evidence[0].Signals, []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}, {Source: "asset_javascript"}}) {
							t.Fatalf("finding=%+v", f)
						}
					} else if tc.wantFinding {
						marker := "?"
						if format == "color" {
							marker = "\x1b[33m?\x1b[0m"
						}
						if !strings.Contains(stdout.String(), marker+" Vue [framework]") || !strings.Contains(stdout.String(), "Asset: "+assetURL) {
							t.Errorf("terminal=%s", &stdout)
						}
					} else if strings.Contains(stdout.String(), "Vue [framework]") {
						t.Errorf("unexpected terminal finding: %s", &stdout)
					}
				})
			}
		}
	}
}
