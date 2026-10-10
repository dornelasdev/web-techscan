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

func TestCLIReactClientAssets(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"react-19-client.js", "react-19-client.min.js"} {
		body, err := os.ReadFile("../detect/testdata/coverage/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		for _, format := range []string{"json", "plain", "color"} {
			for _, tc := range []struct {
				name                         string
				enabled, redact, wantFinding bool
				status                       int
				mime                         string
			}{
				{"default-off", false, false, false, 200, "text/javascript"},
				{"accepted", true, false, true, 200, "text/javascript"},
				{"redacted", true, true, true, 200, "application/javascript"},
				{"failed-status", true, false, false, 403, "text/javascript"},
				{"wrong-mime", true, false, false, 200, "text/css"},
			} {
				t.Run(fixture+"/"+format+"/"+tc.name, func(t *testing.T) {
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "webscan" {
							t.Errorf("request method=%s UA=%q", r.Method, r.Header.Get("User-Agent"))
						}
						switch r.URL.Path {
						case "/":
							w.Header().Set("Content-Type", "text/html")
							fmt.Fprintf(w, `<script>%s</script><script src="/renamed?private-token=1"></script><script src="/renamed?private-token=1#duplicate"></script>`, body)
						case "/renamed":
							if r.Header.Get("Referer") != "" {
								t.Errorf("asset referrer=%q", r.Header.Get("Referer"))
							}
							w.Header().Set("Content-Type", tc.mime)
							w.Header().Set("X-Powered-By", "Next.js") // Asset headers are not page signals.
							w.WriteHeader(tc.status)
							fmt.Fprint(w, string(body))
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
					for _, raw := range []string{"private-runtime-body", "__CLIENT_INTERNALS", "react.transitional.element", "Next.js"} {
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
						status, collected := "incomplete", 0
						if tc.wantFinding {
							status, collected = "complete", 1
						}
						if report.Assets == nil || report.Assets.Status != status || report.Assets.Collected != collected || len(report.Assets.Items) != 1 || report.Assets.Items[0].URL != assetURL {
							t.Fatalf("assets=%+v", report.Assets)
						}
						if !tc.wantFinding {
							if len(report.Findings) != 0 {
								t.Fatalf("failed capture findings=%+v", report.Findings)
							}
							return
						}
						if len(report.Findings) != 1 {
							t.Fatalf("findings=%+v", report.Findings)
						}
						f := report.Findings[0]
						if f.ID != "react" || f.Category != "framework" || f.State != "inferred" || len(f.Evidence) != 1 || f.Evidence[0].RuleID != "asset-client-runtime" || f.Evidence[0].AssetURL != assetURL || !reflect.DeepEqual(f.Evidence[0].Signals, []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}) {
							t.Fatalf("finding=%+v", f)
						}
					} else if tc.wantFinding {
						marker := "?"
						if format == "color" {
							marker = "\x1b[33m?\x1b[0m"
						}
						if !strings.Contains(stdout.String(), marker+" React [framework]") || !strings.Contains(stdout.String(), "Asset: "+assetURL) {
							t.Errorf("terminal=%s", &stdout)
						}
					} else if strings.Contains(stdout.String(), "React [framework]") {
						t.Errorf("unexpected terminal finding: %s", &stdout)
					}
				})
			}
		}
	}
}
