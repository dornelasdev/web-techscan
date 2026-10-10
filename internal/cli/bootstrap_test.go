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

func TestCLIBootstrapCSS(t *testing.T) {
	for _, fixture := range []string{"bootstrap-5.2.css", "bootstrap-5.3.min.css"} {
		body, err := os.ReadFile("../detect/testdata/coverage/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		for _, format := range []string{"json", "plain", "color"} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/assets=%t", fixture, format, enabled), func(t *testing.T) {
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						if r.Method != http.MethodGet {
							t.Errorf("method=%s", r.Method)
						}
						switch r.URL.Path {
						case "/":
							w.Header().Set("Content-Type", "text/html")
							fmt.Fprintf(w, `<style>%s</style><link rel="stylesheet" href="/renamed?asset=1">`, body)
						case "/renamed":
							w.Header().Set("Content-Type", "text/css; charset=utf-8")
							fmt.Fprint(w, string(body))
						default:
							t.Errorf("unexpected request: %s", r.URL.Path)
							w.WriteHeader(http.StatusNotFound)
						}
					}))
					defer server.Close()
					var args []string
					if enabled {
						args = append(args, "--assets")
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
					if enabled {
						wantRequests = append(wantRequests, "/renamed?asset=1")
					}
					mu.Lock()
					gotRequests := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(gotRequests, wantRequests) {
						t.Errorf("requests=%v want=%v", gotRequests, wantRequests)
					}
					assetURL := server.URL + "/renamed?asset=1"
					if format == "json" {
						var report output.Report
						if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
							t.Fatal(err)
						}
						if report.CatalogSize != 19 {
							t.Errorf("catalog size=%d", report.CatalogSize)
						}
						if !enabled {
							if len(report.Findings) != 0 || report.Assets != nil {
								t.Fatalf("default scan=%+v", report)
							}
							return
						}
						if len(report.Findings) != 1 || report.Assets == nil || report.Assets.Status != "complete" || report.Assets.Collected != 1 || report.Assets.Mode != "fingerprint_inspection" {
							t.Fatalf("report=%+v assets=%+v", report, report.Assets)
						}
						f := report.Findings[0]
						if f.ID != "bootstrap" || f.Category != "ui_framework" || f.State != "inferred" || len(f.Evidence) != 1 {
							t.Fatalf("finding=%+v", f)
						}
						e := f.Evidence[0]
						if e.RuleID != "asset-css-banner-and-buttons" || e.AssetURL != assetURL || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []output.Signal{{Source: "asset_css"}, {Source: "asset_css"}}) {
							t.Errorf("evidence=%+v", e)
						}
					} else if enabled {
						marker := "?"
						if format == "color" {
							marker = "\x1b[33m?\x1b[0m"
						}
						if !strings.Contains(stdout.String(), marker+" Bootstrap [UI framework]") || !strings.Contains(stdout.String(), "Asset: "+assetURL) {
							t.Errorf("terminal=%s", &stdout)
						}
					} else if strings.Contains(stdout.String(), "Bootstrap") {
						t.Errorf("inline CSS produced finding: %s", &stdout)
					}
					if strings.Contains(stdout.String(), "--bs-btn-") || strings.Contains(stdout.String(), "getbootstrap.com") {
						t.Error("raw CSS leaked into output")
					}
				})
			}
		}
	}
}
