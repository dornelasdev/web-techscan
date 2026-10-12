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

	"webscan/internal/assets"
	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestCLIAngularComponentAssets(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"angular-component.js", "angular-component.min.js"} {
		body, err := os.ReadFile("../detect/testdata/coverage/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name, mime, reason                                                     string
			enabled, redact, wantRuntime, html, split, css, lateFailure, oversized bool
			status                                                                 int
		}{
			{name: "default-off"},
			{name: "accepted", enabled: true, wantRuntime: true},
			{name: "legacy-mime-redacted", enabled: true, redact: true, wantRuntime: true, mime: "application/x-javascript"},
			{name: "failed-status", enabled: true, status: 403, reason: "unsuccessful_status"},
			{name: "wrong-mime", enabled: true, mime: "text/plain", reason: "unsuitable_content_type"},
			{name: "split-indicators", enabled: true, split: true},
			{name: "stylesheet-decoy", enabled: true, css: true, mime: "text/css"},
			{name: "combined-html-js", enabled: true, redact: true, wantRuntime: true, html: true},
			{name: "html-survives-failed-js", enabled: true, html: true, status: 403, reason: "unsuccessful_status"},
			{name: "later-failure", enabled: true, wantRuntime: true, lateFailure: true},
			{name: "oversized-prefix-excluded", enabled: true, oversized: true, reason: "decoded_body_limit"},
		} {
			for _, format := range []string{"json", "plain", "color"} {
				t.Run(fixture+"/"+tc.name+"/"+format, func(t *testing.T) {
					if tc.mime == "" {
						tc.mime = "text/javascript"
					}
					if tc.status == 0 {
						tc.status = http.StatusOK
					}
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						if r.Method != http.MethodGet || r.UserAgent() != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
							t.Errorf("unexpected request policy: %s %s", r.Method, r.RequestURI)
						}
						if r.URL.Path != "/" && (r.Referer() != "" || r.Header.Get("Accept-Encoding") != "gzip") {
							t.Error("unexpected asset headers")
						}
						switch r.URL.Path {
						case "/":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("Server", "nginx")
							w.Header().Set("Set-Cookie", "fixture=private-cookie-value; Path=/")
							// Inline JS must not supply asset evidence, even with all indicators.
							fmt.Fprintf(w, "<script>%s</script>", body)
							if tc.html {
								fmt.Fprint(w, `<app-shell ng-version="20.3.0" ng-server-context="ssg"></app-shell>`)
							}
							if tc.css {
								fmt.Fprint(w, `<link rel="stylesheet" href="/renamed?private-token=1">`)
							} else {
								fmt.Fprint(w, `<script type="module" src="/renamed?private-token=1"></script><script src="/renamed?private-token=1#duplicate"></script>`)
							}
							if tc.split {
								fmt.Fprint(w, `<script src="/part"></script>`)
							}
							if tc.lateFailure {
								fmt.Fprint(w, `<script src="/fail"></script>`)
							}
						case "/renamed":
							w.Header().Set("Content-Type", tc.mime)
							w.Header().Set("X-Powered-By", "Express") // Not a page header.
							w.WriteHeader(tc.status)
							content := string(body)
							if tc.split {
								content = strings.ReplaceAll(content, "ng-version", "fixture-version")
							}
							if tc.oversized {
								content += strings.Repeat(" ", int(assets.MaxAssetDecodedBytes)+1)
							}
							fmt.Fprint(w, content)
						case "/part":
							w.Header().Set("Content-Type", "application/javascript")
							fmt.Fprint(w, `const attrs=["ng-version","20.3.0"];`)
						case "/fail":
							w.Header().Set("Content-Type", "text/javascript")
							w.WriteHeader(http.StatusForbidden)
							fmt.Fprint(w, "private-failed-body")
						default:
							t.Errorf("unexpected request: %s", r.RequestURI)
							http.NotFound(w, r)
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
					if code := cli.Run(append(args, server.URL+"/?private-page=1"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
						t.Fatalf("code=%d stderr=%s", code, &stderr)
					}
					wantRequests := []string{"/?private-page=1"}
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
					visited := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(visited, wantRequests) {
						t.Errorf("requests=%v want=%v", visited, wantRequests)
					}
					for _, raw := range []string{"private-angular-body", "private-failed-body", "private-cookie-value", "__ngContext__", "20.3.0", "Express", "TypeScript"} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("raw/unsupported output: %s", raw)
						}
					}
					assetURL := server.URL + "/renamed?private-token=1"
					if tc.redact {
						assetURL = server.URL + "/renamed?[redacted]"
						if strings.Contains(stdout.String(), "private-token") || strings.Contains(stdout.String(), "private-page") {
							t.Error("query leaked")
						}
					}
					wantAngular := tc.wantRuntime || tc.html
					if format != "json" {
						marker := "?"
						if format == "color" {
							marker = "\x1b[33m?\x1b[0m"
						}
						if strings.Contains(stdout.String(), marker+" Angular [framework]") != wantAngular || !strings.Contains(stdout.String(), "nginx [web server]") {
							t.Errorf("terminal=%s", &stdout)
						}
						if tc.wantRuntime && !strings.Contains(stdout.String(), "Asset: "+assetURL) {
							t.Error("missing asset evidence URL")
						}
						return
					}
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					wantIDs := []string{"nginx"}
					if wantAngular {
						wantIDs = []string{"angular", "nginx"}
					}
					var ids []string
					for _, f := range report.Findings {
						ids = append(ids, f.ID)
						if f.ID == "nginx" {
							if f.State != "detected" {
								t.Errorf("page server state=%s", f.State)
							}
							continue
						}
						var evidence []output.Evidence
						if tc.wantRuntime {
							evidence = append(evidence, output.Evidence{RuleID: "asset-component-runtime", AssetURL: assetURL, Signals: []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}, {Source: "asset_javascript"}}})
						}
						if tc.html {
							evidence = append(evidence, output.Evidence{RuleID: "server-host-attributes", Signals: []output.Signal{{Source: "html"}}})
						}
						if f.ID != "angular" || f.State != "inferred" || f.Category != "framework" || len(f.Evidence) != len(evidence) {
							t.Fatalf("finding=%+v", f)
						}
						for i, e := range f.Evidence {
							if e.Description == "" || e.RuleID != evidence[i].RuleID || e.AssetURL != evidence[i].AssetURL || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, evidence[i].Signals) {
								t.Errorf("evidence=%+v want=%+v", e, evidence[i])
							}
						}
					}
					if !reflect.DeepEqual(ids, wantIDs) || report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.QueryRedacted != tc.redact {
						t.Fatalf("report=%+v want IDs=%v", report, wantIDs)
					}
					if !tc.enabled {
						if report.Assets != nil {
							t.Error("assets metadata without opt-in")
						}
						return
					}
					status, collected := "complete", 1
					if tc.reason != "" {
						status, collected = "incomplete", 0
					} else if tc.split {
						collected = 2
					} else if tc.lateFailure {
						status = "incomplete"
					}
					if report.Assets == nil || report.Assets.Mode != "fingerprint_inspection" || report.Assets.Status != status || report.Assets.Collected != collected || report.Assets.Attempted != len(wantRequests)-1 || len(report.Assets.Items) != len(wantRequests)-1 {
						t.Fatalf("assets=%+v", report.Assets)
					}
					item := report.Assets.Items[0]
					kind, itemStatus := "javascript", "collected"
					if tc.css {
						kind = "stylesheet"
					}
					if tc.reason != "" {
						itemStatus = "failed"
					}
					if item.URL != assetURL || item.Kind != kind || item.Status != itemStatus || item.Reason != tc.reason || item.HTTPStatus != tc.status {
						t.Errorf("asset item=%+v", item)
					}
					if tc.oversized && (item.DecodedBytes <= assets.MaxAssetDecodedBytes || item.DecodedBytes > assets.MaxAssetDecodedBytes+1) {
						t.Errorf("overflow accounting=%+v", item)
					}
					if tc.lateFailure {
						failed := report.Assets.Items[1]
						if failed.Status != "failed" || failed.Reason != "unsuccessful_status" || failed.HTTPStatus != http.StatusForbidden {
							t.Errorf("later failure=%+v", failed)
						}
					}
				})
			}
		}
	}
}
