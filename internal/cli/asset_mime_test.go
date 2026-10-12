package cli_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"webscan/internal/assets"
	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestCLILegacyJavaScriptResponseMIME(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	const markers = `self.__BUILD_MANIFEST={};self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();/* private-bundle-content */`
	for _, tc := range []struct {
		name                                             string
		types                                            []string
		enabled, css, compressed, oversized, wantFinding bool
		status                                           int
		reason                                           string
	}{
		{"default-off", []string{"application/x-javascript"}, false, false, false, false, false, 200, ""},
		{"accepted", []string{"application/x-javascript"}, true, false, false, false, true, 200, ""},
		{"case-and-parameters", []string{"APPLICATION/X-JAVASCRIPT; charset=UTF-8"}, true, false, false, false, true, 200, ""},
		{"gzip", []string{"application/x-javascript"}, true, false, true, false, true, 200, ""},
		{"wrong-kind", []string{"application/x-javascript"}, true, true, false, false, false, 200, "unsuitable_content_type"},
		{"missing-type", nil, true, false, false, false, false, 200, "unsuitable_content_type"},
		{"plain-not-sniffed", []string{"text/plain"}, true, false, false, false, false, 200, "unsuitable_content_type"},
		{"lookalike", []string{"application/x-javascript-extra"}, true, false, false, false, false, 200, "unsuitable_content_type"},
		{"repeated-type", []string{"application/x-javascript", "application/x-javascript"}, true, false, false, false, false, 200, "unsuitable_content_type"},
		{"status-rejection", []string{"application/x-javascript"}, true, false, false, false, false, 403, "unsuccessful_status"},
		{"redirect-rejection", []string{"application/x-javascript"}, true, false, false, false, false, 302, "redirect_not_allowed"},
		{"gzip-decoded-overflow", []string{"application/x-javascript"}, true, false, true, true, false, 200, "decoded_body_limit"},
	} {
		for _, format := range []string{"json", "plain", "color"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				body := markers
				if tc.oversized {
					body += strings.Repeat(" ", int(assets.MaxAssetDecodedBytes)+1)
				}
				wire := []byte(body)
				if tc.compressed {
					var compressed bytes.Buffer
					writer := gzip.NewWriter(&compressed)
					if _, err := writer.Write(wire); err != nil {
						t.Fatal(err)
					}
					if err := writer.Close(); err != nil {
						t.Fatal(err)
					}
					wire = compressed.Bytes()
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
					switch r.URL.Path {
					case "/":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Server", "nginx")
						w.Header().Set("Set-Cookie", "fixture=private-cookie-value; Path=/")
						if tc.css {
							fmt.Fprint(w, `<link rel="stylesheet" href="/asset?private-token=1">`)
						} else {
							fmt.Fprint(w, `<script type="module" src="/asset?private-token=1"></script>`)
						}
					case "/asset":
						if r.Referer() != "" || r.Header.Get("Accept-Encoding") != "gzip" {
							t.Error("unexpected asset headers")
						}
						// A present nil header prevents net/http from filling a missing
						// Content-Type by sniffing the synthetic response body.
						w.Header()["Content-Type"] = tc.types
						w.Header().Set("X-Powered-By", "Express")
						if tc.compressed {
							w.Header().Set("Content-Encoding", "gzip")
						}
						if tc.status == 302 {
							w.Header().Set("Location", "/never?private-location=1")
						}
						w.WriteHeader(tc.status)
						_, _ = w.Write(wire)
					default:
						t.Errorf("unexpected request: %s", r.RequestURI)
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				args := []string{"--redact-query"}
				if tc.enabled {
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
				if tc.enabled {
					wantRequests = append(wantRequests, "/asset?private-token=1")
				}
				mu.Lock()
				visited := append([]string(nil), requests...)
				mu.Unlock()
				if !reflect.DeepEqual(visited, wantRequests) {
					t.Errorf("requests=%v want=%v", visited, wantRequests)
				}
				for _, raw := range []string{"private-", "__BUILD_MANIFEST", "Express", "application/x-javascript"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw body/header/query leaked: %s", raw)
					}
				}
				assetURL := server.URL + "/asset?[redacted]"
				if format != "json" {
					marker := "?"
					if format == "color" {
						marker = "\x1b[33m?\x1b[0m"
					}
					if strings.Contains(stdout.String(), marker+" Next.js [framework]") != tc.wantFinding || !strings.Contains(stdout.String(), "nginx [web server]") {
						t.Errorf("terminal=%s", &stdout)
					}
					if tc.wantFinding && !strings.Contains(stdout.String(), "Asset: "+assetURL) {
						t.Error("missing asset evidence URL")
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				wantIDs := []string{"nginx"}
				if tc.wantFinding {
					wantIDs = []string{"nextjs", "nginx"}
				}
				gotIDs := []string{}
				for _, f := range report.Findings {
					gotIDs = append(gotIDs, f.ID)
				}
				if !reflect.DeepEqual(gotIDs, wantIDs) || report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || !report.QueryRedacted || report.HTTPStatus != 200 {
					t.Fatalf("report=%+v", report)
				}
				if tc.wantFinding {
					f := report.Findings[0]
					if f.State != "inferred" || len(f.Evidence) != 1 || f.Evidence[0].RuleID != "asset-build-manifest" || f.Evidence[0].AssetURL != assetURL || !reflect.DeepEqual(f.Evidence[0].Signals, []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}) {
						t.Fatalf("finding=%+v", f)
					}
				}
				if report.Findings[len(report.Findings)-1].State != "detected" {
					t.Error("page finding state changed")
				}
				if !tc.enabled {
					if report.Assets != nil {
						t.Error("asset metadata without opt-in")
					}
					return
				}
				status, collected := "incomplete", 0
				if tc.wantFinding {
					status, collected = "complete", 1
				}
				if report.Assets == nil || report.Assets.Status != status || report.Assets.Attempted != 1 || report.Assets.Collected != collected || len(report.Assets.Items) != 1 {
					t.Fatalf("assets=%+v", report.Assets)
				}
				item := report.Assets.Items[0]
				kind := "javascript"
				if tc.css {
					kind = "stylesheet"
				}
				if item.URL != assetURL || item.Kind != kind || item.HTTPStatus != tc.status || item.Reason != tc.reason {
					t.Fatalf("item=%+v", item)
				}
				if tc.wantFinding && item.DecodedBytes != int64(len(body)) {
					t.Errorf("decoded size=%d", item.DecodedBytes)
				}
				if tc.oversized {
					if item.DecodedBytes <= assets.MaxAssetDecodedBytes || item.DecodedBytes > assets.MaxAssetDecodedBytes+1 || report.Assets.DecodedBytes > assets.MaxTotalDecodedBytes || report.Assets.EncodedBytes > assets.MaxTotalEncodedBytes {
						t.Errorf("overflow accounting=%+v", report.Assets)
					}
				} else if !tc.wantFinding && (item.DecodedBytes != 0 || item.EncodedBytes != 0) {
					t.Error("rejected response body was read")
				}
			})
		}
	}
}
