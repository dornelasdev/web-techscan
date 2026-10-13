package cli_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"webscan/internal/assets"
	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestCLIAssetBudgetUsageErrorsBeforeNetwork(t *testing.T) {
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	var connections atomic.Int32
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		connections.Add(1)
		return nil, errors.New("network forbidden for invalid asset budgets")
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	for _, args := range [][]string{
		{"--asset-budget=standard", "http://example.test"},
		{"--asset-budget=expanded", "http://example.test"},
		{"--assets=false", "--asset-budget=standard", "http://example.test"},
		{"--assets", "--asset-budget=unknown", "http://example.test"},
		{"--assets", "--asset-budget=Expanded", "http://example.test"},
		{"--assets", "--asset-budget= expanded", "http://example.test"},
		{"--assets", "--asset-budget=", "http://example.test"},
		{"--assets", "--asset-budget=unlimited", "http://example.test"},
		{"--assets", "--asset-budget"},
		{"--techs", "--asset-budget=standard"},
		{"--techs", "--asset-budget=expanded", "--assets"},
		{"--version", "--asset-budget=standard", "--assets"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := cli.Run(args, &stdout, &stderr, "dev"); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Errorf("code=%d stdout=%s stderr=%s", code, &stdout, &stderr)
			}
		})
	}
	if connections.Load() != 0 {
		t.Errorf("invalid budgets attempted %d connections", connections.Load())
	}
}

func TestCLIAssetBudgetCollection(t *testing.T) {
	fixture, err := os.ReadFile("../detect/testdata/coverage/angular-component.min.js")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, profile, reason                                                                         string
		size                                                                                          int
		enabled, compressed, encodedOverflow, wantFinding, unsupportedPage, noReferences, lateFailure bool
		status                                                                                        int
		mime                                                                                          string
	}{
		{name: "page-only"},
		{name: "implicit-standard", enabled: true, wantFinding: true},
		{name: "explicit-standard", enabled: true, profile: "standard", wantFinding: true},
		{name: "expanded-small", enabled: true, profile: "expanded", wantFinding: true},
		{name: "expanded-gzip-small", enabled: true, profile: "expanded", compressed: true, wantFinding: true},
		{name: "standard-large", enabled: true, size: 3 << 20, reason: "decoded_body_limit"},
		{name: "standard-gzip-large", enabled: true, compressed: true, size: 3 << 20, reason: "decoded_body_limit"},
		{name: "expanded-large", enabled: true, profile: "expanded", size: 3 << 20, wantFinding: true},
		{name: "expanded-gzip-large", enabled: true, profile: "expanded", compressed: true, size: 3 << 20, wantFinding: true},
		{name: "expanded-exact-decoded-cap", enabled: true, profile: "expanded", size: 4 << 20, wantFinding: true},
		{name: "expanded-decoded-overflow", enabled: true, profile: "expanded", size: (4 << 20) + 1, reason: "decoded_body_limit"},
		{name: "expanded-gzip-overflow", enabled: true, profile: "expanded", compressed: true, size: (4 << 20) + 1, reason: "decoded_body_limit"},
		{name: "expanded-encoded-overflow", enabled: true, profile: "expanded", compressed: true, encodedOverflow: true, reason: "encoded_body_limit"},
		{name: "expanded-status-failure", enabled: true, profile: "expanded", status: 403, reason: "unsuccessful_status"},
		{name: "expanded-wrong-mime", enabled: true, profile: "expanded", mime: "text/plain", reason: "unsuitable_content_type"},
		{name: "expanded-redirect", enabled: true, profile: "expanded", status: 302, reason: "redirect_not_allowed"},
		{name: "expanded-skipped-page", enabled: true, profile: "expanded", unsupportedPage: true},
		{name: "expanded-empty-scope", enabled: true, profile: "expanded", noReferences: true},
		{name: "expanded-later-failure", enabled: true, profile: "expanded", wantFinding: true, lateFailure: true},
	} {
		profile := tc.profile
		if profile == "" {
			profile = "standard"
		}
		budget, err := assets.BudgetForProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		body := append([]byte(nil), fixture...)
		if tc.size != 0 {
			paddingSize := tc.size - len(fixture)
			if paddingSize < 4 {
				t.Fatal("large fixture needs room for a closed padding comment")
			}
			// Use inert, non-whitespace comment text. Multi-megabyte spaces
			// unnecessarily exercise unrelated whitespace-heavy regex paths
			// under -race; matcher stress is not this collection test's scope.
			padding := bytes.Repeat([]byte("0"), paddingSize)
			copy(padding[:2], "/*")
			copy(padding[len(padding)-2:], "*/")
			if tc.reason == "decoded_body_limit" && profile == "expanded" {
				// Even a valid marker prefix cannot identify a failed capture.
				body = append(body, padding...)
			} else {
				// Successful larger collection must inspect beyond the old cap.
				body = append(padding, body...)
			}
		}
		wire := body
		if tc.compressed {
			var buffer bytes.Buffer
			writer := gzip.NewWriter(&buffer)
			if _, err := writer.Write(body); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if tc.encodedOverflow {
				// Valid empty gzip members with bounded-size extra headers
				// exhaust encoded input without exhausting decoded output.
				extra := make([]byte, 65535)
				for int64(buffer.Len()) <= budget.MaxAssetEncodedBytes {
					writer.Reset(&buffer)
					writer.Header.Extra = extra
					if err := writer.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			wire = buffer.Bytes()
		}
		if tc.status == 0 {
			tc.status = http.StatusOK
		}
		if tc.mime == "" {
			tc.mime = "application/x-javascript"
		}
		formats := []string{"json", "plain", "color"}
		if tc.size != 0 || tc.encodedOverflow {
			// Payload boundaries and full-body detection are independent of
			// presentation. Keep one real large capture per case; the small
			// cases above check JSON/plain/color, including gzip and failures.
			formats = []string{"json"}
		}
		for _, format := range formats {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
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
					case "/page":
						w.Header().Set("Content-Type", "text/html")
						if tc.unsupportedPage {
							w.Header().Set("Content-Type", "text/plain")
						}
						w.Header().Set("Server", "nginx")
						w.Header().Set("Set-Cookie", "fixture=private-cookie-value; Path=/")
						fmt.Fprint(w, `<app-root></app-root>`)
						if !tc.noReferences {
							fmt.Fprint(w, `<script type="module" src="/main?private-token=1"></script>`)
						}
						if tc.lateFailure {
							fmt.Fprint(w, `<script src="/late?private-late=1"></script>`)
						}
					case "/main", "/late":
						if r.Referer() != "" || r.Header.Get("Accept-Encoding") != "gzip" {
							t.Error("unexpected asset headers")
						}
						w.Header().Set("Content-Type", tc.mime)
						w.Header().Set("X-Powered-By", "Express")
						if r.URL.Path == "/late" {
							w.WriteHeader(http.StatusForbidden)
							fmt.Fprint(w, "private-failed-body")
							return
						}
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
				args := []string{"--redact-query", "--max-body=16384", "--max-encoded-body=32768"}
				if tc.enabled {
					args = append(args, "--assets")
				}
				if tc.profile != "" {
					args = append(args, "--asset-budget="+tc.profile)
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
				if code := cli.Run(append(args, server.URL+"/page?private-page=1"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("code=%d stderr=%s", code, &stderr)
				}
				wantRequests := []string{"/page?private-page=1"}
				if tc.enabled && !tc.unsupportedPage && !tc.noReferences {
					wantRequests = append(wantRequests, "/main?private-token=1")
					if tc.lateFailure {
						wantRequests = append(wantRequests, "/late?private-late=1")
					}
				}
				mu.Lock()
				visited := append([]string(nil), requests...)
				mu.Unlock()
				if !reflect.DeepEqual(visited, wantRequests) {
					t.Errorf("requests=%v want=%v", visited, wantRequests)
				}
				for _, raw := range []string{"private-", "20.3.0", "__ngContext__", "Express", "TypeScript"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw/unsupported output: %s", raw)
					}
				}
				assetURL := server.URL + "/main?[redacted]"
				if format != "json" {
					text := strings.NewReplacer("\x1b[33m", "", "\x1b[32m", "", "\x1b[0m", "").Replace(stdout.String())
					if strings.Contains(text, "? Angular [framework]") != tc.wantFinding || !strings.Contains(text, "✓ nginx [web server]") {
						t.Errorf("terminal=%s", text)
					}
					line := fmt.Sprintf("Budget: %s; per asset %d decoded / %d encoded bytes; combined %d decoded / %d encoded bytes", profile, budget.MaxAssetDecodedBytes, budget.MaxAssetEncodedBytes, budget.MaxTotalDecodedBytes, budget.MaxTotalEncodedBytes)
					if strings.Contains(text, line) != tc.enabled || (!tc.enabled && strings.Contains(text, "Assets:")) {
						t.Error("missing/unexpected budget metadata")
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				wantIDs := []string{"nginx"}
				if tc.wantFinding {
					wantIDs = []string{"angular", "nginx"}
				}
				var ids []string
				for _, f := range report.Findings {
					ids = append(ids, f.ID)
					if f.ID == "angular" && (f.State != "inferred" || len(f.Evidence) != 1 || f.Evidence[0].RuleID != "asset-component-runtime" || f.Evidence[0].AssetURL != assetURL || !reflect.DeepEqual(f.Evidence[0].Signals, []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}, {Source: "asset_javascript"}})) {
						t.Errorf("Angular evidence=%+v", f)
					}
				}
				if !reflect.DeepEqual(ids, wantIDs) || report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || !report.QueryRedacted {
					t.Fatalf("report=%+v", report)
				}
				if !tc.enabled {
					if report.Assets != nil || strings.Contains(stdout.String(), `"budget"`) {
						t.Error("page-only report gained asset budget")
					}
					return
				}
				wantBudget := output.AssetBudget{Profile: profile, MaxAssetDecodedBytes: budget.MaxAssetDecodedBytes, MaxAssetEncodedBytes: budget.MaxAssetEncodedBytes, MaxTotalDecodedBytes: budget.MaxTotalDecodedBytes, MaxTotalEncodedBytes: budget.MaxTotalEncodedBytes}
				if report.Assets == nil || report.Assets.Budget != wantBudget || report.Assets.Mode != "fingerprint_inspection" || report.Assets.Attempted != len(wantRequests)-1 || len(report.Assets.Items) != len(wantRequests)-1 {
					t.Fatalf("asset metadata=%+v", report.Assets)
				}
				status, reason, collected := "complete", "", 1
				if tc.noReferences {
					collected = 0
				} else if tc.unsupportedPage {
					status, reason, collected = "skipped", "unsupported_page_type", 0
				} else if tc.reason != "" {
					status, reason, collected = "incomplete", "asset_failures_or_skips", 0
				} else if tc.lateFailure {
					status, reason = "incomplete", "asset_failures_or_skips"
				}
				if report.Assets.Status != status || report.Assets.Reason != reason || report.Assets.Collected != collected || report.Assets.DecodedBytes > budget.MaxTotalDecodedBytes || report.Assets.EncodedBytes > budget.MaxTotalEncodedBytes {
					t.Errorf("asset scope/accounting=%+v", report.Assets)
				}
				if len(report.Assets.Items) == 0 {
					return
				}
				item := report.Assets.Items[0]
				itemStatus := "collected"
				if tc.reason != "" {
					itemStatus = "failed"
				}
				if item.URL != assetURL || item.Kind != "javascript" || item.Status != itemStatus || item.Reason != tc.reason || item.HTTPStatus != tc.status {
					t.Errorf("asset item=%+v", item)
				}
				if tc.wantFinding && item.DecodedBytes != int64(len(body)) {
					t.Errorf("decoded bytes=%d want=%d", item.DecodedBytes, len(body))
				}
				if tc.reason == "decoded_body_limit" && item.DecodedBytes != budget.MaxAssetDecodedBytes+1 {
					t.Errorf("decoded overflow=%+v", item)
				}
				if tc.encodedOverflow && item.EncodedBytes != budget.MaxAssetEncodedBytes+1 {
					t.Errorf("encoded overflow=%+v", item)
				}
			})
		}
	}
}
