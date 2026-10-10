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

	"webscan/internal/cli"
	"webscan/internal/output"
)

const buildManifestFixture = `self.__BUILD_MANIFEST={"/fixture":["private-body.js"]};self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();`
const ssgManifestFixture = `self.__SSG_MANIFEST=new Set;self.__SSG_MANIFEST_CB&&self.__SSG_MANIFEST_CB();`

func TestCLIAssetFindingsEvidenceAndPrivacy(t *testing.T) {
	for _, format := range []string{"json", "plain", "color"} {
		for _, redacted := range []bool{false, true} {
			for _, header := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/redact=%t/header=%t", format, redacted, header), func(t *testing.T) {
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						switch r.URL.Path {
						case "/":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("Server", "nginx")
							if header {
								w.Header().Set("X-Powered-By", "Next.js")
							}
							fmt.Fprint(w, `<script src="/renamed.js?private-token=1"></script><script src="/renamed.js?private-token=1#duplicate"></script><script src="/second?private-other=1"></script><script src="/fail"></script>`)
						case "/renamed.js":
							w.Header().Set("Content-Type", "application/javascript")
							w.Header().Set("Content-Encoding", "gzip")
							w.Header().Set("X-Powered-By", "Express") // Not a page finding.
							gz := gzip.NewWriter(w)
							fmt.Fprint(gz, buildManifestFixture)
							if err := gz.Close(); err != nil {
								t.Error(err)
							}
						case "/second":
							w.Header().Set("Content-Type", "text/javascript")
							fmt.Fprint(w, ssgManifestFixture)
						case "/fail":
							w.WriteHeader(403)
							fmt.Fprint(w, "private-error-body")
						default:
							t.Errorf("unexpected path: %s", r.URL.Path)
						}
					}))
					defer server.Close()
					args := []string{"--assets"}
					if format == "json" {
						args = append(args, "--json")
					} else if format == "color" {
						args = append(args, "--color=always")
					} else {
						args = append(args, "--no-color")
					}
					if redacted {
						args = append(args, "--redact-query")
					}
					var stdout, stderr bytes.Buffer
					code := cli.Run(append(args, server.URL), &stdout, &stderr, "dev")
					if code != 0 || stderr.Len() != 0 {
						t.Fatalf("code=%d stderr=%s", code, &stderr)
					}
					mu.Lock()
					gotRequests := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(gotRequests, []string{"/", "/renamed.js?private-token=1", "/second?private-other=1", "/fail"}) {
						t.Errorf("requests=%v", gotRequests)
					}
					for _, raw := range []string{"private-body", "private-error-body", "Express", "self.__"} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("raw asset value leaked: %s", raw)
						}
					}
					url1, url2 := server.URL+"/renamed.js?private-token=1", server.URL+"/second?private-other=1"
					if redacted {
						url1, url2 = server.URL+"/renamed.js?[redacted]", server.URL+"/second?[redacted]"
						if strings.Contains(stdout.String(), "private-") {
							t.Fatal("asset/evidence query leaked")
						}
					}
					if format == "json" {
						var report output.Report
						if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
							t.Fatal(err)
						}
						if report.CatalogSize != 19 || len(report.Findings) != 2 || report.Findings[0].ID != "nextjs" || report.Findings[1].ID != "nginx" || report.Assets == nil || report.Assets.Status != "incomplete" || report.Assets.Collected != 2 {
							t.Fatalf("report=%+v assets=%+v", report, report.Assets)
						}
						next := report.Findings[0]
						wantState, wantEvidence := "inferred", 2
						if header {
							wantState, wantEvidence = "detected", 3
						}
						if next.State != wantState || len(next.Evidence) != wantEvidence || next.Evidence[0].AssetURL != url1 || next.Evidence[1].AssetURL != url2 {
							t.Fatalf("next=%+v", next)
						}
						for i, rule := range []string{"asset-build-manifest", "asset-ssg-manifest"} {
							if next.Evidence[i].RuleID != rule || !reflect.DeepEqual(next.Evidence[i].Signals, []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}) {
								t.Errorf("evidence=%+v", next.Evidence[i])
							}
						}
					} else {
						marker := "?"
						if header {
							marker = "✓"
						}
						if format == "color" {
							if header {
								marker = "\x1b[32m✓\x1b[0m"
							} else {
								marker = "\x1b[33m?\x1b[0m"
							}
						}
						if !strings.Contains(stdout.String(), marker+" Next.js [framework]") || !strings.Contains(stdout.String(), "    Asset: "+url1+"\n") || !strings.Contains(stdout.String(), "    Asset: "+url2+"\n") {
							t.Fatalf("output=%s", &stdout)
						}
					}
				})
			}
		}
	}
}

func TestCLIAssetFingerprintsRejectUnusableOrWrongSourceBodies(t *testing.T) {
	for _, scenario := range []string{"disabled", "css", "html-type", "missing-type", "error-status", "redirect", "truncated", "oversized", "split-files", "inline", "wrong-headers", "successful"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html")
					w.Header().Set("Server", "nginx")
					switch scenario {
					case "inline":
						fmt.Fprintf(w, "<script>%s</script>", buildManifestFixture)
					case "css":
						fmt.Fprint(w, `<link rel="stylesheet" href="/a">`)
					case "split-files":
						fmt.Fprint(w, `<script src="/a"></script><script src="/b"></script>`)
					default:
						fmt.Fprint(w, `<script src="/a"></script>`)
					}
					return
				}
				if scenario == "disabled" || r.URL.Path == "/destination" {
					t.Errorf("unexpected asset/redirect request: %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "text/javascript")
				switch scenario {
				case "css":
					w.Header().Set("Content-Type", "text/css")
				case "html-type":
					w.Header().Set("Content-Type", "text/html")
				case "missing-type":
					w.Header()["Content-Type"] = nil
				case "error-status":
					w.WriteHeader(403)
				case "redirect":
					w.Header().Set("Location", "/destination")
					w.WriteHeader(302)
				case "truncated":
					w.Header().Set("Content-Length", fmt.Sprint(len(buildManifestFixture)+100))
				case "oversized":
					fmt.Fprint(w, buildManifestFixture+strings.Repeat(" ", 512<<10))
					return
				case "split-files":
					if r.URL.Path == "/a" {
						fmt.Fprint(w, `self.__BUILD_MANIFEST={};`)
					} else {
						fmt.Fprint(w, `self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()`)
					}
					return
				case "wrong-headers":
					w.Header().Set("X-Powered-By", "Next.js")
					fmt.Fprint(w, "unrelated body")
					return
				}
				fmt.Fprint(w, buildManifestFixture)
			}))
			defer server.Close()
			args := []string{"--json"}
			if scenario != "disabled" {
				args = append(args, "--assets")
			}
			var stdout, stderr bytes.Buffer
			if code := cli.Run(append(args, server.URL), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
				t.Fatalf("code=%d stderr=%s", code, &stderr)
			}
			var report output.Report
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			want := []string{"nginx"}
			if scenario == "successful" {
				want = []string{"nextjs", "nginx"}
			}
			var ids []string
			for _, f := range report.Findings {
				ids = append(ids, f.ID)
			}
			if !reflect.DeepEqual(ids, want) {
				t.Fatalf("IDs=%v want=%v", ids, want)
			}
			if scenario == "disabled" && report.Assets != nil {
				t.Error("default report gained assets")
			}
		})
	}
}
