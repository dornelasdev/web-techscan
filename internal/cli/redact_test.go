package cli_test

import (
	"bytes"
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

func TestCLIQueryRedactionDoesNotChangeRequests(t *testing.T) {
	const start = "/start?private-start=a&private-start=b"
	const middle = "/middle?private-middle=%zz&private-bare"
	const final = "/final%3Fpath?private-final=café&private-nested=a?b"
	for _, status := range []int{200, 403} {
		for _, setting := range []string{"default", "false", "true", "bare"} {
			for _, mode := range []string{"plain", "color", "json"} {
				t.Run(fmt.Sprintf("status=%d/redact=%s/%s", status, setting, mode), func(t *testing.T) {
					type request struct{ uri, referer string }
					var mu sync.Mutex
					var requests []request
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, request{r.RequestURI, r.Referer()})
						mu.Unlock()
						if r.Method != "GET" || r.UserAgent() != "webscan" {
							t.Errorf("unexpected request: %s UA=%q", r.Method, r.UserAgent())
						}
						switch r.URL.Path {
						case "/start":
							w.Header().Set("Location", middle)
							w.WriteHeader(302)
						case "/middle":
							w.Header().Set("Location", final)
							w.WriteHeader(307)
						case "/final?path":
							w.Header().Set("Server", "nginx")
							w.Header().Set("Content-Type", "text/plain")
							w.WriteHeader(status)
							fmt.Fprint(w, "page")
						default:
							t.Errorf("unexpected request path: %q", r.URL.Path)
							http.NotFound(w, r)
						}
					}))
					defer server.Close()
					args := []string{"--color=always"}
					if mode == "plain" {
						args = []string{"--no-color"}
					} else if mode == "json" {
						args = append(args, "--json")
					}
					if setting == "bare" {
						args = append(args, "--redact-query")
					} else if setting != "default" {
						args = append(args, "--redact-query="+setting)
					}
					var stdout, stderr bytes.Buffer
					code := cli.Run(append(args, server.URL+start+"#private-fragment"), &stdout, &stderr, "dev")
					if code != 0 || stderr.Len() != 0 {
						t.Fatalf("exit=%d stderr=%q", code, stderr.String())
					}
					mu.Lock()
					gotRequests := append([]request(nil), requests...)
					mu.Unlock()
					wantRequests := []request{{start, ""}, {middle, server.URL + start}, {final, server.URL + middle}}
					if !reflect.DeepEqual(gotRequests, wantRequests) {
						t.Errorf("requests/referrers changed: got=%#v want=%#v", gotRequests, wantRequests)
					}
					redact := setting == "true" || setting == "bare"
					startURL, middleURL, finalURL := server.URL+start, server.URL+middle, server.URL+final
					if redact {
						startURL, middleURL, finalURL = server.URL+"/start?[redacted]", server.URL+"/middle?[redacted]", server.URL+"/final%3Fpath?[redacted]"
						if strings.Contains(stdout.String(), "private-") {
							t.Errorf("report contains original query data: %q", stdout.String())
						}
					}
					if mode == "json" {
						var report output.Report
						if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
							t.Fatal(err)
						}
						wantRedirects := []output.Redirect{{FromURL: startURL, ToURL: middleURL, StatusCode: 302}, {FromURL: middleURL, ToURL: finalURL, StatusCode: 307}}
						if report.SchemaVersion != 1 || report.URL != startURL || report.FinalURL != finalURL || report.QueryRedacted != redact || !reflect.DeepEqual(report.Redirects, wantRedirects) {
							t.Errorf("unexpected report URLs/policy: %#v", report)
						}
						if strings.Contains(stdout.String(), `"query_redacted"`) != redact {
							t.Error("redaction metadata should be omitted when disabled")
						}
						if report.HTTPStatus != status || report.BodyBytes != 4 || len(report.Findings) != 1 || report.Findings[0].ID != "nginx" || report.Findings[0].State != "detected" {
							t.Errorf("scan data changed: %#v", report)
						}
						wantScope := "final_response"
						if status == 403 {
							wantScope = "http_error_response"
						}
						if report.ResponseScope != wantScope {
							t.Errorf("scope=%q want=%q", report.ResponseScope, wantScope)
						}
						if strings.Contains(stdout.String(), "\x1b") {
							t.Error("JSON contains styling")
						}
					} else {
						if !strings.HasPrefix(stdout.String(), "URL: "+finalURL+"\n") || strings.Contains(stdout.String(), "Query strings redacted in this report.") != redact {
							t.Errorf("unexpected terminal URL/policy: %q", stdout.String())
						}
						marker := "✓"
						if mode == "color" {
							marker = "\x1b[32m✓\x1b[0m"
						}
						if !strings.Contains(stdout.String(), marker+" nginx [web server]") {
							t.Error("missing finding or styling")
						}
					}
				})
			}
		}
	}
}

func TestQueryRedactionDoesNotHideFetchFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/final?private-target=secret")
			w.WriteHeader(302)
			return
		}
		fmt.Fprint(w, "page")
	}))
	defer server.Close()
	for _, tc := range []struct{ path, flag, reason string }{
		{"/redirect", "--max-redirects=0", "redirect limit exceeded"},
		{"/page", "--max-body=1", "response body limit exceeded"},
	} {
		for _, asJSON := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", tc.path, asJSON), func(t *testing.T) {
				args := []string{"--redact-query", tc.flag}
				if asJSON {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				code := cli.Run(append(args, server.URL+tc.path+"?private-input=secret"), &stdout, &stderr, "dev")
				if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.reason) || strings.Contains(stderr.String(), "private-") {
					t.Errorf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
			})
		}
	}
}
