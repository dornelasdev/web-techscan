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

func TestRedirectUnicodeIsSanitizedOnlyForTerminal(t *testing.T) {
	const query = "q=café-\u202eevil\u202c-\u2066text\u2069-\u061c\u200e\u200f\u2028\u2029&literal=%E2%80%AE"
	const cleanQuery = "q=café-�evil�-�text�-�����&literal=%E2%80%AE"
	for _, mode := range []string{"plain", "color", "json"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, r.URL.RequestURI())
				mu.Unlock()
				if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "webscan" {
					t.Errorf("unexpected request: %s UA=%q", r.Method, r.Header.Get("User-Agent"))
				}
				switch r.URL.Path {
				case "/start":
					// Set the raw Location explicitly; http.Redirect may escape it.
					w.Header().Set("Location", "/final?"+query)
					w.WriteHeader(http.StatusFound)
				case "/final":
					w.Header().Set("Server", "nginx")
					w.Header().Set("Content-Type", "text/plain")
					fmt.Fprint(w, "page")
				default:
					t.Errorf("unexpected path: %q", r.URL.Path)
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
			var stdout, stderr bytes.Buffer
			code := cli.Run(append(args, server.URL+"/start"), &stdout, &stderr, "dev")
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			mu.Lock()
			gotRequests := append([]string(nil), requests...)
			mu.Unlock()
			if !reflect.DeepEqual(gotRequests, []string{"/start", "/final?" + query}) {
				t.Errorf("request URL changed or extra requests made: %q", gotRequests)
			}
			if mode == "json" {
				if strings.Contains(stdout.String(), "\x1b") {
					t.Error("JSON contains ANSI styling despite ignoring color flags")
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				if report.URL != server.URL+"/start" || report.FinalURL != server.URL+"/final?"+query || len(report.Redirects) != 1 || report.Redirects[0].ToURL != report.FinalURL {
					t.Fatalf("JSON URLs changed: %#v", report)
				}
				if report.BodyBytes != 4 || len(report.Findings) != 1 || report.Findings[0].ID != "nginx" || report.Findings[0].State != "detected" {
					t.Errorf("unexpected scan results: %#v", report)
				}
				return
			}
			if !strings.HasPrefix(stdout.String(), "URL: "+server.URL+"/final?"+cleanQuery+"\nHTTP status: 200\n") {
				t.Errorf("unexpected terminal URL: %q", stdout.String())
			}
			marker := "✓"
			if mode == "color" {
				marker = "\x1b[32m✓\x1b[0m"
			} else if strings.Contains(stdout.String(), "\x1b") {
				t.Error("plain output contains ANSI styling")
			}
			if !strings.Contains(stdout.String(), marker+" nginx [web server]\n") {
				t.Errorf("missing finding: %q", stdout.String())
			}
		})
	}
}
