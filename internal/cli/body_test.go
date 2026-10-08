package cli_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/output"
)

func TestBodyHandlingThroughCLI(t *testing.T) {
	const body = `<script id="__NEXT_DATA__">{"private":"private-payload"}</script><script src="/_next/static/private-asset.js"></script>`
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	checksum := append([]byte(nil), compressed.Bytes()...)
	checksum[len(checksum)-8] ^= 1
	for _, tc := range []struct {
		name      string
		encodings []string
		wire      []byte
		status    int
		reason    string
		flags     []string
	}{
		{"gzip-success", []string{"gzip"}, compressed.Bytes(), 200, "", nil},
		{"gzip-error-page", []string{"gzip"}, compressed.Bytes(), 403, "", nil},
		{"identity", []string{"identity"}, []byte(body), 200, "", nil},
		{"unsupported", []string{"private-unsupported"}, []byte(body), 200, "unsupported or ambiguous response content encoding", nil},
		{"stacked", []string{"gzip, br"}, compressed.Bytes(), 200, "unsupported or ambiguous response content encoding", nil},
		{"repeated-fields", []string{"gzip", "br"}, compressed.Bytes(), 200, "unsupported or ambiguous response content encoding", nil},
		{"gzip-header", []string{"gzip"}, []byte("private-invalid-gzip"), 200, "invalid gzip header", nil},
		{"gzip-checksum", []string{"gzip"}, checksum, 200, "invalid gzip checksum", nil},
		{"gzip-truncated", []string{"gzip"}, compressed.Bytes()[:compressed.Len()-4], 200, "incomplete response body", nil},
		{"gzip-limit", []string{"gzip"}, compressed.Bytes(), 200, "response body limit exceeded", []string{"--max-body=32"}},
		{"short-length", nil, []byte(body), 200, "incomplete response body", nil},
		{"bad-chunk", nil, nil, 200, "invalid or incomplete response body", nil},
		{"body-timeout", nil, nil, 200, "timed out", []string{"--timeout=200ms"}},
		{"gzip-header-timeout", []string{"gzip"}, nil, 200, "timed out", []string{"--timeout=200ms"}},
		{"large-header", nil, nil, 200, "network error or invalid HTTP response", nil},
		{"no-content", []string{"gzip"}, nil, 204, "", nil},
		{"not-modified", []string{"br"}, nil, 304, "", nil},
	} {
		for _, asJSON := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", tc.name, asJSON), func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.Method != "GET" || r.URL.Path != "/" || r.Header.Get("Accept-Encoding") != "gzip" {
						t.Errorf("unexpected request: %s %s %v", r.Method, r.URL.Path, r.Header)
					}
					if tc.name == "bad-chunk" {
						conn, rw, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						defer conn.Close()
						fmt.Fprint(rw, "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npart\r\nZZ\r\n")
						if err := rw.Flush(); err != nil {
							t.Error(err)
						}
						return
					}
					w.Header().Set("Content-Type", "text/html")
					w.Header().Set("Server", "nginx")
					for _, encoding := range tc.encodings {
						w.Header().Add("Content-Encoding", encoding)
					}
					if tc.name == "short-length" {
						w.Header().Set("Content-Length", "9999")
					}
					if tc.name == "large-header" {
						w.Header().Set("X-Large", strings.Repeat("x", (1<<20)+4096))
					}
					w.WriteHeader(tc.status)
					if tc.name == "body-timeout" || tc.name == "gzip-header-timeout" {
						if tc.name == "body-timeout" {
							fmt.Fprint(w, "partial")
						}
						w.(http.Flusher).Flush()
						<-r.Context().Done()
						return
					}
					w.Write(tc.wire)
				}))
				defer server.Close()
				args := append([]string{"--no-color"}, tc.flags...)
				if asJSON {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				code := cli.Run(append(args, server.URL), &stdout, &stderr, "dev")
				if requests.Load() != 1 {
					t.Errorf("unexpected extra requests: %d", requests.Load())
				}
				for _, raw := range []string{"private-payload", "private-asset.js", "private-unsupported", "private-invalid-gzip", "\x1b"} {
					if strings.Contains(stdout.String()+stderr.String(), raw) {
						t.Errorf("output contains raw data %q", raw)
					}
				}
				if tc.reason != "" {
					if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.reason) {
						t.Fatalf("exit=%d stdout=%q stderr=%q want failure %q", code, &stdout, &stderr, tc.reason)
					}
					return
				}
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, &stderr)
				}
				noBody := tc.status == 204 || tc.status == 304
				if !asJSON {
					if !strings.Contains(stdout.String(), "✓ nginx [web server]") || strings.Contains(stdout.String(), "? Next.js [framework]") != !noBody {
						t.Errorf("unexpected findings: %s", &stdout)
					}
					if strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") != (tc.status >= 400) {
						t.Error("wrong response scope")
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				wantBytes, wantCount := len(body), 2
				if noBody {
					wantBytes, wantCount = 0, 1
				}
				if report.BodyBytes != wantBytes || report.HTTPStatus != tc.status || len(report.Findings) != wantCount {
					t.Fatalf("unexpected report: %+v", report)
				}
				if !noBody && (report.Findings[0].ID != "nextjs" || report.Findings[0].State != "inferred") {
					t.Errorf("missing decoded HTML evidence: %+v", report.Findings)
				}
				last := report.Findings[len(report.Findings)-1]
				if last.ID != "nginx" || last.State != "detected" {
					t.Errorf("incorrect header evidence: %+v", last)
				}
			})
		}
	}
}
