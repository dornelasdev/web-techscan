package cli_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/output"
)

func TestJSONCLIReport(t *testing.T) {
	for _, status := range []int{200, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					http.Redirect(w, r, "/final", http.StatusFound)
					return
				}
				w.Header().Set("Server", "nginx")
				http.SetCookie(w, &http.Cookie{Name: "laravel_session", Value: "secret-cookie"})
				http.SetCookie(w, &http.Cookie{Name: "XSRF-TOKEN", Value: "secret-cookie"})
				w.WriteHeader(status)
				fmt.Fprint(w, "secret-body")
			}))
			defer server.Close()
			var stdout, stderr bytes.Buffer
			code := cli.Run([]string{"--json", "--color=always", server.URL + "/start"}, &stdout, &stderr, "dev")
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
			decoder.DisallowUnknownFields()
			var report output.Report
			if err := decoder.Decode(&report); err != nil {
				t.Fatalf("invalid JSON report: %v; output=%s", err, &stdout)
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				t.Errorf("extra output after JSON: %v", err)
			}
			if report.SchemaVersion != 1 || report.HTTPStatus != status || len(report.Findings) != 3 {
				t.Fatalf("unexpected report: %+v", report)
			}
			if report.URL != server.URL+"/start" || report.FinalURL != server.URL+"/final" || len(report.Redirects) != 1 {
				t.Errorf("missing URL/redirect metadata: %+v", report)
			}
			if report.Findings[2].ID != "php" || report.Findings[2].State != "inferred" || report.Findings[2].Evidence[0].InferredFrom != "laravel" {
				t.Errorf("missing inference evidence: %+v", report.Findings)
			}
			wantScope := "final_response"
			if status == 403 {
				wantScope = "http_error_response"
			}
			if report.ResponseScope != wantScope {
				t.Errorf("scope=%q, want %q", report.ResponseScope, wantScope)
			}
			for _, absent := range []string{"\x1b", "secret-body", "secret-cookie", "✓"} {
				if strings.Contains(stdout.String(), absent) {
					t.Errorf("unexpected JSON content %q", absent)
				}
			}
		})
	}
}

func TestJSONEmptyResultsAndFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "unrecognized page")
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"--json", server.URL}, &stdout, &stderr, "dev"); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, &stderr)
	}
	if !json.Valid(stdout.Bytes()) || !strings.Contains(stdout.String(), `"findings": []`) {
		t.Errorf("unexpected empty report: %s", &stdout)
	}
	for _, args := range [][]string{
		{"--json", "--max-body=1", server.URL},
		{"--json", "invalid-url"},
		{"--json", "--color=invalid", server.URL},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := cli.Run(args, &stdout, &stderr, "dev"); code == 0 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("failed request must not emit a success report: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}

func TestCLIColorFlags(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
	}))
	defer server.Close()
	for _, tc := range []struct {
		args      []string
		wantColor bool
	}{
		{[]string{"--color=always"}, true},
		{[]string{"--color=never"}, false},
		{[]string{"--color=always", "--no-color"}, false},
		{[]string{"--no-color", "--color=always"}, false},
		{nil, false},
	} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run(append(tc.args, server.URL), &stdout, &stderr, "dev"); code != 0 {
			t.Fatalf("code=%d stderr=%s", code, &stderr)
		}
		if strings.Contains(stdout.String(), "\x1b[") != tc.wantColor {
			t.Errorf("args=%v output=%q, want color=%t", tc.args, stdout.String(), tc.wantColor)
		}
	}
}

type brokenOutput struct{}

func (brokenOutput) Write([]byte) (int, error) { return 0, errors.New("closed output") }

func TestCLIReportWriteFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	for _, flags := range [][]string{nil, {"--json"}} {
		var stderr bytes.Buffer
		if code := cli.Run(append(flags, server.URL), brokenOutput{}, &stderr, "dev"); code != 1 || !strings.Contains(stderr.String(), "write report") {
			t.Errorf("code=%d stderr=%q, want execution error", code, stderr.String())
		}
	}
}
