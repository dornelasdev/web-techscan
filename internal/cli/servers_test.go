package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/output"
)

func TestServerCoverageThroughCLI(t *testing.T) {
	for _, tech := range []struct {
		id, name, valid, malformed, redirectBanner string
	}{
		{"apache", "Apache HTTP Server", "Apache/2.4.62 (Unix) PHP/8.3.12 MyMod/1.2", "Apache/2..4", "Microsoft-IIS/10.0"},
		{"iis", "Microsoft IIS", "Microsoft-IIS/10.0", "Microsoft-IIS/10..0", "nginx/1.26.2"},
		{"nginx", "nginx", "nginx/1.26.2 (private build 123)", "nginx/1..2", "Apache/2.4.62"},
	} {
		for _, tc := range []struct {
			name, contentType string
			values            []string
			status            int
			redirect, want    bool
		}{
			{"html", "text/html", []string{tech.valid}, 200, false, true},
			{"plain-error", "text/plain", []string{tech.valid}, 403, false, true},
			{"repeated-fields", "text/html", []string{tech.malformed, tech.valid, tech.valid}, 200, false, true},
			{"malformed-version", "text/html", []string{tech.malformed}, 200, false, false},
			{"unstructured-trailer", "text/plain", []string{tech.valid + " proxy"}, 200, false, false},
			{"combined-field", "text/html", []string{tech.valid + ", " + tech.redirectBanner}, 200, false, false},
			{"wrong-source-only", "text/html", nil, 200, false, false},
			{"generic-error", "text/plain", nil, 503, false, false},
			{"redirect-to-valid", "text/html", []string{tech.valid}, 200, true, true},
			{"redirect-to-empty", "text/html", nil, 200, true, false},
			{"redirect-to-malformed", "text/plain", []string{tech.malformed}, 403, true, false},
		} {
			for _, format := range []string{"terminal", "json"} {
				t.Run(tech.id+"/"+tc.name+"/"+format, func(t *testing.T) {
					var requests atomic.Int32
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if r.URL.Path == "/start" {
							w.Header().Set("Server", tech.redirectBanner)
							http.Redirect(w, r, "/final", http.StatusFound)
							return
						}
						if r.URL.Path != "/final" {
							http.NotFound(w, r)
							return
						}
						w.Header().Set("Content-Type", tc.contentType)
						w.Header().Set("X-Server", tech.valid)
						for _, value := range tc.values {
							w.Header().Add("Server", value)
						}
						w.WriteHeader(tc.status)
						fmt.Fprintf(w, `<footer>%s</footer><script src="/asset.js"></script><a href="/other">fixture</a>`, tech.valid)
					}))
					defer server.Close()
					url, count := server.URL+"/final", int32(1)
					if tc.redirect {
						url, count = server.URL+"/start", 2
					}
					args := []string{"--no-color"}
					if format == "json" {
						args = append(args, "--json")
					}
					var stdout, stderr bytes.Buffer
					if code := cli.Run(append(args, url), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
						t.Fatalf("exit=%d stderr=%q", code, &stderr)
					}
					if requests.Load() != count {
						t.Errorf("requests=%d, want %d page/redirect requests", requests.Load(), count)
					}
					for _, raw := range []string{tech.valid, tech.malformed, tech.redirectBanner, "\x1b"} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("unexpected raw response value/style %q", raw)
						}
					}
					if format == "terminal" {
						wantLines := []string{}
						if tc.want {
							wantLines = append(wantLines, "✓ "+tech.name+" [web server]")
						}
						gotLines := []string{}
						for _, line := range strings.Split(stdout.String(), "\n") {
							if (strings.HasPrefix(line, "✓ ") || strings.HasPrefix(line, "? ")) && strings.Contains(line, " [") {
								gotLines = append(gotLines, line)
							}
						}
						if !reflect.DeepEqual(gotLines, wantLines) {
							t.Fatalf("findings=%v want=%v", gotLines, wantLines)
						}
						if strings.Contains(stdout.String(), "No technologies detected.") != !tc.want || strings.Contains(stdout.String(), "may be an intermediary") != tc.want {
							t.Errorf("unexpected evidence/empty result: %s", &stdout)
						}
						if strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") != (tc.status >= 400) {
							t.Error("incorrect error-response scope")
						}
						return
					}
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					scope := "final_response"
					if tc.status >= 400 {
						scope = "http_error_response"
					}
					if report.SchemaVersion != 1 || report.URL != url || report.FinalURL != server.URL+"/final" || report.HTTPStatus != tc.status || report.ResponseScope != scope || len(report.Redirects) != int(count-1) {
						t.Errorf("unexpected report metadata: %+v", report)
					}
					if !tc.want {
						if report.Findings == nil || len(report.Findings) != 0 {
							t.Fatalf("want empty findings, got %+v", report.Findings)
						}
						return
					}
					if len(report.Findings) != 1 {
						t.Fatalf("findings=%+v, want only %s without inferred languages", report.Findings, tech.id)
					}
					finding := report.Findings[0]
					if finding.ID != tech.id || finding.Name != tech.name || finding.Category != "web_server" || finding.State != "detected" || len(finding.Evidence) != 1 {
						t.Fatalf("unexpected finding: %+v", finding)
					}
					evidence := finding.Evidence[0]
					if evidence.RuleID != "server-header" || evidence.InferredFrom != "" || !strings.Contains(evidence.Description, "may be an intermediary") || !reflect.DeepEqual(evidence.Signals, []output.Signal{{Source: "header", Name: "Server"}}) {
						t.Errorf("unexpected evidence: %+v", evidence)
					}
				})
			}
		}
	}
}
