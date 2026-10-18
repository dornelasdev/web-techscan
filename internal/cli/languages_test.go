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

func requireLanguageReport(t *testing.T, finding output.Finding, id, parent string) {
	t.Helper()
	names := map[string]string{"php": "PHP", "python": "Python", "ruby": "Ruby"}
	parents := map[string]string{"laravel": "Laravel", "django": "Django", "rails": "Ruby on Rails"}
	if names[id] == "" || parents[parent] == "" {
		t.Fatalf("unsupported language expectation: %s from %s", id, parent)
	}
	if finding.ID != id || finding.Name != names[id] || finding.Category != "language" || finding.State != "inferred" || len(finding.Evidence) != 1 {
		t.Fatalf("want inferred %s, got %+v", names[id], finding)
	}
	e := finding.Evidence[0]
	if e.InferredFrom != parent || e.Description != "Inferred from "+parents[parent] || e.RuleID != "" || e.AssetURL != "" || e.Signals == nil || len(e.Signals) != 0 {
		t.Errorf("want relationship evidence with a non-null empty signals array: %+v", e)
	}
}

func TestLanguagesThroughCLI(t *testing.T) {
	for _, complete := range []bool{false, true} {
		for _, format := range []string{"plain", "color", "json"} {
			t.Run(fmt.Sprintf("complete=%t/%s", complete, format), func(t *testing.T) {
				var requests atomic.Int32
				var unexpected atomic.Bool
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.Method != "GET" || r.URL.Path != "/page" || r.URL.Query().Get("token") != "private-query" || r.Header.Get("Cookie") != "" {
						unexpected.Store(true)
					}
					w.Header().Set("Content-Type", "text/html")
					for _, name := range []string{"csrftoken", "laravel_session", "XSRF-TOKEN"} {
						http.SetCookie(w, &http.Cookie{Name: name, Value: "private-cookie", Path: "/"})
					}
					body := `<input type="hidden"><meta name="csrf-param" content="authenticity_token">`
					if complete {
						body = `<input type="hidden" name="csrfmiddlewaretoken" value="private-django-token"><meta name="csrf-param" content="authenticity_token"><meta name="csrf-token" content="private-rails-token">`
					}
					fmt.Fprint(w, body)
				}))
				defer server.Close()
				args := []string{"--redact-query", "--color=always"}
				if format == "plain" {
					args = append(args, "--no-color")
				} else if format == "json" {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				code := cli.Run(append(args, server.URL+"/page?token=private-query"), &stdout, &stderr, "dev")
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, &stderr)
				}
				if requests.Load() != 1 || unexpected.Load() {
					t.Fatalf("language inference changed request scope: requests=%d unexpected=%t", requests.Load(), unexpected.Load())
				}
				for _, private := range []string{"private-query", "private-cookie", "private-django-token", "private-rails-token"} {
					if strings.Contains(stdout.String(), private) {
						t.Errorf("raw private value leaked: %s", private)
					}
				}
				if strings.Contains(stdout.String(), "\x1b") != (format == "color") {
					t.Error("incorrect color handling")
				}
				wantIDs := []string{"laravel", "php"}
				if complete {
					wantIDs = []string{"django", "laravel", "php", "python", "rails", "ruby"}
				}
				if format == "json" {
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					if report.SchemaVersion != 1 || !report.QueryRedacted || report.Assets != nil {
						t.Errorf("unexpected report metadata: %+v", report)
					}
					ids := []string{}
					for _, finding := range report.Findings {
						ids = append(ids, finding.ID)
						if parent := map[string]string{"php": "laravel", "python": "django", "ruby": "rails"}[finding.ID]; parent != "" {
							requireLanguageReport(t, finding, finding.ID, parent)
						}
					}
					if !reflect.DeepEqual(ids, wantIDs) {
						t.Errorf("IDs=%v want=%v", ids, wantIDs)
					}
					return
				}
				marker := "?"
				if format == "color" {
					marker = "\x1b[33m?\x1b[0m"
				}
				wantLines := []string{marker + " Laravel [framework]", marker + " PHP [language]"}
				if complete {
					wantLines = []string{marker + " Django [framework]", marker + " Laravel [framework]", marker + " PHP [language]", marker + " Python [language]", marker + " Ruby on Rails [framework]", marker + " Ruby [language]"}
				}
				gotLines := []string{}
				for _, line := range strings.Split(stdout.String(), "\n") {
					if strings.HasPrefix(line, marker+" ") && strings.Contains(line, " [") {
						gotLines = append(gotLines, line)
					}
				}
				if !reflect.DeepEqual(gotLines, wantLines) {
					t.Errorf("findings=%v want=%v", gotLines, wantLines)
				}
				for _, parent := range []string{"Django", "Ruby on Rails"} {
					if strings.Contains(stdout.String(), "Inferred from "+parent) != complete {
						t.Errorf("incorrect language provenance for %s", parent)
					}
				}
			})
		}
	}
}
