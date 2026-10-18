package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestTechsCatalogOffline(t *testing.T) {
	// Do not allow accidental network access, including if fetching is introduced
	// into this command later. These tests must not run in parallel.
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	var connections atomic.Int32
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		connections.Add(1)
		return nil, errors.New("network forbidden for --techs")
	}
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = original
		transport.CloseIdleConnections()
	})
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--techs"}, {"--techs", "--color=always"}, {"--no-color", "--techs"},
		{"--techs", "--json"}, {"--json", "--techs", "--color=always"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := cli.Run(args, &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			if strings.Contains(stdout.String(), "\x1b") {
				t.Error("catalog should remain unstyled")
			}
			if !strings.Contains(strings.Join(args, " "), "--json") {
				for _, want := range []string{"Supported technologies (", "Web development", "Infrastructure", "Web servers", "Web frameworks", "JavaScript frameworks", "JavaScript libraries", "UI frameworks", "CMS", "Languages", "CDN/edge", "Load balancers", "WAFs", "identification is not guaranteed"} {
					if !strings.Contains(stdout.String(), want) {
						t.Errorf("missing %q in %s", want, &stdout)
					}
				}
				for _, tech := range engine.Technologies() {
					if !strings.Contains(stdout.String(), "    "+tech.Name+"\n") {
						t.Errorf("missing bundled technology %s", tech.ID)
					}
				}
				if !strings.Contains(stdout.String(), "    Next.js\n    Nuxt\n") {
					t.Error("Nuxt must appear in the alphabetically ordered framework group")
				}
				if !strings.Contains(stdout.String(), "Web frameworks\n    Django\n    Express\n") {
					t.Error("Django and Express must appear under web frameworks")
				}
				if !strings.Contains(stdout.String(), "    Nuxt\n    Ruby on Rails\n  JavaScript frameworks\n") {
					t.Error("Rails must end the web-framework category before JavaScript frameworks")
				}
				if !strings.Contains(stdout.String(), "JavaScript frameworks\n    Angular\n    React\n    Vue\n  JavaScript libraries\n    jQuery\n  UI frameworks\n") {
					t.Error("Angular, React and Vue must be ordered under JavaScript frameworks")
				}
				if !strings.Contains(stdout.String(), "\n  UI frameworks\n    Bootstrap\n") {
					t.Error("Bootstrap must appear under UI frameworks")
				}
				if !strings.Contains(stdout.String(), "\n  Languages\n    PHP\n    Python\n    Ruby\n") {
					t.Error("direct and inference-only languages must appear in alphabetical order")
				}
				if !strings.Contains(stdout.String(), "\n  Web servers\n    Apache HTTP Server\n    Jetty\n    Microsoft IIS\n    nginx\n") {
					t.Error("Jetty must appear in the alphabetically ordered infrastructure web-server category")
				}
				if strings.Count(stdout.String(), "\nWeb development\n") != 1 || strings.Count(stdout.String(), "\nInfrastructure\n") != 1 {
					t.Error("each nonempty organization group must have one heading")
				}
				return
			}
			var report output.CatalogReport
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || len(report.Technologies) != engine.Len() {
				t.Fatalf("unexpected catalog metadata: %+v", report)
			}
			byID := make(map[string]output.Technology)
			for _, tech := range report.Technologies {
				byID[tech.ID] = tech
			}
			if got := byID["jetty"]; got.Name != "Jetty" || got.Category != "web_server" {
				t.Errorf("missing or incorrect Jetty metadata: %+v", got)
			}
			if got := byID["angular"]; got.Name != "Angular" || got.Category != "javascript_framework" {
				t.Errorf("missing or incorrect Angular metadata: %+v", got)
			}
			if got := byID["nuxt"]; got.Name != "Nuxt" || got.Category != "framework" {
				t.Errorf("missing or incorrect Nuxt metadata: %+v", got)
			}
			if got := byID["django"]; got.Name != "Django" || got.Category != "framework" {
				t.Errorf("missing or incorrect Django metadata: %+v", got)
			}
			if got := byID["rails"]; got.Name != "Ruby on Rails" || got.Category != "framework" {
				t.Errorf("missing or incorrect Rails metadata: %+v", got)
			}
			for id, name := range map[string]string{"python": "Python", "ruby": "Ruby"} {
				if got := byID[id]; got.Name != name || got.Category != "language" {
					t.Errorf("missing or incorrect inference-only language metadata: %+v", got)
				}
			}
			if got := byID["react"]; got.Name != "React" || got.Category != "javascript_framework" {
				t.Errorf("missing or incorrect React metadata: %+v", got)
			}
			if got := byID["vue"]; got.Name != "Vue" || got.Category != "javascript_framework" {
				t.Errorf("missing or incorrect Vue metadata: %+v", got)
			}
			if got := byID["bootstrap"]; got.Name != "Bootstrap" || got.Category != "ui_framework" {
				t.Errorf("missing or incorrect Bootstrap metadata: %+v", got)
			}
			if got := byID["jquery"]; got.Name != "jQuery" || got.Category != "javascript_library" {
				t.Errorf("missing or incorrect jQuery metadata: %+v", got)
			}
			for _, tech := range engine.Technologies() {
				if got := byID[tech.ID]; got.Name != tech.Name || got.Category != string(tech.Category) {
					t.Errorf("catalog mismatch for %s: %+v", tech.ID, got)
				}
			}
			var raw struct {
				Technologies []map[string]json.RawMessage `json:"technologies"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			for _, entry := range raw.Technologies {
				if len(entry) != 3 || entry["id"] == nil || entry["name"] == nil || entry["category"] == nil {
					t.Errorf("catalog JSON must retain flat id/name/category entries: %v", entry)
				}
			}
		})
	}
	if connections.Load() != 0 {
		t.Errorf("--techs attempted %d network connections", connections.Load())
	}
}

func TestTechsConflictingArguments(t *testing.T) {
	for _, extra := range [][]string{
		{"https://example.test"}, {"--version"}, {"--timeout=15s"},
		{"--max-redirects=5"}, {"--max-body=2097152"}, {"--color=invalid"},
		{"--max-encoded-body=4194304"},
		{"--allow-http-downgrade"}, {"--allow-http-downgrade=false"},
		{"--redact-query"}, {"--redact-query=false"},
		{"--asset-budget=standard"}, {"--asset-budget=expanded"},
	} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run(append([]string{"--techs", "--json"}, extra...), &stdout, &stderr, "dev"); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("args=%v exit=%d stdout=%q stderr=%q", extra, code, stdout.String(), stderr.String())
		}
	}
}

func TestTechsWriteFailure(t *testing.T) {
	for _, args := range [][]string{{"--techs"}, {"--techs", "--json"}} {
		var stderr bytes.Buffer
		if code := cli.Run(args, brokenOutput{}, &stderr, "dev"); code != 1 || !strings.Contains(stderr.String(), "write catalog") {
			t.Errorf("exit=%d stderr=%q", code, stderr.String())
		}
	}
}
