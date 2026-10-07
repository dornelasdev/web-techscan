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
				for _, want := range []string{"Supported technologies (", "Web servers", "Frameworks", "CMS", "Languages", "CDN/edge", "Load balancers", "WAFs", "identification is not guaranteed"} {
					if !strings.Contains(stdout.String(), want) {
						t.Errorf("missing %q in %s", want, &stdout)
					}
				}
				for _, tech := range engine.Technologies() {
					if !strings.Contains(stdout.String(), "  "+tech.Name+"\n") {
						t.Errorf("missing bundled technology %s", tech.ID)
					}
				}
				if !strings.Contains(stdout.String(), "  Next.js\n  Nuxt\n") {
					t.Error("Nuxt must appear in the alphabetically ordered framework group")
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
			if got := byID["nuxt"]; got.Name != "Nuxt" || got.Category != "framework" {
				t.Errorf("missing or incorrect Nuxt metadata: %+v", got)
			}
			for _, tech := range engine.Technologies() {
				if got := byID[tech.ID]; got.Name != tech.Name || got.Category != string(tech.Category) {
					t.Errorf("catalog mismatch for %s: %+v", tech.ID, got)
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
