package cli_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"webscan/internal/cli"
)

func TestInformationalCommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "no arguments", want: "Usage: webscan"},
		{name: "short help", args: []string{"-h"}, want: "Usage: webscan"},
		{name: "long help", args: []string{"--help"}, want: "Usage: webscan"},
		{name: "version", args: []string{"--version"}, want: "webscan v0.1.0-test\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := cli.Run(tc.args, &stdout, &stderr, "v0.1.0-test")
			if code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr: %s", code, &stderr)
			}
			if !strings.Contains(stdout.String(), tc.want) {
				t.Errorf("stdout = %q, want to contain %q", stdout.String(), tc.want)
			}
			if stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown option", args: []string{"--unknown"}, want: "flag provided but not defined"},
		{name: "invalid boolean", args: []string{"--version=invalid"}, want: "invalid boolean value"},
		{name: "multiple URLs", args: []string{"https://one.example", "https://two.example"}, want: "expected a single URL"},
		{name: "empty URL", args: []string{""}, want: "URL must not be empty"},
		{name: "version with URL", args: []string{"--version", "https://example.com"}, want: "--version does not accept a URL"},
		{name: "option after URL", args: []string{"https://example.com", "--version"}, want: "place options before the URL"},
		{name: "missing scheme", args: []string{"example.com"}, want: "include an http:// or https:// scheme"},
		{name: "unsupported scheme", args: []string{"file:///etc/hosts"}, want: "include an http:// or https:// scheme"},
		{name: "zero timeout", args: []string{"--timeout=0", "https://example.com"}, want: "timeout must be positive"},
		{name: "bad timeout", args: []string{"--timeout=soon", "https://example.com"}, want: "invalid value"},
		{name: "negative redirects", args: []string{"--max-redirects=-1", "https://example.com"}, want: "max-redirects must not be negative"},
		{name: "zero body limit", args: []string{"--max-body=0", "https://example.com"}, want: "max-body must be positive"},
		{name: "zero encoded limit", args: []string{"--max-encoded-body=0", "https://example.com"}, want: "max-encoded-body must be positive"},
		{name: "negative encoded limit", args: []string{"--max-encoded-body=-1", "https://example.com"}, want: "max-encoded-body must be positive"},
		{name: "overflow encoded limit", args: []string{"--max-encoded-body=9223372036854775808", "https://example.com"}, want: "invalid value"},
		{name: "invalid color", args: []string{"--color=rainbow", "https://example.com"}, want: "color must be auto, always, or never"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := cli.Run(tc.args, &stdout, &stderr, "dev")
			if code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want to contain %q", stderr.String(), tc.want)
			}
		})
	}
}

func TestFetchSummary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "page")
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{server.URL}, &stdout, &stderr, "dev")
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d, stderr=%q; want a successful fetch", code, stderr.String())
	}
	for _, want := range []string{server.URL, "HTTP status: 404", "Body: 4 bytes", "No technologies detected."} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout=%q, want to contain %q", stdout.String(), want)
		}
	}
}

func TestFetchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "too large")
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"--max-body=1", server.URL}, &stdout, &stderr, "dev")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "response body limit exceeded") {
		t.Errorf("stderr = %q, want a body limit error", stderr.String())
	}
}
