package cli_test

import (
	"bytes"
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

func TestScanningIsExplicitlyUnavailable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"https://example.com"}, &stdout, &stderr, "dev")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "scanning is not implemented yet") {
		t.Errorf("stderr = %q, want an explicit unavailable message", stderr.String())
	}
}
