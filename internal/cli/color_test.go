package cli

import (
	"bytes"
	"os"
	"testing"
)

func TestColorPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, mode, noColorEnv, term string
		noColor, want                bool
	}{
		{"buffer auto", "auto", "", "xterm", false, false},
		{"forced color", "always", "", "xterm", false, true},
		{"never", "never", "", "xterm", false, false},
		{"explicit disable wins", "always", "", "xterm", true, false},
		{"explicit force overrides environment", "always", "1", "dumb", false, true},
		{"environment opt out", "auto", "1", "xterm", false, false},
		{"dumb terminal", "auto", "", "dumb", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", tc.noColorEnv)
			t.Setenv("TERM", tc.term)
			var stdout bytes.Buffer
			if got := useColor(outputOptions{color: tc.mode, noColor: tc.noColor}, &stdout); got != tc.want {
				t.Errorf("color=%t, want %t", got, tc.want)
			}
		})
	}
}

func TestAutoColorForFileAndEnvironment(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm")
	file, err := os.CreateTemp(t.TempDir(), "report")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if useColor(outputOptions{color: "auto"}, file) {
		t.Error("regular file should not receive automatic color")
	}
	device, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	t.Setenv("NO_COLOR", "1")
	if useColor(outputOptions{color: "auto"}, device) {
		t.Error("NO_COLOR must disable automatic color even for a character device")
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if useColor(outputOptions{color: "auto"}, device) {
		t.Error("TERM=dumb must disable automatic color")
	}
}
