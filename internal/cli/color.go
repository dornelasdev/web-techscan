package cli

import (
	"io"
	"os"
)

type outputOptions struct {
	json        bool
	color       string
	noColor     bool
	redactQuery bool
}

func useColor(options outputOptions, stdout io.Writer) bool {
	if options.noColor || options.color == "never" {
		return false
	}
	if options.color == "always" {
		return true
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	// A portable, dependency-free heuristic: pipes and regular files are plain.
	// --color explicitly overrides this when a terminal is not recognized.
	file, ok := stdout.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
