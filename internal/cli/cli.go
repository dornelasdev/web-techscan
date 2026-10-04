// Package cli handles command-line arguments and coordinates the application.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

const usage = `Usage: webscan [options] <url>

Inspect the likely technology stack of a single website.
Scanning is not available in this foundation checkpoint.

Options:
  -h, --help  Show help
  --version   Show version

Place options before the URL.
`

// Run executes the CLI and returns a process exit code. It does not exit the
// process or use global output streams, so callers control its lifecycle.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	flags := flag.NewFlagSet("webscan", flag.ContinueOnError)
	// Handle parsing output ourselves so help goes to stdout and errors to stderr.
	flags.SetOutput(io.Discard)
	showVersion := flags.Bool("version", false, "Show version")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return exitOK
		}
		return usageError(stderr, err.Error())
	}

	if *showVersion {
		if flags.NArg() != 0 {
			return usageError(stderr, "--version does not accept a URL")
		}
		fmt.Fprintf(stdout, "webscan %s\n", version)
		return exitOK
	}

	switch flags.NArg() {
	case 0:
		fmt.Fprint(stdout, usage)
		return exitOK
	case 1:
		if flags.Arg(0) == "" {
			return usageError(stderr, "URL must not be empty")
		}
		fmt.Fprintln(stderr, "webscan: scanning is not implemented yet")
		return exitError
	default:
		return usageError(stderr, "expected a single URL; place options before the URL")
	}
}

func usageError(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "webscan: %s\nRun 'webscan --help' for usage.\n", message)
	return exitUsage
}
