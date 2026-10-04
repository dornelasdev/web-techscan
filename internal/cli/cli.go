// Package cli handles command-line arguments and coordinates the application.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"webscan/internal/fetch"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

const usage = `Usage: webscan [options] <url>

Inspect the likely technology stack of a single website.
Fetch a page and show response metadata. Technology detection is not yet available.

Options:
  -h, --help           Show help
  --version           Show version
  --timeout duration  Total fetch timeout (default 15s)
  --max-redirects n    Maximum followed redirects (default 5; 0 disallows redirects)
  --max-body bytes    Maximum response body size (default 2097152)

Place options before the URL. Include http:// or https://.
`

// Run executes the CLI and returns a process exit code. It does not exit the
// process or use global output streams, so callers control its lifecycle.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	flags := flag.NewFlagSet("webscan", flag.ContinueOnError)
	// Handle parsing output ourselves so help goes to stdout and errors to stderr.
	flags.SetOutput(io.Discard)
	showVersion := flags.Bool("version", false, "Show version")
	options := fetch.DefaultOptions()
	flags.DurationVar(&options.Timeout, "timeout", options.Timeout, "Total fetch timeout")
	flags.IntVar(&options.MaxRedirects, "max-redirects", options.MaxRedirects, "Maximum followed redirects")
	flags.Int64Var(&options.MaxBodyBytes, "max-body", options.MaxBodyBytes, "Maximum response body size")

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
		return fetchPage(flags.Arg(0), options, stdout, stderr)
	default:
		return usageError(stderr, "expected a single URL; place options before the URL")
	}
}

func fetchPage(target string, options fetch.Options, stdout, stderr io.Writer) int {
	client, err := fetch.New(options)
	if err != nil {
		return usageError(stderr, err.Error())
	}
	defer client.CloseIdleConnections()
	snapshot, err := client.Fetch(context.Background(), target)
	if err != nil {
		if errors.Is(err, fetch.ErrInvalidURL) {
			return usageError(stderr, err.Error())
		}
		fmt.Fprintf(stderr, "webscan: %s\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "URL: %s\nHTTP status: %d\nRedirects: %d\nBody: %d bytes\n",
		snapshot.FinalURL, snapshot.StatusCode, len(snapshot.Redirects), len(snapshot.Body))
	fmt.Fprintln(stdout, "Technology detection is not yet available.")
	return exitOK
}

func usageError(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "webscan: %s\nRun 'webscan --help' for usage.\n", message)
	return exitUsage
}
