// Package cli handles command-line arguments and coordinates the application.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net/http"

	"webscan/internal/detect"
	"webscan/internal/fetch"
	"webscan/internal/output"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

const usage = `Usage: webscan [options] <url>

Inspect the likely technology stack of a single website.
Fetch a page and match its signals against the bundled fingerprint catalog.

Options:
  -h, --help           Show help
  --version           Show version
  --json              Print a JSON scan report
  --color mode        Color: auto, always, never (default auto)
  --no-color          Disable color, overriding --color
  --timeout duration  Total fetch timeout (default 15s)
  --max-redirects n    Maximum followed redirects (default 5; 0 disallows redirects)
  --max-body bytes     Maximum response body size (default 2097152)

Place options before the URL. Include http:// or https://.
`

// Run executes the CLI and returns a process exit code. It does not exit the
// process or use global output streams, so callers control its lifecycle.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	flags := flag.NewFlagSet("webscan", flag.ContinueOnError)
	// Handle parsing output ourselves so help goes to stdout and errors to stderr.
	flags.SetOutput(io.Discard)
	showVersion := flags.Bool("version", false, "Show version")
	presentation := outputOptions{}
	flags.BoolVar(&presentation.json, "json", false, "Print a JSON scan report")
	flags.StringVar(&presentation.color, "color", "auto", "Color: auto, always, never")
	flags.BoolVar(&presentation.noColor, "no-color", false, "Disable color")
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

	if presentation.color != "auto" && presentation.color != "always" && presentation.color != "never" {
		return usageError(stderr, "color must be auto, always, or never")
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
		return fetchPage(flags.Arg(0), options, presentation, stdout, stderr)
	default:
		return usageError(stderr, "expected a single URL; place options before the URL")
	}
}

func fetchPage(target string, options fetch.Options, presentation outputOptions, stdout, stderr io.Writer) int {
	client, err := fetch.New(options)
	if err != nil {
		return usageError(stderr, err.Error())
	}
	defer client.CloseIdleConnections()
	engine, err := detect.LoadBundled()
	if err != nil {
		fmt.Fprintf(stderr, "webscan: load fingerprints: %s\n", err)
		return exitError
	}
	snapshot, err := client.Fetch(context.Background(), target)
	if err != nil {
		if errors.Is(err, fetch.ErrInvalidURL) {
			return usageError(stderr, err.Error())
		}
		fmt.Fprintf(stderr, "webscan: %s\n", err)
		return exitError
	}
	findings := engine.Detect(detect.Input{
		Headers:     snapshot.Headers,
		CookieNames: snapshot.CookieNames,
		HTML:        htmlForDetection(snapshot.Headers, snapshot.Body),
	})
	report := output.NewReport(*snapshot, findings, engine.Len())
	if presentation.json {
		err = output.JSON(stdout, report)
	} else {
		err = output.Terminal(stdout, report, useColor(presentation, stdout))
	}
	if err != nil {
		fmt.Fprintf(stderr, "webscan: write report: %s\n", err)
		return exitError
	}
	return exitOK
}

func htmlForDetection(headers http.Header, body []byte) []byte {
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(body)
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err == nil && (mediaType == "text/html" || mediaType == "application/xhtml+xml") {
		return body
	}
	return nil
}

func usageError(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "webscan: %s\nRun 'webscan --help' for usage.\n", message)
	return exitUsage
}
