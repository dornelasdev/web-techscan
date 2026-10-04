# webscan

A small Go CLI for identifying the likely web stack behind a single URL.
Planned coverage starts with web frameworks, web servers, and supported
programming-language inferences, with evidence attached to every finding.

## Current status

The fetching checkpoint retrieves a single page and reports its final URL,
HTTP status, redirect count, and body size. Technology detection is not yet
implemented. `v0.1.0` is a planned release.

Requires Go 1.27 or newer. There are currently no external dependencies.

## Build and use

```sh
go build -o bin/webscan .
./bin/webscan --help
./bin/webscan --version
./bin/webscan https://example.com
./bin/webscan --timeout 10s --max-redirects 3 --max-body 1048576 https://example.com
```

No arguments displays help. Options go before the target URL. Development
builds report `webscan dev`; a release version can be supplied at build time:

```sh
go build -ldflags "-X main.version=v0.1.0" -o bin/webscan .
```

Help and version output use stdout. Errors use stderr. Exit codes are `0` for
success, `1` for an execution failure, and `2` for invalid arguments. An HTTP
error status such as 404 still counts as a successful fetch: its response may
contain useful technology signals. Network failures and exceeded limits do not
produce partial results.

## Fetch behavior

- Supply an explicit `http://` or `https://` URL. Shorthand hostnames and URLs
  containing credentials are rejected. Fragments are removed before fetching.
- The default timeout is 15 seconds for the entire operation, including
  redirects and reading the response body. Override it with `--timeout`.
- Follow up to five redirects by default. `--max-redirects 0` rejects redirects;
  exceeding the configured limit is an error, rather than a truncated scan.
- Read at most 2 MiB of response body by default. `--max-body` sets a positive
  byte limit, including for chunked and transparently decompressed gzip bodies.
- Response headers are capped at 1 MiB per response. Normal TLS certificate
  verification and Go's standard environment proxy support remain enabled.
- Requests use GET and the `webscan` user agent. No assets or other pages are
  fetched beyond the redirect chain, and cookies are not replayed.
- The internal response snapshot stores final-page headers, cookie names,
  and body content. Cookie values in `Set-Cookie` are discarded; redirect
  metadata is separate from the final page's detection inputs.

## Structure

`main.go` only connects process arguments, output streams, and the exit code
to `internal/cli`. `internal/fetch` handles URL validation and bounded HTTP
retrieval, returning a snapshot for offline inspection. Future sections add
separate detection and output packages. Fingerprints will be data files
embedded in the executable so adding technology coverage does not require
changes to the CLI.

The module is currently named `webscan` for local development. Once a remote
repository path is chosen, update the module declaration and internal imports
before publishing installation instructions.

## Development checks

The user runs tests and all Git commands. The current behavioral checks cover
help/version output, argument errors, output stream separation, and fetching
against local HTTP servers. Fetch checks cover redirects, response isolation,
body/header limits, timeouts, cancellation, incomplete bodies, and untrusted
TLS certificates. No live third-party websites are needed:

```sh
go test ./...
```
