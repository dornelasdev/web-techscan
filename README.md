# web-techscan

A small Go CLI for identifying the likely web stack behind a single URL.
Coverage starts with web frameworks, web servers, and supported
programming-language inferences, with evidence attached to every finding.

## v0.1.0

The CLI retrieves a single page and matches its captured signals against a
small bundled fingerprint catalog. It prints findings, evidence, and
detected/inferred states, with terminal and JSON output. This first version
is a personal CLI built from local source, with an executable
named `webscan`. See the [release notes](CHANGELOG.md).

Requires Go 1.27 or newer. There are currently no external dependencies.

## Initial coverage

| Category | Technologies | Signals |
| --- | --- | --- |
| Web servers | nginx, Apache HTTP Server, Microsoft IIS | Identifying Server header |
| Frameworks | Express, Next.js | Identifying X-Powered-By header; paired Next.js HTML markers also support an inference |
| Frameworks | Laravel | Paired default cookie names support an inference |
| Languages | PHP | Identifying X-Powered-By header or inference from Laravel |

This is a limited starting set. Missing or customized signals can produce no
findings even when a supported technology is present. Header matches are
direct evidence, not proof; cookie and HTML heuristics stay inferred. The
initial catalog does not guess source languages from frontend assets or infer
languages from web-server implementations. See the
[coverage notes and official sources](internal/detect/fingerprints/SOURCES.md)
for each rule's rationale and limits.

## Build and use

Clone the repository or download and extract its source archive, then open a
terminal in the project root (the directory containing `go.mod`). With Go
installed, build and run:

```sh
go build -buildvcs=false -o bin/webscan .
./bin/webscan --help
./bin/webscan --version
./bin/webscan https://example.com
./bin/webscan --no-color https://example.com
./bin/webscan --json https://example.com
./bin/webscan --timeout 10s --max-redirects 3 --max-body 1048576 https://example.com
```

No arguments displays help. Options go before the target URL. Development
builds report `webscan dev`; a release version can be supplied at build time:

```sh
go build -buildvcs=false -ldflags "-X main.version=v0.1.0" -o bin/webscan .
./bin/webscan --version
```

The versioned build reports `webscan v0.1.0`. A Git tag alone does not change
the binary's version string; without the build flag it remains `webscan dev`.

These commands build from local source and disable automatic VCS metadata
collection. Setting the version string does not create a release or Git tag.
No GitHub connection is required by the build itself; the required Go toolchain
must already be available for an offline build. Remote `go install` support is
deferred, not a requirement for using this version.

The resulting binary runs without Go installed on a compatible OS/architecture.
You can run it by its full path, or place it in a directory on your `PATH` to use
`webscan` from anywhere. The examples below assume you remain in the project root.
To update, obtain the newer source and repeat the build command; there is no
automatic updater or prebuilt-binary distribution workflow at this stage.

Help and version output use stdout. Errors use stderr. Exit codes are `0` for
success, `1` for an execution failure, and `2` for invalid arguments. An HTTP
error status such as 404 still counts as a successful fetch: its response may
contain useful technology signals. Network failures and exceeded limits do not
produce partial results.

## Output

Terminal findings use green `✓` for detected and yellow `?` for inferred,
with a legend and evidence beneath each finding. Symbols remain when color
is disabled. For example, a response with nginx's header and Laravel's paired
cookie names could show:

```text
? Laravel [framework]
  - laravel_session and XSRF-TOKEN cookie names suggest Laravel
✓ nginx [web server]
  - Server header reports nginx; this may be an intermediary
? PHP [language]
  - Inferred from Laravel

✓ Detected  ? Inferred
```

`--color auto` is the default. Pipes and regular files receive plain output;
automatic color uses a dependency-free character-device check. Set
`--color always` or `--color never` to override that heuristic. Nonempty
`NO_COLOR` or `TERM=dumb` disables automatic color; explicit `--color always`
overrides those environment settings. `--no-color` always disables color,
regardless of flag order.

`--json` prints one indented JSON report with a trailing newline, and always
ignores color. Reports include URLs, HTTP status, response scope, redirect
metadata, body size, catalog size, findings, and evidence. Empty results use
`"findings": []`. Response bodies, header values, and cookie values are excluded.
The report's `schema_version` is separate from the fingerprint file format.
See the [JSON contract](internal/output/README.md) for fields and semantics.

Fetch/configuration errors leave stdout empty and report the error on stderr.
Output-write failures also return a nonzero exit code, but may leave a partial
report at the destination. Help and version requests remain plain text even
with `--json`; the JSON contract applies to scan results.

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
retrieval, returning a snapshot for offline inspection. `internal/detect`
loads and validates JSON fingerprints, compiles patterns once, and matches
headers, cookie names, and HTML without network access. Fingerprints are
embedded in the executable so adding technology coverage does not require
changes to the CLI. `internal/output` builds the public report representation
and renders either terminal text or JSON independently of detection.

Findings carry `detected` or `inferred` states and rule evidence. Supported
technology relationships can infer additional findings, with their source
recorded. Direct detections are never downgraded by inference. Invalid rules
or cyclic relationships fail catalog loading. See the
[fingerprint format](internal/detect/fingerprints/README.md) for authoring details.

Detection inspects the final response only, which may be a proxy or an error
page. It does not establish the stack of a hidden origin server. There are no
confidence percentages.

The module remains named `webscan`, with the executable entry point at the
root. This supports the local-source build workflow. A public module path and
remote installation can be added later without changing the current CLI scope.

## Development checks

The behavioral checks cover
help/version output, argument errors, output stream separation, and fetching
against local HTTP servers. Fetch checks cover redirects, response isolation,
body/header limits, timeouts, cancellation, incomplete bodies, and untrusted
TLS certificates. Detection checks use synthetic rules for positive and near-miss
signals, required signal combinations, inference chains, stable evidence,
and catalog validation. Bundled rules have positive and near-miss cases;
CLI fixtures cover mixed stacks, HTML filtering, error pages, and redirect
isolation. Output checks cover the JSON contract, color policy, empty results,
inference evidence, clean output streams, and write failures. No live
third-party websites are needed:

```sh
go test -v ./...
```

Optional race and coverage checks:

```sh
go test -race ./...
go test -coverprofile=bin/coverage.out ./...
go tool cover -html=bin/coverage.out
```

Run the build command above first to create `bin/` for the coverage output.
The race detector requires a supported platform and a C compiler.
The fixture integration checks exercise both output formats, detected/inferred
state handling, redirect isolation, and the absence of asset/link fetching.

### Local smoke check

No third-party website is required. From the repository root, serve the
synthetic fixtures in one terminal (requires Python 3):

```sh
python3 -m http.server 8000 --bind 127.0.0.1 --directory internal/detect/testdata/coverage
```

In another terminal, after building:

```sh
./bin/webscan --no-color http://127.0.0.1:8000/next-pages.html
./bin/webscan --json http://127.0.0.1:8000/next-cdn.html
```

Both should report only Next.js as **inferred**, with the paired HTML markers
as evidence. The JSON finding uses `id: "nextjs"` and `state: "inferred"`.
The different byte counts are expected. Referenced scripts do not need to exist:
only their URLs in the HTML are inspected. Stop the Python server with Ctrl-C.

## Limitations and future scope

- v0.1 inspects one final HTTP response, not the whole site's stack. HTTP error
  pages and intermediaries can expose different technologies from the application.
- External CSS/JS contents are not downloaded. JavaScript is not executed, so
  runtime variables, dynamically added DOM content, and browser-triggered
  requests are unavailable. There is no crawling, path guessing, or port scanning.
- HTML rules use raw-text patterns, not a DOM parser. Copied markup or comments
  can resemble real signals; missing signals do not establish absence.
- The catalog contains seven technologies. No version extraction, confidence
  percentages, or automatic fingerprint updates are included.
- Reports retain URL query strings, which may contain sensitive data. Review
  reports before sharing them even though raw bodies and cookie values are omitted.
- This is a local CLI for targets you choose, not a sandboxed fetch service for
  untrusted URLs. It can reach local/private addresses and follow redirects to
  other hosts; do not expose it as a public URL-processing endpoint as-is.

Possible later increments include broader curated fingerprints, bounded asset
inspection, and an optional browser-backed mode. These are directions, not
v0.1 features or a promise of Wappalyzer coverage parity. Go and the CLI interface
do not impose the current collection limits.
