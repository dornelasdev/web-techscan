# web-techscan

A small Go CLI for identifying the likely web stack behind a single URL.
Coverage includes web frameworks, web servers, CMSs, CDN/edge providers,
load balancers, WAFs, and supported programming-language inferences,
with evidence attached to every finding.

## Current development build

The CLI retrieves a single page and matches its captured signals against a
small bundled fingerprint catalog. It prints findings, evidence, and
detected/inferred states, with terminal and JSON output. This
is a personal CLI built from local source, with an executable
named `webscan`. See the [release notes](CHANGELOG.md).

Requires Go 1.27 or newer. There are currently no external dependencies.
v0.2.0 is the latest released baseline. Development since that tag adds
Cloudflare and Amazon CloudFront header fingerprints plus AWS Application and
Classic Load Balancer cookie-pair fingerprints, an AWS WAF action-header rule,
Nuxt header/HTML fingerprints, Django cookie/HTML inference, and Rails paired
CSRF metadata inference, bringing coverage to eighteen technologies.
These additions are unreleased;
no new version is assigned. Collection remains limited to one final HTTP response.

## Supported technologies

List the actual catalog bundled in your build without fetching a website:

```sh
./bin/webscan --techs
./bin/webscan --techs --json
```

Terminal output groups technologies under Web servers, Frameworks, CMS, Languages,
CDN/edge, Load balancers, and WAFs,
with names sorted alphabetically (case-insensitive) within each category. The
list updates automatically when fingerprints are added and the binary is rebuilt.
It describes supported coverage, not findings: there are no detected/inferred
labels, and identification still depends on exposed signals.

`--techs` does not accept a URL, `--version`, or fetch-only options (`--timeout`,
`--max-redirects`, `--max-body`). Color options are accepted but the listing is
always plain. JSON returns catalog metadata, not the scan-report shape; see the
[catalog JSON contract](internal/output/README.md#technology-catalog-json).

| Category | Technologies | Signals |
| --- | --- | --- |
| Web servers | nginx, Apache HTTP Server, Microsoft IIS | Identifying Server header |
| Frameworks | Express, Next.js | Identifying X-Powered-By header; paired Next.js HTML markers also support an inference |
| Frameworks | Laravel | Paired default cookie names support an inference |
| Frameworks | Nuxt | Exact Nuxt X-Powered-By header; paired __NUXT_DATA__ script ID and /_nuxt/ script path support an inference |
| Frameworks | Django | Default CSRF cookie name plus matching hidden-input markup support an inference |
| Frameworks | Ruby on Rails | Paired CSRF meta tags support an inference |
| CMS | WordPress, Drupal, Joomla | Generator meta tags support an inference; Drupal's identifying X-Generator header supports detection |
| Languages | PHP | Identifying X-Powered-By header or inference from Laravel |
| CDN/edge | Cloudflare, Amazon CloudFront | Shaped CF-Ray header or identifying standalone CloudFront Via header, respectively |
| Load balancers | AWS Application Load Balancer, AWS Classic Load Balancer | AWSALB + AWSALBCORS or AWSELB + AWSELBCORS cookie-name pairs, respectively; inferred |
| WAFs | AWS WAF | X-Amzn-Waf-Action header with exact challenge or captcha value; detected |

This is a limited starting set. Missing or customized signals can produce no
findings even when a supported technology is present. Header matches are
direct evidence, not proof; cookie and HTML heuristics stay inferred. The
initial catalog does not guess source languages from frontend assets or infer
languages from web-server implementations. See the
[coverage notes and official sources](internal/detect/fingerprints/SOURCES.md)
for each rule's rationale and limits. CMS rules deliberately start with generator
markers; removed/customized markers may be missed. No PHP inference is made from
these CMS markers alone, since artifacts may be copied, cached, or exported.

CDN/edge findings describe identifying response evidence, not a hidden origin,
cache hit, enabled WAF, load-balancer configuration, or network topology. The first
rules accept Cloudflare's 16-hex-digit Ray ID plus three-letter location suffix
and CloudFront's standalone `Via` value containing its host and product comment.
Other header forms (including comma-combined `Via` chains) can be missed. Generic
cache headers, status codes, and provider names in HTML do not produce findings.

Load-balancer rules require both exact, case-sensitive cookie names in the final
response. Names alone are indirect evidence, so findings remain inferred. Cookie
values are neither inspected nor reported, and cookies are not replayed. A single
cookie, a pair split across redirects, other stickiness modes, and installations
without these cookies are missed by this first batch. Findings do not establish
backend counts, live routing, hidden origins, WAF configuration, or topology.

AWS WAF detection requires its explicit action header (`challenge` or `captcha`,
lowercase, allowing outer spaces/tabs). Status codes, provider identity, cookie
names, and challenge text in HTML do not suffice. The header is matched regardless
of HTTP status; status and response scope are still reported separately. Allowed
traffic and ordinary blocks without this header may reveal no WAF evidence.
The CLI does not execute challenge scripts, solve CAPTCHAs, or retry to bypass them.

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
builds report `webscan dev`. When building the v0.2.0 source, its release version
can be supplied at build time (do not label newer development code as v0.2.0):

```sh
go build -buildvcs=false -ldflags "-X main.version=v0.2.0" -o bin/webscan .
./bin/webscan --version
```

The versioned build reports `webscan v0.2.0`. A Git tag alone does not change
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
with `--json`; `--techs --json` uses its separate catalog contract.

## Fetch behavior

- Supply an explicit `http://` or `https://` URL. Shorthand hostnames and URLs
  containing credentials are rejected. Fragments are removed before fetching.
- The default timeout is 15 seconds for the entire operation, including
  redirects and reading the response body. Override it with `--timeout`.
- Follow up to five redirects by default. `--max-redirects 0` rejects redirects;
  exceeding the configured limit is an error, rather than a truncated scan.
- Cross-origin redirects omit `Referer`: changing scheme, hostname, or effective
  port counts as a different origin. Same-origin redirects retain Go's normal
  referrer behavior, including query strings. No DNS lookup is used for this check.
- Request/redirect error messages omit raw URLs and `Location` values. Known
  failures retain category-specific reasons; unknown network/HTTP failures use
  a generic diagnostic. Successful reports still retain URL query strings.
- Read at most 2 MiB of response body by default. `--max-body` sets a positive
  decoded-byte limit, including for chunked and gzip bodies.
- Requests advertise gzip. Final response bodies support no encoding, a single
  `identity`, or a single `gzip` value. Unsupported encodings (such as Brotli or
  deflate), repeated encoding fields, and encoding lists fail explicitly; no
  fallback request is made. Encoding metadata on bodyless 204/304 responses is
  not decoded. Redirect bodies are not detection inputs.
- Incomplete/corrupt bodies, decoding failures, cancellation, and exceeded limits
  fail without a partial scan report. Body errors use safe summaries while keeping
  their underlying causes available internally.
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
go test ./...
```

Add `-v` for individual test output. Optional race and coverage checks:

```sh
go test -race ./...
go test -coverprofile=bin/coverage.out ./...
go tool cover -html=bin/coverage.out
```

Run the build command above first to create `bin/` for the coverage output.
The race detector requires a supported platform and a C compiler.
Body regressions cover decoded-size boundaries, gzip integrity and concatenated
members, unsupported/ambiguous encodings, malformed chunking, active cancellation,
and a shared deadline across redirects and body reading. CLI checks assert empty
stdout on failure in both formats; successful gzip reports use decoded byte counts.
The fixture integration checks exercise both output formats, detected/inferred
state handling, redirect isolation, and the absence of asset/link fetching.
The synthetic mixed-stack fixture also combines application, CDN, load-balancer,
and WAF signals to check evidence preservation, duplicate signals, misleading
near-matches, challenge/error responses, and body-limit failures without partial
results. This combination is a regression fixture, not a claim about a real
site's network topology; no challenge forms are submitted.
Dedicated server checks cover nginx, Apache, and IIS banner boundaries, repeated
header fields, wrong-source decoys, response scope, and both output formats.
Combined checks exercise every subset of the Nuxt/Django/Rails paired signals
against valid and malformed banners for all three servers. The mixed-stack CLI
fixture also checks these frameworks alongside existing application and
infrastructure findings, including independent state upgrades and language evidence.
Server fingerprints accept conservative banner shapes; see the
[supported forms and custom-banner limits](internal/detect/fingerprints/SOURCES.md#server-banner-hardening--2026-10-07).

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
only their URLs in the HTML are inspected.

The same fixture server also provides `wordpress.html`, `drupal.html`, and
`joomla.html`. For example:

```sh
./bin/webscan --no-color http://127.0.0.1:8000/wordpress.html
./bin/webscan --json http://127.0.0.1:8000/drupal.html
```

Each CMS fixture should produce only its own **inferred** CMS finding, without
PHP. The Drupal fixture server does not send the identifying `X-Generator`
header, so it exercises HTML inference rather than direct detection.
The `nuxt-payload.html` fixture in the same directory can also be inspected:

```sh
./bin/webscan --no-color http://127.0.0.1:8000/nuxt-payload.html
./bin/webscan --json http://127.0.0.1:8000/nuxt-payload.html
```

Keep the fixture server running for these commands. Expect only Nuxt as
**inferred**, with two HTML signals; the Python server does not send Nuxt's
identifying header. No linked scripts, stylesheets, or pages are fetched.
The `rails-csrf.html` fixture should likewise report only inferred Ruby on Rails:

```sh
./bin/webscan --no-color http://127.0.0.1:8000/rails-csrf.html
./bin/webscan --json http://127.0.0.1:8000/rails-csrf.html
```

The `django-csrf.html` fixture alone will not identify Django with this Python
server: its rule also needs a `csrftoken` cookie set by the same response.
The automated Django and mixed-stack CLI checks supply that cookie locally.
Stop the Python server with Ctrl-C when finished.

## Limitations and future scope

- The CLI inspects one final HTTP response, not the whole site's stack. HTTP error
  pages and intermediaries can expose different technologies from the application.
- External CSS/JS contents are not downloaded. JavaScript is not executed, so
  runtime variables, dynamically added DOM content, and browser-triggered
  requests are unavailable. There is no crawling, path guessing, or port scanning.
- HTML rules use raw-text patterns, not a DOM parser. Copied markup or comments
  can resemble real signals; missing signals do not establish absence.
- Nuxt HTML coverage requires the single-app JSON-payload script ID and a default
  `/_nuxt/` script path together. Legacy inline payloads, multi-app/custom markers,
  or renamed asset directories can be missed without the identifying header.
- The development catalog contains eighteen technologies. No version extraction, confidence
  percentages, or automatic fingerprint updates are included.
- Reports retain URL query strings, which may contain sensitive data. Review
  reports before sharing them even though raw bodies and cookie values are omitted.
- This is a local CLI for targets you choose, not a sandboxed fetch service for
  untrusted URLs. It can reach local/private addresses and follow redirects to
  other hosts; do not expose it as a public URL-processing endpoint as-is.

Possible later increments include more infrastructure fingerprints from exposed
response signals (additional CDN/edge, load-balancer, and WAF coverage), broader curated
coverage, bounded asset inspection, and an optional browser-backed mode. These
are directions, not implemented features or a promise of Wappalyzer coverage parity.
Go and the CLI interface do not impose the current collection limits.
