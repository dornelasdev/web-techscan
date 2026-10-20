# Usage

[README](../README.md) · [Policies](policies.md) · [Fingerprints](fingerprints.md)

## Build

Requires Go 1.27 or newer. From the project root:

```sh
go build -buildvcs=false -o bin/webscan .
./bin/webscan --version
```

Default builds report `webscan dev`. To label a build of the v0.3.0 source:

```sh
go build -buildvcs=false -ldflags "-X main.version=v0.3.0" -o bin/webscan .
```

Use that version label only for the matching release source. Tags do not set
the binary's version string. `-buildvcs=false` disables VCS metadata collection.

The build requires the Go toolchain and `golang.org/x/net v0.61.0`; both must
be available locally for an offline build. The binary runs without Go on a
compatible OS/architecture. Run it by path or place it on `PATH`.

To update, obtain newer source and rebuild. Remote `go install`, automatic
updates, and prebuilt distribution are not provided.

## Commands

```sh
./bin/webscan --help
./bin/webscan https://example.com
./bin/webscan --no-color https://example.com
./bin/webscan --json https://example.com
./bin/webscan --prefer-html https://example.com
./bin/webscan --assets --redact-query --json https://example.com
./bin/webscan --assets --asset-budget expanded --json https://example.com
./bin/webscan --timeout 10s --max-redirects 3 --max-body 1048576 https://example.com
./bin/webscan --redact-query --json 'https://example.com/page?token=secret'
./bin/webscan --techs
./bin/webscan --techs --json
```

Accept one explicit HTTP(S) URL. Put all options before it. No arguments shows
help. URLs containing credentials are rejected; fragments are removed.

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `-h`, `--help` | — | Show help. |
| `--version` | — | Show the build version. |
| `--techs` | false | List bundled technologies without network access. |
| `--json` | false | Render a scan report or catalog as JSON. |
| `--prefer-html` | false | Prefer HTML for page requests, not assets. |
| `--assets` | false | Inspect eligible same-origin JS/CSS. |
| `--asset-budget standard\|expanded` | standard | Select asset payload limits; requires `--assets`. |
| `--redact-query` | false | Replace queries in report URLs. |
| `--color auto\|always\|never` | auto | Set terminal color behavior. |
| `--no-color` | false | Disable color, overriding `--color`. |
| `--timeout duration` | 15s | Set the shared page-and-assets network timeout. |
| `--max-redirects n` | 5 | Set the page redirect budget; 0 rejects redirects. |
| `--max-body bytes` | 2097152 | Set the page's decoded body limit. |
| `--max-encoded-body bytes` | 4194304 | Set the page body limit before decoding. |
| `--allow-http-downgrade` | false | Permit HTTPS-to-HTTP page redirects. |

Timeout and byte limits must be positive. Redirect count must be nonnegative.
Asset budgets are independent of page-body flags. Explicit `--asset-budget`
requires enabled `--assets` and cannot be used with `--version` or `--techs`.
Profile names are exact and case-sensitive; there is no unlimited/custom profile.
See [policies](policies.md) for exact scope and limits.

### HTML preference

`--prefer-html` sends an HTML-preferring Accept header on the supplied page and
followed page redirects. The default (or `--prefer-html=false`) omits Accept.
Assets keep their existing headers. See the [request policy](policies.md#page-fetching)
for the exact value.

This can expose HTML signals when a server otherwise selects JSON. It does not
execute JavaScript or guarantee HTML. Servers may ignore it or return HTTP 406;
the returned response is inspected normally, without a fallback request.
Findings describe that selected representation, not all representations of a URL.

### Catalog mode

`--techs` lists the catalog bundled in the binary. Rebuild after changing rules.
Terminal entries use group → category → technology, with names sorted
case-insensitively within each category:

| Group | Categories |
| --- | --- |
| Web development | Web frameworks, JavaScript frameworks, JavaScript libraries, UI frameworks, CMS, languages. |
| Infrastructure | Web servers, CDN/edge, load balancers, WAFs. |

Angular, React, and Vue use `javascript_framework`. ASP.NET Core, Django, Express,
Fiber, Laravel, Next.js, Nuxt, Rails, and Spring Boot use `framework` (web frameworks,
including full-stack frameworks). Groups are static organization, not additional detections.
jQuery uses `javascript_library`; its content rule requires `--assets`.
Catalog JSON remains a flat array with `id`, `name`, and `category`; no `group`
field is added. Use technology IDs for automation, not category assignments.

Catalog entries have no scan state and do not guarantee identification.
Python and Ruby are inference-only entries; scans require a Django or Rails
finding, respectively. Listing them does not mean they have direct language rules.

`--techs` rejects a URL, `--version`, and explicitly supplied scan options:
`--timeout`, `--max-redirects`, `--max-body`, `--max-encoded-body`,
`--allow-http-downgrade`, `--prefer-html`, `--assets`, `--asset-budget`, and `--redact-query`.
Explicit false values are also rejected. Color options are accepted; catalog
output always remains plain.

## Output

Terminal findings include a state marker, technology, category, and evidence:

```text
? Laravel [framework]
  - laravel_session and XSRF-TOKEN cookie names suggest Laravel
✓ nginx [web server]
  - Server header reports nginx; this may be an intermediary
? PHP [language]
  - Inferred from Laravel

✓ Detected  ? Inferred
```

`--json` writes one indented document with a trailing newline and no ANSI color.
Scans and catalogs have separate schema-1 contracts. Empty results use arrays,
including `"findings": []`. Scan JSON includes response metadata, redirects,
findings, evidence, and optional asset metadata.

See the [output contract](../internal/output/README.md) for field definitions.
See [privacy](policies.md#privacy) for URL handling and display sanitization.

### Color

- `auto`: character-device check; pipes and files receive plain output.
- Nonempty `NO_COLOR` or `TERM=dumb` disables automatic color.
- `always` overrides those environment settings; `never` disables color.
- `--no-color` takes precedence regardless of flag order.
- JSON, help, version, and catalog output are plain.

### Exit codes and streams

| Code | Meaning |
| --- | --- |
| 0 | Successful scan, help, version, or catalog listing. |
| 1 | Fetching, catalog loading, or output failure. |
| 2 | Invalid arguments. |

Reports, help, and version go to stdout. Errors go to stderr.
HTTP error statuses such as 403/404 remain inspectable responses. No findings
is a successful result. Page failures leave stdout empty; output-write failures
may leave partial output. Optional asset failures preserve page results and exit
0; check the asset status and items to assess collection completeness.

## Development checks

Run from the project root:

```sh
go test ./...
```

Tests use synthetic fixtures and local servers. They cover fetch boundaries,
rule validation, positive/near-miss detections, inference, redirects, mixed
frontend/network stacks, JS/CSS isolation, optional failures, privacy, and output
contracts. Combined frontend checks include Angular HTML/JS and React
client/ReactDOM evidence, split indicators and oversized captures.
jQuery checks include core-indicator pairs, plugin-style decoys, source isolation,
gzip, incomplete/oversized captures and evidence URL redaction.
Passing fixtures are not a measurement of real-world detection accuracy.

Optional checks, after building to create `bin/`:

```sh
go test -v ./...
go test -race ./...
go test -coverprofile=bin/coverage.out ./...
go tool cover -html=bin/coverage.out
```

The race detector requires a supported platform and a C compiler.

### Local smoke check

Serve the synthetic HTML fixtures in one terminal:

```sh
python3 -m http.server 8000 --bind 127.0.0.1 --directory internal/detect/testdata/coverage
```

After building, run in another terminal:

```sh
./bin/webscan --no-color http://127.0.0.1:8000/next-pages.html
./bin/webscan --json http://127.0.0.1:8000/next-cdn.html
```

| Fixture | Expected finding with the Python server |
| --- | --- |
| `next-pages.html`, `next-cdn.html` | Inferred Next.js. |
| `wordpress.html` | Inferred WordPress, without PHP. |
| `drupal.html` | Inferred Drupal; the server supplies no X-Generator header. |
| `joomla.html` | Inferred Joomla, without PHP. |
| `nuxt-payload.html` | Inferred Nuxt. |
| `rails-csrf.html` | Inferred Ruby on Rails and Ruby. |
| `django-csrf.html` | No Django or Python finding; the server supplies no csrftoken cookie. |
| `aspnet-core-antiforgery.html` | No ASP.NET Core finding; the server supplies no antiforgery cookie. |
| `tomcat-error.html` | No Tomcat finding: the Python server returns this file with HTTP 200, not an error status. |
| `spring-boot-servlet-error.html`, `spring-boot-reactive-error.html` | No Spring Boot finding: these files are returned with HTTP 200. |

These page-only commands do not fetch linked assets. Referenced files need not
exist. Go integration tests supply controlled headers/cookies and exercise asset
inspection. Stop the Python server with Ctrl-C.
