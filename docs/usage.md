# Usage

[README](../README.md) · [Policies](policies.md) · [Fingerprints](fingerprints.md)

## Build

Requires Go 1.27 or newer. From the project root:

```sh
go build -buildvcs=false -o bin/webscan .
./bin/webscan --version
```

Default builds report `webscan dev`. To label a build of the v0.2.0 source:

```sh
go build -buildvcs=false -ldflags "-X main.version=v0.2.0" -o bin/webscan .
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
./bin/webscan --assets --redact-query --json https://example.com
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
| `--assets` | false | Inspect eligible same-origin JS/CSS. |
| `--redact-query` | false | Replace queries in report URLs. |
| `--color auto\|always\|never` | auto | Set terminal color behavior. |
| `--no-color` | false | Disable color, overriding `--color`. |
| `--timeout duration` | 15s | Set the shared page-and-assets network timeout. |
| `--max-redirects n` | 5 | Set the page redirect budget; 0 rejects redirects. |
| `--max-body bytes` | 2097152 | Set the page's decoded body limit. |
| `--max-encoded-body bytes` | 4194304 | Set the page body limit before decoding. |
| `--allow-http-downgrade` | false | Permit HTTPS-to-HTTP page redirects. |

Timeout and byte limits must be positive. Redirect count must be nonnegative.
Asset limits are fixed; the page body flags do not change them.
See [policies](policies.md) for exact scope and limits.

### Catalog mode

`--techs` lists the catalog bundled in the binary. Rebuild after changing rules.
Entries are grouped by category and sorted by name, case-insensitively.
Catalog entries have no scan state and do not guarantee identification.

`--techs` rejects a URL, `--version`, and explicitly supplied scan options:
`--timeout`, `--max-redirects`, `--max-body`, `--max-encoded-body`,
`--allow-http-downgrade`, `--assets`, and `--redact-query`.
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
stacks, JS/CSS isolation, optional failures, privacy, and output contracts.
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
| `rails-csrf.html` | Inferred Ruby on Rails. |
| `django-csrf.html` | No Django finding; the server supplies no csrftoken cookie. |

These page-only commands do not fetch linked assets. Referenced files need not
exist. Go integration tests supply controlled headers/cookies and exercise asset
inspection. Stop the Python server with Ctrl-C.
