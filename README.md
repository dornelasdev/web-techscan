# web-techscan

A Go CLI that identifies likely web technologies from a single URL.
The executable is named `webscan`.

## Build

Requires Go 1.27 or newer.

```sh
go build -buildvcs=false -o bin/webscan .
```

Build from the project root. See [build and update instructions](docs/usage.md#build).

## Use

```sh
./bin/webscan https://example.com
./bin/webscan --json https://example.com
./bin/webscan --assets --redact-query https://example.com
./bin/webscan --techs
```

Place options before the URL. Include `http://` or `https://`.

## Findings

| State | Marker | Meaning |
| --- | --- | --- |
| `detected` | Green `✓` | A distinctive observed signal matches a rule. |
| `inferred` | Yellow `?` | An indirect signal or supported relationship matches a rule. |

Each finding includes evidence. States are not confidence percentages or
guarantees. Missing findings do not establish that a technology is absent.

## Coverage

The development catalog includes 28 technologies across ten categories:
web frameworks, JavaScript frameworks, JavaScript libraries, UI frameworks, CMSs,
languages, web servers, CDN/edge providers, load balancers, and WAFs.
`--techs` organizes these under Web development and Infrastructure.
Python and Ruby are inferred from Django and Rails findings, respectively;
they are not independent language detections.

Default scans inspect the final response. `--assets` also inspects bounded,
directly referenced same-origin JS/CSS. Asset rules currently cover Next.js
manifests, React client/ReactDOM runtime markers, Vue 3-shaped renderer markers,
Angular component-runtime markers, jQuery core-runtime indicators, and Bootstrap CSS.

There is no crawling, JavaScript execution, version extraction, bulk scanning,
or vulnerability testing. Findings describe exposed signals; intermediaries
and error pages can hide the application stack.

Release baseline: **v0.3.0**. Development additions are unreleased.
See [CHANGELOG.md](CHANGELOG.md).

## Documentation

- [Usage](docs/usage.md): build, commands, flags, output, and development checks.
- [Policies](docs/policies.md): fetching, asset limits, redirects, and privacy.
- [Fingerprints](docs/fingerprints.md): supported rules, limitations, and sources.
- [Output contract](internal/output/README.md): scan and catalog JSON.
- [Fingerprint format](internal/detect/fingerprints/README.md): rule authoring.
