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

The development catalog includes 19 technologies across web servers, frameworks,
UI frameworks, CMSs, languages, CDN/edge providers, load balancers, and WAFs.

Default scans inspect the final response. `--assets` also inspects bounded,
directly referenced same-origin JS/CSS. Asset rules currently cover Next.js
manifests and Bootstrap CSS.

There is no crawling, JavaScript execution, version extraction, bulk scanning,
or vulnerability testing. Findings describe exposed signals; intermediaries
and error pages can hide the application stack.

Latest release: **v0.2.0**. The development additions are unreleased.
See [CHANGELOG.md](CHANGELOG.md).

## Documentation

- [Usage](docs/usage.md): build, commands, flags, output, and development checks.
- [Policies](docs/policies.md): fetching, asset limits, redirects, and privacy.
- [Fingerprints](docs/fingerprints.md): supported rules, limitations, and sources.
- [Output contract](internal/output/README.md): scan and catalog JSON.
- [Fingerprint format](internal/detect/fingerprints/README.md): rule authoring.
