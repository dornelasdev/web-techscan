# webscan

A small Go CLI for identifying the likely web stack behind a single URL.
Planned coverage starts with web frameworks, web servers, and supported
programming-language inferences, with evidence attached to every finding.

## Current status

The foundation checkpoint provides CLI help, version output, and argument
handling. Scanning is not implemented yet; supplying a target returns an
explicit error without making network requests. `v0.1.0` is a planned release.

Requires Go 1.27 or newer. There are currently no external dependencies.

## Build and use

```sh
go build -o bin/webscan .
./bin/webscan --help
./bin/webscan --version
```

No arguments displays help. Options go before the target URL. Development
builds report `webscan dev`; a release version can be supplied at build time:

```sh
go build -ldflags "-X main.version=v0.1.0" -o bin/webscan .
```

Help and version output use stdout. Errors use stderr. Exit codes are `0` for
success, `1` for an execution failure (currently unavailable scanning), and
`2` for invalid arguments. URL validation arrives with HTTP fetching.

## Structure

`main.go` only connects process arguments, output streams, and the exit code
to `internal/cli`. Future sections add separate fetching, detection, and output
packages. Fingerprints will be data files embedded in the executable so adding
technology coverage does not require changes to the CLI.

The module is currently named `webscan` for local development. Once a remote
repository path is chosen, update the module declaration and internal imports
before publishing installation instructions.

## Development checks

The user runs tests and all Git commands. The current behavioral checks cover
help/version output, argument errors, output stream separation, and the
explicit unavailable-scan result:

```sh
go test ./...
```

Workflow instructions: [local-notes/agents.md](local-notes/agents.md).
See the [brief](local-notes/brief.md) and
[checkpoint plan](local-notes/structure.md) for scope and future sections.
