# Asset-reference extraction

This package is offline groundwork for optional bounded asset inspection. It is
not wired into the CLI yet: there is no `--assets` flag, asset downloading, or
asset-content fingerprint source in this checkpoint. Existing HTML fingerprints
and default scan/report behavior are unchanged.

## Parser and inputs

`Extract(finalURL, body, options)` takes the final page URL and UTF-8 HTML bytes.
The future caller must select an HTML response; this function does not infer
content type or decode legacy character encodings. Invalid URLs, invalid UTF-8,
exceeded input limits, and parser failures return no references and safe errors.

Use the Go project's [HTML5 tree parser](https://pkg.go.dev/golang.org/x/net/html)
from `golang.org/x/net v0.61.0` (BSD-3-Clause), pinned in `go.mod` and `go.sum`.
The HTML parser and its atom package do not require other external packages.
The full module declares dependencies for its other packages; they are not used
by this extraction code. The tree parser handles entity decoding, raw-text
elements, and malformed HTML tree construction. Existing fingerprint regexes
are not repurposed for extraction.

Parsing uses scripting-enabled tree construction solely to exclude noscript
fallback content. No script executes. Tree traversal also excludes template
and foreign-namespace subtrees (including HTML nested inside SVG/MathML), and
never interprets comments, script/style strings, textarea content or iframe
documents as new references. This is not a browser or a sanitizer for HTML reuse.

## Selection and resolution

- Select `script[src]` with absent/empty type, `module`, or the explicit
  `text/javascript`, `application/javascript`, `text/ecmascript`, and
  `application/ecmascript` types, case-insensitively. With no type, a nonempty
  legacy language must be `javascript` or `ecmascript`. Other types/aliases are
  excluded conservatively. Both module and nomodule declarations can be selected;
  extraction does not emulate browser feature support.
- Select `link[href]` whose ASCII-whitespace-separated rel tokens include
  `stylesheet`, with absent/empty type or `text/css`. Alternate/disabled/media
  stylesheets are static references too; media conditions are not evaluated.
- Do not select preload/modulepreload-only links, anchors, images, inline imports,
  data attributes, source maps, or guessed paths. File extensions are not required.
- Use the first non-inert HTML `base[href]` in parsed tree order, even if it occurs
  after a reference. Later bases cannot override it. An unusable first base makes
  relative references ineligible, rather than falling back to guessed URLs;
  independently valid absolute URLs can still qualify. A cross-origin base is
  used for resolution, then the resolved URL is subjected to origin checks.
- Resolve using Go's `net/url`; trim outer HTML ASCII whitespace and reject
  embedded tabs/newlines/form feeds, NULs, and literal backslashes in parsed URL
  values. This deliberately does not reproduce every browser URL repair rule.
- Reuse fetch URL validation: explicit resolved HTTP(S), no credentials, valid
  ports, no opaque URLs, and fragments removed. Only the final page's origin
  qualifies (scheme, case-insensitive hostname, effective port). No DNS, alias,
  IP-address or private-network inference. Same-origin local targets are valid.
- Skip empty/fragment-only references and normalized references to the final
  page itself. Keep queries exactly, including query-only references; later
  collection must verify successful response status and suitable content type.
- Deduplicate by URL regardless of declared kind, retaining the first declaration
  and its kind hint. Normalize hostname case, numeric/default ports and an empty
  path for the comparison key only. Preserve query order, empty query markers,
  and escaped path bytes. No percent-decoding or query sorting. The retained URL
  is the resolved URL, not the deduplication key.

## Limits and results

Defaults: at most 2 MiB of input HTML and five unique eligible references.
The parser owns the bounded input tree; the result and deduplication map are
limited to `MaxReferences`. The parser also enforces its own nesting limit.
Traversal is iterative. These are input/storage bounds, not a hard CPU deadline.

References are returned in parsed document order. `Truncated` means at least one
additional eligible distinct URL was not retained. `Skipped` counts ineligible
script-src/stylesheet-href declarations, not every unselected HTML node.
`Duplicates` counts repeat URLs among the retained candidates; extra URLs beyond
the cap are not stored merely to count their duplicates. No excluded URL/raw
attribute text is copied into diagnostics. An empty successful result has a
non-nil empty reference slice.

Reference URLs can still contain sensitive queries. Future reporting must apply
the existing report-redaction and terminal-sanitization policies to asset URLs.

## Next checkpoints (not implemented here)

1. Opt-in, sequential collection: five attempts including failures; no asset
   redirects or third-party origins; 512 KiB decoded/1 MiB encoded per asset,
   2 MiB decoded/4 MiB encoded combined, under the page-and-assets shared deadline.
   Preserve page results while marking incomplete asset inspection explicitly.
2. Asset-specific detection/evidence with reviewed initial JS/CSS fingerprints.
   Keep each asset separate; do not treat asset headers as the page server's
   identity or concatenate asset text into HTML.

User-run checks: `go test ./...`. Tests use inline offline fixtures, not live sites.
