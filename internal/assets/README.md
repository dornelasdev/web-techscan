# Bounded asset collection

`Extract` is offline reference discovery. `Collect` connects it to opt-in
`--assets` collection, preserving each captured body separately. The CLI passes
accepted captures to the offline detector's separate JS/CSS inputs. Initial
content fingerprints cover Next.js manifests; default page-only scans are unchanged.

## Parser and inputs

`Extract(finalURL, body, options)` takes the final page URL and UTF-8 HTML bytes.
The caller must select an HTML response; this function does not infer
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

Reference URLs can still contain sensitive queries. Reporting applies existing
query-redaction and terminal-sanitization policies to all asset URLs.

## Collection policy

`Collect` takes a final-page snapshot and the same context/deadline used for its
fetch. The CLI starts that context before requesting the page. Sequential asset
requests never reset the deadline; no requests start after observed cancellation
or aggregate exhaustion. Parsing is input-bounded, not forcibly preempted.

Page selection requires `text/html`, with absent charset, UTF-8 or US-ASCII,
and valid UTF-8 bytes. An absent/empty Content-Type uses Go's bounded sniffing;
ambiguous/repeated Content-Type is rejected. XHTML and legacy declared charsets
are skipped rather than interpreted with HTML5 semantics/transcoded. In-document
encoding declarations are not browser-emulated. The fixed 2 MiB extractor cap
still applies even if the page fetch limit is increased. HTTP error pages remain
eligible HTML, with their existing page response scope.

At most five selected URLs are attempted, including failures. There is no retry
loop, cookie jar, authentication, Referer, recursive discovery or script execution.
Go's transport retains its standard connection handling. Asset redirects are
never followed, even same-origin redirects or when page downgrade opt-in is set.
Normal TLS and proxy behavior remain unchanged; same-origin private/local targets
are allowed, just like page fetching. This is not a public untrusted-URL service.

The fetch layer rejects non-2xx, 206 and Content-Range responses before reading
their bodies. It requires exactly one valid Content-Type: `text/css` for styles,
or `text/javascript`, `application/javascript`, `text/ecmascript`, or
`application/ecmascript` for scripts. MIME parameters are parsed, but collection
does not transcode or interpret asset contents. No MIME sniffing or file-extension
fallback. Successful bodyless responses can yield empty captures. Missing or
unsupported MIME, unsupported content encoding, corruption and truncation are
reported, not silently treated as successful captures. Bodies are always closed.

Per asset: 512 KiB decoded / 1 MiB encoded, plus at most one overflow probe in
each dimension. Combined: 2 MiB decoded / 4 MiB encoded, **including** failed
reads/probes. Before each request, the body limits are clamped to the remaining
aggregate budget minus one reserved probe byte. Remaining budgets of one byte
or less stop further requests. This conservative boundary policy can reject an
asset that exactly fills the aggregate budget. Counts describe payload reads,
not headers, HTTP framing, TLS or transport buffering. Gzip input accounting
starts before the header parser, including read-ahead and empty members.

Only completely accepted bodies enter `Captures`; failure accounting survives
discarding partial bodies. Captures are not serialized. Item statuses are
`collected`, `failed` (attempted), or `skipped` (not attempted). Collection is
`incomplete` if selection truncates or any selected item fails/is skipped;
`skipped` means the whole pass could not begin; otherwise `complete` means only
the bounded eligible scope. Off-origin/ineligible declarations are counted,
not coverage failures. Zero eligible assets can be complete. Page findings
survive all optional failures; JSON/terminal metadata makes limitations explicit.

## Offline detection handoff

Only `Captures` (complete, accepted bodies) reach the detector. Collection failures
never supply partial bodies; previously captured assets remain usable. JS/CSS kinds
map to separate matcher sources. Asset headers never identify the page server,
and bodies are never concatenated with each other or HTML. Rules cannot combine
markers across files. No character transcoding, JS/CSS parsing or execution is
introduced; raw text can include copied/commented examples.

The first two production rules infer Next.js from paired build/SSG manifest
markers. CSS is collected but has no production fingerprint yet. Evidence retains
each matched asset URL, subject to report redaction and display sanitization.
See [rule rationale and sources](../detect/fingerprints/SOURCES.md#nextjs-asset-manifests--reviewed-2026-10-10).

User-run checks: `go test ./...`. Tests use inline fixtures and local servers,
not live third-party sites.
