# Bounded asset collection

`Extract` discovers references and inline CSS offline. `Collect` connects it to opt-in
`--assets` collection, preserving each captured body separately. The CLI passes
accepted captures to the offline detector's separate JS/CSS inputs. Current
content fingerprints cover Next.js manifests, React client/ReactDOM, Vue and
Angular runtime markers, jQuery core indicators, Radix UI style mappings,
Bootstrap CSS and Tailwind CSS.
See [user policies](../../docs/policies.md#asset-inspection) for scan scope and limits.

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
  ports, no opaque URLs, and fragments removed. The final page's origin qualifies
  by default (scheme, case-insensitive hostname, effective port). Options may
  explicitly allow additional exact origins; see below. No DNS, alias,
  IP-address or private-network inference. Local targets remain valid.
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

`ExternalOrigins` summarizes otherwise valid direct script/stylesheet declarations
excluded by the origin check. Keep the first 20 distinct origins in parsed order,
with separate script/stylesheet declaration counts. Repeated URLs count again;
these are not unique-file counts. Normalize hostname case and numeric/default
ports using the existing URL comparison key. Retain only scheme, host and
non-default port, never credentials, paths, queries or fragments. No ownership,
CDN identity, browser execution or technology finding is implied.

Origin summaries reuse declaration, base, URL and inert-subtree policies; invalid
references, unsupported types and preload-only links do not contribute. Discovery
continues beyond the five retained fetch candidates. Its map/slice are capped
independently at 20; `ExternalOriginsTruncated` means another origin was omitted.
Later declarations for retained origins still increment their counts. An empty
successful extraction has an empty origin slice. Discovery performs no I/O.

`Options.AllowedOrigins` adds exact HTTP(S) origins via `NormalizeOrigins`.
Accept at most 20 distinct origins in input order; normalize hostname case and
numeric/default ports and deduplicate with `fetch.SameOrigin`. Reject credentials,
paths other than empty or `/`, escaped paths, queries/fragments including empty
delimiters, wildcards, backslashes, controls, whitespace and invalid UTF-8.
Validation errors omit input. Invalid configuration yields no extraction result.
Matching reuses `fetch.SameOrigin`, not suffix, IP/DNS or ownership comparisons.
HTTPS final pages cannot select HTTP assets, regardless of configured origins or
page downgrade settings. Such declarations still enter skipped-origin metadata.
Allowed references otherwise share the same candidate order, deduplication and
five-reference cap; allowed origins are not automatically fetched or probed.

## Inline CSS extraction

The same non-inert tree walk collects actual `style` elements with absent/empty
type or `text/css` (outer ASCII whitespace/case variations accepted). No style
attributes, JS strings, fake elements in comments, foreign/template/noscript or
iframe content. Media conditions and CSS syntax are not interpreted. Use parsed
text children without decoding CSS escapes or fetching imports. HTML parser text
handling applies; these are not source byte offsets or a rendered stylesheet.

`Result.InlineCSS` has independent local limits: the first 20 eligible element
slots, 512 KiB per parsed block and 1 MiB of retained CSS combined. Empty and
rejected blocks consume slots. Measure before copying; skip oversized/over-budget
blocks whole and allow smaller later blocks within the first 20 slots. Never keep
a rejected prefix. Beyond slot 20, count skipped blocks and set inline `Truncated`
without retaining more bodies/items. The fixed HTML input cap still bounds parsing.

`InlineStyle.Index` is one-based among eligible CSS elements in parsed order,
including empty/skipped blocks. `Blocks` holds accepted bodies only. `Items`
holds safe index/status/reason/full parsed size metadata for the first 20 slots.
`Seen` counts all eligible elements; `Collected` counts accepted blocks, `Skipped`
counts rejected blocks including those beyond the cap, and `Bytes` counts retained
CSS only. Complete includes an empty successful pass. Any local cap yields
`incomplete` with the first reason (`block_limit`, `block_byte_limit` or
`total_byte_limit`). No raw body is serialized.

Collection preserves inline data before asset requests. Whole-pass failures use
the same safe skip reason for inline inspection. Inline status/truncation are
independent of network status, attempt counts, encoded/decoded read usage,
origins, profile and deadline. Expanded profiles do not change inline limits.
Network failures cannot discard already accepted inline blocks. The CLI supplies
them as separate detector `InlineStyles`, never `AssetCSS` or synthetic URLs.

Reference URLs can still contain sensitive queries. Reporting applies existing
query-redaction and terminal-sanitization policies to all asset URLs.

## Collection policy

`Collect` retains the standard profile and same-origin scope. `BudgetForProfile` resolves exact
`standard`/`expanded` names to independent value copies; `CollectWithBudget`
accepts only an unchanged supported budget and rejects invalid configuration
before selection or I/O. `CollectWithOptions` accepts a supported `Budget` and
`AllowedOrigins`, validating both before selection/I/O. Existing collection APIs
retain same-origin defaults. Normalized configured origins are independently
copied into `Collection.AllowedOrigins`, even for empty/skipped passes; they are
scope metadata, not proof of requests. All collection paths take a final-page snapshot and
the same context/deadline used for its fetch. Budget metadata survives canceled,
unsupported and empty scopes. The CLI starts that context before requesting the
page. Sequential asset requests never reset the deadline; no requests start
after observed cancellation
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
Normal TLS and proxy behavior remain unchanged; same-origin and explicitly allowed
private/local targets are valid, just like page fetching. This is not a public
untrusted-URL service. Configured origins never expand attempts, byte profiles or
deadline, and never relax the HTTPS-page/HTTP-asset exclusion.

The fetch layer rejects non-2xx, 206 and Content-Range responses before reading
their bodies. It requires exactly one valid Content-Type: `text/css` for styles,
or `text/javascript`, `application/javascript`, `text/ecmascript`,
`application/ecmascript`, or `application/x-javascript` for scripts. This response
alias does not change the HTML declaration types accepted by `Extract` above.
MIME parameters are parsed, but collection
does not transcode or interpret asset contents. No MIME sniffing or file-extension
fallback. Successful bodyless responses can yield empty captures. Missing or
unsupported MIME, unsupported content encoding, corruption and truncation are
reported, not silently treated as successful captures. Bodies are always closed.

Payload bounds use the selected profile; see the
[profile table](../../docs/policies.md#requests-and-limits). Standard defaults
remain 512 KiB decoded / 1 MiB encoded per asset and 2 MiB decoded / 4 MiB encoded
combined. Per-asset reads can consume one extra probe byte in each dimension;
aggregate bounds **include** failed reads/probes. Before each request, the body
limits are clamped to the remaining
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
the bounded eligible scope. Excluded-origin/ineligible declarations are counted,
not coverage failures. Zero eligible assets can be complete. Page findings
survive all optional failures; JSON/terminal metadata makes limitations explicit.
Origin summaries and their separate truncation flag survive optional asset
failures. Origin-summary truncation alone does not change collection status or
the existing eligible-reference `Truncated` flag.

## Offline detection handoff

Only `Captures` (complete, accepted bodies) reach the detector. Collection failures
never supply partial bodies; previously captured assets remain usable. JS/CSS kinds
map to separate matcher sources. Asset headers never identify the page server,
and bodies are never concatenated with each other or HTML. Rules cannot combine
markers across files. No character transcoding, JS/CSS parsing or execution is
introduced; raw text can include copied/commented examples.

Production asset rules cover Next.js manifests, React client/ReactDOM, Vue,
Angular component-runtime shapes, jQuery core indicators, Radix UI style mappings,
Bootstrap CSS and Tailwind CSS build markers. Evidence retains
each matched asset URL, subject to report redaction and display sanitization.
Separate inline CSS rules cover Bootstrap/Tailwind with their existing patterns,
requiring all markers within one block and retaining only its ordinal as provenance.
See [rule rationale and sources](../../docs/fingerprints.md).

User-run checks: `go test ./...`. Tests use inline fixtures and local servers,
not live third-party sites.
