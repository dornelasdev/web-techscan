# Output contract

`--json <url>` writes one scan report to stdout, indented with two spaces and followed
by a newline. No status messages, terminal symbols, or ANSI styling are mixed
into this stream. Diagnostics go to stderr. Successful HTTP retrieval with no
findings is still exit code 0. Page-fetch/configuration errors do not emit a report;
a failed output write can leave partial bytes, so consumers must check the
exit code too.

## JSON schema version 1

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Output contract version, currently 1 |
| `url` | string | Normalized requested URL, without a fragment |
| `final_url` | string | Final URL after followed redirects |
| `query_redacted` | boolean, optional | `true` when query redaction is enabled for this report; omitted by default |
| `http_status` | integer | Final response's HTTP status code |
| `response_scope` | string | `final_response` or `http_error_response` for status 400 and above |
| `body_bytes` | integer | Size of the captured body after any automatic gzip decompression |
| `catalog_size` | integer | Number of technologies in the loaded catalog, not the number found |
| `redirects` | array | Followed hops in request order, each with `from_url`, `to_url`, and `status_code` |
| `findings` | array | Findings ordered by technology ID |
| `assets` | object, optional | Bounded collection metadata when `--assets` is enabled; omitted by default |

Each finding contains `id`, `name`, `category`, `state`, and `evidence`.
Categories currently include `framework`, `web_server`, `cms`, `language`, `cdn`,
`load_balancer`, and `waf`.
New category strings may be added; consumers should preserve unknown values.
`cdn` is displayed as CDN/edge. It describes identifying edge-provider evidence,
not enabled security services, cache behavior, or the hidden origin's identity.
`load_balancer` is displayed as `load balancer` in findings and Load balancers
in catalog listings. Initial cookie-pair rules remain inferred; they do not
establish a network topology or number of backend servers.
`waf` is displayed as WAF in findings and WAFs in catalog listings. The initial
AWS WAF rule uses explicit action-header evidence, not status codes or provider
relationships. A challenge response with status 202 retains `final_response`
scope; that label does not mean the origin application was reached.
States are `detected`
and `inferred`; neither is a guarantee of the hidden origin's technology.
`response_scope` describes the inspected response, not its ownership or origin.

Each evidence entry has a `description` and a `signals` array. Matched rules
also have `rule_id`. A signal has `source` (`header`, `cookie`, or `html`) and
an optional `name` for header names. Inference relationships instead have an
`inferred_from` technology ID, and an empty `signals` array. An indirect rule
can have state `inferred` while retaining its own `rule_id` and observed signals.

All collection fields are arrays, including when empty; they are not `null`.
Absent optional strings are omitted. A catalog of size 0 is distinct from a
populated catalog with no findings. There are no confidence scores, raw body
contents, raw header values, or cookie values in the report. URLs retain query
strings by default. With `--redact-query`, the query in `url`, `final_url`, and
every redirect's `from_url`/`to_url`, and every asset item's `url` is replaced with
`?[redacted]`. Both names and
values are removed, including bare parameters and malformed query escapes.
An empty trailing `?` is also replaced; URLs with no query are unchanged.
Escaped path delimiters such as `%3F` are preserved without decoding.

`query_redacted: true` records that the policy was applied, even when all URLs
were query-free. It is an additive optional field in schema 1; default report
bytes are unchanged. Redacted URLs are display/export representations and must
not be interpreted as the exact requested URLs. Redaction copies the report's
URL fields, redirect slice, asset metadata and item slice; it never mutates the source report/snapshot or
changes findings, actual requests, referrers, or fetch-error behavior.

This is not general anonymization. Sensitive hostnames/paths, process arguments,
shell history, and network/server logs are outside this flag's scope.

Consumers should check `schema_version`, use IDs rather than display names,
and allow additional fields within a schema version. A breaking change to
field types or meanings must increment the output schema version. Report
types are separate from the internal fetch/detection structures so refactoring
those structures does not implicitly change the public JSON shape.

## Optional asset collection

`--assets` adds an `assets` object in schema 1; default JSON is unchanged.
No asset content contributes findings in this checkpoint (`mode: collection_only`).
Asset failures do not change successful page scans to exit 1; consumers needing
all selected assets must check the collection status and individual items.

| Field | Meaning |
| --- | --- |
| `mode` | Currently `collection_only`; no asset-content findings |
| `status` | `complete` within bounded eligible scope, `incomplete`, or whole-pass `skipped` |
| `reason` | Optional safe summary code |
| `truncated` | More eligible distinct references existed than the five retained |
| `skipped_declarations` | Ineligible/off-origin script or stylesheet declarations, not every HTML node |
| `duplicates` | Repeat URLs among the retained candidates |
| `attempted`, `collected` | Attempted requests (including failures) and accepted complete bodies |
| `decoded_bytes`, `encoded_bytes` | Payload bytes consumed, including failed reads and overflow probes |
| `items` | Selected assets in document order; always an array, including when empty |

Each item includes `url`, `kind` (`javascript`/`stylesheet`), `status`
(`collected`/`failed`/`skipped`), optional `reason`, optional `http_status` when
a response was available, and `decoded_bytes`/`encoded_bytes`. Failed items were
attempted; skipped items were not. Bodies, header values, redirect targets and
raw error messages are never serialized. Queries remain present by default;
`--redact-query` covers every item, even failed/skipped ones.

Whole-pass reason codes include `unsupported_page_type`, `invalid_utf8_html`,
`html_limit`, `extraction_failed`, `timeout` and `canceled`. Incomplete summaries
use `reference_limit` or `asset_failures_or_skips`. Item reasons include
`redirect_not_allowed`, `unsuccessful_status`, `unsuitable_content_type`,
`unsupported_content_encoding`, `decoded_body_limit`, `encoded_body_limit`,
`request_or_body_error`, `timeout`, `canceled` and `total_byte_limit`.
Consumers should tolerate future reason codes. A malformed redirect parsed by
Go before its redirect hook can be a generic request error instead of a redirect
policy reason; neither exposes its raw destination.

`complete` does not mean complete site coverage: third-party assets and nested
references are out of scope, and no eligible assets is also complete. Truncation
or a failed/skipped selected asset makes the pass incomplete. See the
[fixed limits and conservative aggregate-boundary policy](../assets/README.md#collection-policy).
Byte counts are not file sizes or total wire traffic; they exclude transport
buffers, framing and headers, and can exceed accepted body size by a probe.

## Terminal output

Terminal output shows final-response metadata, findings with evidence, and a
legend: green `✓` for detected, yellow `?` for inferred. It uses friendly
category labels such as `web server`. Control characters in displayed values
are replaced so they cannot insert terminal commands or extra lines.
When query redaction is enabled, the report includes a policy note and the
displayed final URL uses the same `?[redacted]` placeholder as JSON.
Opt-in asset output includes status, counts, per-item URLs/reasons, and an
explicit collection-only note. Every asset string uses the same terminal safety
filter as the rest of the report; optional query redaction happens first.

Color is selected by the CLI; the renderer receives an explicit boolean.
JSON has no color option. `--no-color` has highest priority, followed by an
explicit `--color always|never`. In automatic mode, nonempty `NO_COLOR` and
`TERM=dumb` disable color. Otherwise, the CLI uses the stdout file's
character-device bit as a portable heuristic, not a full terminal capability
probe. Pipes, regular files, and in-memory writers remain uncolored.

The terminal presentation may evolve without a JSON schema change. For
automation, consume JSON rather than parsing human-readable lines.

## Technology catalog JSON

`--techs --json` writes a separate offline catalog document, not a scan report.
Its independent schema starts at version 1:

```json
{
  "schema_version": 1,
  "catalog_size": 1,
  "technologies": [
    {"id": "php", "name": "PHP", "category": "language"}
  ]
}
```

This example shows one entry, not the full bundled catalog. Each technology has
only `id`, `name`, and `category`; support does not assign a finding state or
guarantee identification. Technologies supported only by inference are included.
`catalog_size` equals the array length. An empty catalog uses `technologies: []`.

Both catalog formats order categories as `web_server`, `framework`, `cms`,
`language`, `cdn`, `load_balancer`, `waf`,
then names case-insensitively within each category, with ID as a tie-breaker.
Terminal output uses friendly group headings and a coverage disclaimer. It is
always plain text, regardless of color flags. JSON uses two-space indentation,
a trailing newline, and no status text. Load/write errors use stderr and exit 1;
invalid argument combinations use exit 2. Failed writes can leave partial output.
The existing scan JSON schema is unchanged.

## Terminal text safety

Scan and catalog terminal renderers replace C0/C1 controls, including ESC,
Unicode `Bidi_Control` characters (direction marks, embeddings, overrides, and
isolates), and U+2028/U+2029 line/paragraph separators with U+FFFD (`�`) in
displayed string values. The implementation uses Go's
[Unicode property tables](https://pkg.go.dev/unicode#Bidi_Control). Renderer-owned
line breaks and optional scan-marker color sequences are not filtered.

Ordinary Unicode letters, combining marks, and joiners/variation selectors used
in scripts and emoji are preserved. Literal percent escapes are not decoded.
This is not general Unicode spoofing or homoglyph protection.

Unicode sanitization is presentation-only: it does not change request URLs,
snapshots, findings, catalog metadata, or JSON values. Both JSON formats retain
valid Unicode strings through JSON escaping (scan URL queries may separately
be redacted with `--redact-query`); they are data formats, not
terminal-safe display formats. Consumers must sanitize values for their display
context, including after decoding JSON strings.
