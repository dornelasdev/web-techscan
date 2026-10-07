# Output contract

`--json <url>` writes one scan report to stdout, indented with two spaces and followed
by a newline. No status messages, terminal symbols, or ANSI styling are mixed
into this stream. Diagnostics go to stderr. Successful HTTP retrieval with no
findings is still exit code 0. Fetch/configuration errors do not emit a report;
a failed output write can leave partial bytes, so consumers must check the
exit code too.

## JSON schema version 1

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Output contract version, currently 1 |
| `url` | string | Normalized requested URL, without a fragment |
| `final_url` | string | Final URL after followed redirects |
| `http_status` | integer | Final response's HTTP status code |
| `response_scope` | string | `final_response` or `http_error_response` for status 400 and above |
| `body_bytes` | integer | Size of the captured body after any automatic gzip decompression |
| `catalog_size` | integer | Number of technologies in the loaded catalog, not the number found |
| `redirects` | array | Followed hops in request order, each with `from_url`, `to_url`, and `status_code` |
| `findings` | array | Findings ordered by technology ID |

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
contents, raw header values, or cookie values in the report. URLs are retained,
including query strings; this is not a general redaction/export facility.

Consumers should check `schema_version`, use IDs rather than display names,
and allow additional fields within a schema version. A breaking change to
field types or meanings must increment the output schema version. Report
types are separate from the internal fetch/detection structures so refactoring
those structures does not implicitly change the public JSON shape.

## Terminal output

Terminal output shows final-response metadata, findings with evidence, and a
legend: green `✓` for detected, yellow `?` for inferred. It uses friendly
category labels such as `web server`. Control characters in displayed values
are replaced so they cannot insert terminal commands or extra lines.

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
