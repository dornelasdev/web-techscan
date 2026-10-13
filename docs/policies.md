# Policies

[README](../README.md) · [Usage](usage.md) · [Fingerprints](fingerprints.md)

## Scope

- Inspect one final HTTP response and optional eligible JS/CSS assets.
- Keep redirect-hop signals separate from the final page.
- Use GET with the `webscan` user agent and normal TLS certificate verification.
- Honor Go's standard environment proxy settings.
- Do not replay cookies.
- Support local/private targets. This CLI is not a sandbox for untrusted URLs.
- No crawling, guessed paths, port scans, vulnerability tests, JS execution,
  challenge submission, or CAPTCHA solving.

Findings describe exposed response evidence. A proxy, CDN, challenge, error page,
cached artifact, or static export can expose a different stack from the origin.
Provider identity does not establish enabled WAF/LB features or network topology.

## Page fetching

| Limit | Default | Setting |
| --- | --- | --- |
| Shared network timeout | 15 seconds | `--timeout` |
| Followed page redirects | 5 | `--max-redirects` |
| Decoded final-page body | 2 MiB | `--max-body` |
| Final-page body before decoding | 4 MiB | `--max-encoded-body` |
| Response headers | 1 MiB per response | Fixed |

The timeout spans page redirects, body reads, and optional assets. It is not
reset per request. Local parsing and rendering are not preempted by it.

Both body limits must be satisfied. Reads can consume one extra overflow-probe
byte. Encoded limits cover payload bytes, including gzip headers and all members;
they do not cap HTTP framing, TLS overhead, or transport buffers.

Requests advertise gzip. Final responses support absent Content-Encoding, one
`identity`, or one `gzip` value. Reject empty, unknown, stacked, or repeated
encoding fields. No fallback request is made. Bodyless 204/304 responses skip
decoding. Corrupt/incomplete bodies, timeouts, cancellation, and page-limit
failures produce an error without a partial report.

HTTP error statuses are retained for inspection and identified as
`http_error_response`. Other statuses use `final_response`; this does not prove
that an origin application was reached.

### Redirects

- Require HTTP(S) URLs; reject embedded credentials and remove fragments.
- Enforce the redirect budget; 0 rejects redirects.
- Block each HTTPS-to-HTTP hop before contacting its destination.
- `--allow-http-downgrade` permits page downgrades with normal TLS checks on HTTPS.
- Direct HTTP, HTTP-to-HTTPS, and HTTPS-to-HTTPS remain supported.
- Omit Referer on origin changes: scheme, case-insensitive hostname, or effective
  port. The check does not use DNS.
- Same-origin redirects retain Go's normal referrer behavior, including queries.
- Redirect bodies do not supply detection signals.

Request and body diagnostics use safe summaries. Rejected Location values and
raw request URLs are omitted. Internal error causes remain available to code;
they can contain sensitive data and should not be printed directly.

## Asset inspection

Enable with `--assets`. Default scans fetch only the page redirect chain.

### Selection

- Select direct script sources and stylesheet links from the final HTML page.
- Require UTF-8 HTML: absent/UTF-8/US-ASCII charset and valid UTF-8 bytes.
  Skip XHTML, declared legacy charsets, and unsupported page types.
- Use the first non-inert base declaration and resolve against the final URL.
- Keep only same-origin HTTP(S) URLs, with strict URL validation.
- Deduplicate resolved URLs and retain the first five eligible references.
- Ignore comments, templates, noscript, foreign markup, imports, source maps,
  preloads, guessed paths, and other linked pages.
- Do not fetch third-party/CDN origins. HTML URL fingerprints can still recognize
  supported path markers without downloading those assets.

The [extractor reference](../internal/assets/README.md) defines type hints, base
handling, URL normalization, and parser limits.

### Requests and limits

HTML extraction remains limited to 2 MiB; at most five assets are attempted,
sequentially, including failures. `--asset-budget` selects payload bounds:

| Payload limit | Standard (default) | Expanded |
| --- | ---: | ---: |
| Decoded bytes per asset | 512 KiB | 4 MiB |
| Encoded bytes per asset | 1 MiB | 8 MiB |
| Combined decoded asset reads | 2 MiB | 8 MiB |
| Combined encoded asset reads | 4 MiB | 16 MiB |

Expanded is explicit opt-in with `--assets --asset-budget expanded`.
Profiles do not change page-body limits, attempts, origins or the shared timeout.
Both encoded and decoded bounds apply. Larger captures can increase bandwidth,
retained data and fingerprint-matching work; these are not hard memory limits.
The network timeout does not preempt local parsing or fingerprint matching.
Failed reads and overflow probes count toward the combined budgets. Each request
reserves one remaining aggregate byte for a probe; an asset at the exact combined
boundary can be rejected. These limits cover payload reads, not wire overhead.

Asset requests use normal TLS/proxy/encoding behavior, with no cookies,
authorization, Referer, asset redirects, or application retries. Page downgrade
permission does not allow asset redirects.

Accept successful, non-partial responses with an explicit matching MIME type:
`text/css` for stylesheets; `text/javascript`, `application/javascript`,
`text/ecmascript`, `application/ecmascript`, or `application/x-javascript` for
scripts. The added alias is a [recognized JavaScript MIME type](https://mimesniff.spec.whatwg.org/#javascript-mime-type).
Require one valid Content-Type; media-type casing and valid parameters are handled
by the MIME parser. Reject missing, repeated, malformed or mismatched MIME,
HTTP 206, and Content-Range responses. Do not sniff asset MIME or trust extensions.
This response allowlist does not expand the extractor's HTML script-type hints.

### Detection and failures

- Supply only complete accepted bodies to detection.
- Keep JS and CSS sources separate; require each rule's markers in one body.
- Do not use asset headers as page headers or concatenate bodies with HTML.
- Preserve accepted captures and page findings when another asset fails.
- Continue after optional failures while time and byte budgets permit.

Collection reports use `complete`, `incomplete`, or `skipped`, with safe reason
codes, per-item metadata and the configured budget profile/four limits, including
for skipped or empty scopes. `complete` means the selected bounded scope, not
all resources or complete technology coverage. Optional failures preserve exit
0; page failures remain fatal. See the [asset output contract](../internal/output/README.md#optional-asset-collection).

## Privacy

Reports include URLs and evidence locations. They omit raw bodies, header
values, and cookie values. Page cookie names remain available to detection.

### Query redaction

`--redact-query` replaces the entire query with `?[redacted]` in:

- Original and final page URLs.
- Both ends of every redirect hop.
- All asset items, including failures/skips.
- Asset evidence URLs.

Query-free URLs and encoded paths are preserved. JSON includes
`query_redacted: true`; terminal output states the policy. Redaction changes
the report copy only. Requests, redirects, and referrers retain their original
queries. Hostnames, paths, shell history, process arguments, and remote logs are
outside its scope.

### Terminal text

Scan and catalog displays replace C0/C1 controls, Unicode Bidi_Control, and
U+2028/U+2029 with `�`. Ordinary international text, combining marks, joiners,
and emoji remain intact. Percent escapes are not decoded.

JSON preserves strings subject to JSON escaping and optional query redaction.
JSON consumers must sanitize values for their own display context.
