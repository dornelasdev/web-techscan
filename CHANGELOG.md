# Changelog

## Unreleased

- Added opt-in `--assets` collection/reporting: up to five sequential same-origin
  direct JS/CSS assets, no asset redirects, one page-and-assets deadline, per-asset
  and aggregate decoded/encoded budgets including failed reads. MIME/status checks
  and safe per-item failure/skip reasons preserve page findings on optional failure.
  Added optional schema-1 `assets` metadata, asset URL query redaction and terminal
  sanitization. Default scans and findings are unchanged; asset fingerprints are
  deferred. Added local collection, accounting, privacy and integration regressions.
- Added offline asset-reference extraction groundwork using a pinned Go HTML
  parser: same-origin JS/CSS references, base resolution, deduplication, and
  bounded candidates/input, with positive/negative regression fixtures. This is
  initially separate from the CLI (now connected by the collection checkpoint
  above). Added the first module dependency, `golang.org/x/net v0.61.0`.
- Added optional `--redact-query` for scan reports: replace entire queries in
  original/final/redirect URLs with `?[redacted]`, with a terminal policy note
  and optional `query_redacted: true` JSON metadata. Default output, actual
  requests, referrers, and findings remain unchanged. Added redaction boundary,
  non-mutation, request-fidelity, failure, and terminal/JSON regressions.
- Block HTTPS-to-HTTP redirects by default, checking every hop even in chains
  that started on HTTP. Added explicit `--allow-http-downgrade` opt-in without
  weakening TLS verification, URL validation, or redirect limits. Direct HTTP
  and private/local targets remain supported. Added redirect-policy and local
  TLS terminal/JSON regressions, including no requests to blocked destinations.
- Hardened scan/catalog terminal text against Unicode bidi controls and
  line/paragraph separators, preserving ordinary Unicode and emoji. Added
  colored/plain rendering, JSON-preservation, and local redirect regressions.
  Request URLs, JSON schemas/values, and detection behavior remain unchanged.
- Bound final-response input before content decoding with `--max-encoded-body`
  (default 4 MiB), independently of the existing decoded-body limit. Reject
  oversized input, including empty gzip member sequences, without partial reports.
  Added exact-boundary, gzip-header/member, chunked, cleanup, option-validation,
  and terminal/JSON regressions. No new dependencies or collection requests.
- Validate final-response content encodings before decoding with the standard
  library. Preserve plain/identity/gzip support and decoded-body limits; reject
  unsupported, stacked, or repeated encodings without partial scan reports.
  Added gzip corruption/truncation, chunking, cancellation, shared-deadline,
  cleanup, and terminal/JSON regressions. Body errors now use safe summaries.
  No new dependencies, extra requests, or fingerprint changes.
- Prevented rejected/malformed redirect destinations from appearing in request
  error messages, preserving underlying error classification. Unknown request
  failures use safe generic diagnostics. Cross-origin redirects now omit Referer;
  same-origin behavior and successful report URLs remain unchanged. Added origin,
  redirect-chain, error-privacy, and terminal/JSON failure regressions. No new
  requests, dependencies, or fingerprint changes.
- Added combined server/framework regressions: all subsets of Nuxt/Django/Rails
  paired signals against valid and malformed nginx, Apache, and IIS banners.
  Expanded the mixed-stack CLI fixture across all three servers, preserving
  independent evidence/state upgrades, language-inference sources, privacy,
  final-response isolation, and GET-only collection in both output formats.
  No production fingerprints, collection behavior, or catalog-size changes.
- Added initial Ruby on Rails inference from paired CSRF meta tags on the final
  HTML response. Added boundary, partial-pair, cross-framework, privacy, redirect,
  terminal/JSON, and offline catalog checks. Eighteen technologies are now bundled;
  no Ruby inference, generic session-cookie detection, or collection changes.
- Added inferred Django coverage requiring both its default CSRF cookie name
  and hidden-input markup on the final response. Added positive/near-miss,
  cross-source, redirect-isolation, privacy, terminal/JSON, and catalog checks.
  Seventeen technologies are now bundled; cookie names alone remain insufficient.
  No Python inference, form submission, or collection changes.
- Added Nuxt framework coverage: an exact identifying header produces detected
  state; paired payload/script-path HTML markers produce inferred state. Added
  synthetic fixtures, boundary/evidence tests, terminal/JSON integration, and
  offline catalog checks. Sixteen technologies are now bundled; no language
  inferences, asset fetching, JavaScript execution, or User-Agent changes.
- Tightened nginx/Apache Server-header fingerprints to reject malformed product
  versions and unstructured trailing text while retaining supported OS/build
  comments and Apache module banners. Added detector and terminal/JSON CLI
  regressions for nginx, Apache, and IIS; IIS's rule is unchanged. Unusual custom
  banners may be missed; no new technologies, requests, or language inferences.
- Added mixed-stack CLI regressions across application, CDN, load-balancer, and
  WAF signals in terminal and JSON output, covering evidence/state preservation,
  duplicate signals, near-misses, redirect isolation, response scope, privacy,
  and body-limit failures. No new fingerprints or collection behavior.
- Added AWS WAF detection from explicit challenge/CAPTCHA action-header values,
  with `waf` in JSON and WAF/WAFs terminal labels. Coverage totals fifteen
  technologies. Added positive/near-miss, independent-evidence, redirect, status,
  and output checks; no challenge execution, bypass attempts, or extra requests.
- Added inferred AWS Application Load Balancer and Classic Load Balancer findings
  from exact stickiness-cookie pairs, with a `load_balancer` category in scan and
  catalog output. Added cookie-boundary,
  privacy, redirect-isolation, mixed-stack, and local CLI checks; no new requests.
- Added Cloudflare and Amazon CloudFront response-header fingerprints under
  `cdn`, displayed as CDN/edge in findings and `--techs`. These findings do not
  imply enabled WAF/load-balancer services or identify a hidden origin.
  No additional requests or dependencies.
- Added CDN positive/near-miss, mixed-stack, catalog, and local CLI checks for
  evidence, redirect isolation, error responses, and both output formats.

## v0.2.0 — 2026-10-06

Catalog discovery, CMS coverage, and detection hardening. The bundled catalog
now contains ten technologies. Local-source builds and the existing collection
scope remain unchanged; no CDN, load-balancer, or WAF detection is included.

- Hardened Next.js HTML inference to require complete script opening tags and
  actual attribute tokens; asset markers must be in URL paths, not hostnames,
  query strings, or fragments. Added quote-style and URL-boundary regressions.
- Restricted WordPress/Joomla generator version suffixes to numbered prerelease
  forms, rejecting lookalikes such as `-compatible`.
- Added WordPress, Drupal, and Joomla generator fingerprints in a new `cms`
  category. HTML markers remain inferred; Drupal's identifying header is detected.
  Added CMS fixtures and near-miss/integration checks without new network behavior
  or automatic PHP inference from CMS markers.
- Added offline `--techs` listing from the bundled catalog, grouped by category
  with stable name ordering, plus a separate `--techs --json` catalog report.

## v0.1.0 — 2026-10-05

Initial single-URL technology inspection CLI. The repository is named
`web-techscan`; the local module and executable use `webscan`. Build from local
source for this version; a public module path and remote `go install` are deferred.

### Included

- Bounded HTTP(S) fetching with configurable timeout, redirect count, and body
  size; normal TLS verification and separate redirect metadata.
- Embedded, validated fingerprint catalogs for nginx, Apache HTTP Server,
  Microsoft IIS, Express, Next.js, Laravel, and PHP.
- Explicit detected/inferred states and per-finding evidence, including
  supported language relationships, without confidence percentages.
- Terminal output with optional color and schema-versioned JSON output.
- Local fixtures and automated checks for fetching, rule validation, detection,
  output, and the integrated CLI. No live third-party targets are needed.

### Release boundaries

One final response only. No asset downloading, crawling, JavaScript execution,
version extraction, bulk targets, or vulnerability checks. Detection describes
observed signals, not proof of the complete stack or hidden origin.
