# Changelog

## Unreleased

- Added Python inferred from Django and Ruby inferred from Ruby on Rails,
  with framework provenance. No independent language rules or extra requests.
- Added Jetty server-header detection for complete parenthesized release banners.
  No Java or framework implication, version reporting, or extra requests.
- The development catalog contains 26 technologies across ten categories.

## v0.3.0 — 2026-10-16

Bounded asset inspection, broader frontend/infrastructure coverage, and fetching
and reporting hardening. The catalog contains 23 technologies across ten categories.

### Added

- Opt-in `--assets` inspection of directly referenced same-origin JS/CSS, with
  bounded requests/reads, a shared network deadline, MIME/status validation,
  per-item collection metadata and asset URL evidence. Optional failures preserve
  page findings.
- `--asset-budget standard|expanded` profiles. Standard remains the default;
  expanded permits larger bounded captures without changing discovery, origins,
  attempt limits or execution behavior.
- Inferred asset rules for Next.js manifests, React client/ReactDOM, Vue,
  Angular component-runtime shapes, Bootstrap CSS and jQuery core indicators.
  Added Angular HTML inference from paired attributes on one tag. No version reporting.
- Nuxt header/HTML detection, Django CSRF cookie/input inference, and Ruby on
  Rails CSRF metadata inference.
- Cloudflare/CloudFront header fingerprints, AWS Application/Classic Load
  Balancer cookie-pair inference, and independent AWS WAF action-header detection.
- `--redact-query` for page, redirect, asset and evidence report URLs.

### Changed

- Organized terminal `--techs` output as group → category → technology under
  Web development and Infrastructure.
- Added `javascript_framework` for Angular/React/Vue and `javascript_library`
  for jQuery. Next.js/Nuxt retain `framework`. Technology IDs and evidence states
  remain stable; groups are presentation metadata, not additional findings.
- Retained schema 1 for scan/catalog JSON, with additive asset, budget, provenance
  and query-redaction fields. Catalog JSON remains flat, without a `group` field.
- Added bounded HTML reference extraction using `golang.org/x/net v0.61.0`;
  accepted explicit `application/x-javascript` responses without MIME sniffing.
- Reorganized documentation into usage, policies and fingerprint references.

### Hardened

- Blocked HTTPS-to-HTTP page redirects by default; added `--allow-http-downgrade`.
  Removed cross-origin Referer and raw rejected URLs from diagnostics.
- Added explicit content-encoding validation and `--max-encoded-body`
  (4 MiB default), retaining normal TLS verification.
- Tightened nginx/Apache banner patterns and terminal handling of Unicode bidi
  and line/paragraph controls.
- Expanded local regression coverage for mixed stacks, split/partial indicators,
  source isolation, fetch/asset failures, byte budgets, privacy and output contracts.

### Scope

Single-URL inspection with optional direct same-origin assets. No crawling,
JavaScript execution, version extraction, bulk scanning or vulnerability testing.
Local-source builds remain the installation method.

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
