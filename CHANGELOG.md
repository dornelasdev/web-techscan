# Changelog

## Unreleased

- Added Cloudflare and Amazon CloudFront header fingerprints under CDN/edge.
- Added AWS Application and Classic Load Balancer cookie-pair inference.
- Added AWS WAF action-header detection.
- Added Nuxt header/HTML detection, Django CSRF cookie/input inference, and
  Ruby on Rails CSRF metadata inference.
- Added Bootstrap CSS inference under UI frameworks. The catalog now has
  19 technologies.
- Added opt-in `--assets` inspection of direct same-origin JS/CSS, with fixed
  attempt/body budgets, a shared deadline, MIME/status validation, and per-item
  collection metadata. Optional failures preserve page findings.
- Added Next.js build/SSG manifest inference and asset URL evidence.
- Added bounded HTML reference extraction using `golang.org/x/net v0.61.0`.
- Added `--redact-query` for page, redirect, asset, and evidence report URLs.
- Blocked HTTPS-to-HTTP page redirects by default; added `--allow-http-downgrade`.
- Removed Referer on cross-origin redirects and raw rejected URLs from diagnostics.
- Added explicit encoding validation and `--max-encoded-body` (4 MiB default).
- Hardened terminal text handling for Unicode bidi and line/paragraph controls.
- Tightened nginx/Apache banner patterns.
- Added mixed-stack, fetch-failure, privacy, and combined JS/CSS regressions.
- Reorganized documentation into usage, policies, and fingerprint references.

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
