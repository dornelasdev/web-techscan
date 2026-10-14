# Changelog

## Unreleased

- Added inferred jQuery core-runtime detection from paired prototype/expando
  indicators in one captured JS asset, under JavaScript libraries. Reviewed
  3.7.1/4.0.0 full/slim minified baselines; no version reporting or collection changes.
- Organized terminal `--techs` output as group → category → technology under
  Web development and Infrastructure, with shared category validation/display metadata.
- Moved Angular, React, and Vue from `framework` to `javascript_framework` in
  scan and catalog output. Next.js/Nuxt retain `framework`; technology IDs,
  rules, states and evidence are unchanged. Both JSON contracts retain their
  schema-1 structures without a `group` field. The catalog has ten categories.
- Added Cloudflare and Amazon CloudFront header fingerprints under CDN/edge.
- Added AWS Application and Classic Load Balancer cookie-pair inference.
- Added AWS WAF action-header detection.
- Added Nuxt header/HTML detection, Django CSRF cookie/input inference, and
  Ruby on Rails CSRF metadata inference.
- Added Bootstrap CSS inference under UI frameworks.
- Added paired React 19-shaped client runtime inference in captured JavaScript.
- Added Angular HTML inference from paired version/server-context attributes
  on one tag, with same-tag boundaries, source isolation and CLI regressions.
- Added Angular component-runtime inference from three JS indicators in one
  captured asset, including escaped component properties; collection limits
  and version reporting are unchanged.
- Added ReactDOM 18/19-shaped key/error-formatter inference for the existing React
  finding, accepting exact legacy/modern error URLs with compatibility decoys
  and client/renderer coexistence checks.
- Added Vue 3-shaped renderer runtime inference from three paired JS markers.
- The development catalog now has 23 technologies.
- Added opt-in `--assets` inspection of direct same-origin JS/CSS, with bounded
  attempt/body budgets, a shared deadline, MIME/status validation, and per-item
  collection metadata. Optional failures preserve page findings.
- Added `--assets --asset-budget expanded` for larger bounded captures while
  retaining standard defaults, with profile/limit reporting and gzip, overflow,
  aggregate-budget and CLI regressions. No new discovery or JS execution.
- Accepted explicit `application/x-javascript` responses for selected scripts,
  with MIME rejection, gzip/size-limit and detection regressions; no sniffing
  or collection-limit changes.
- Added Next.js build/SSG manifest inference and asset URL evidence.
- Added bounded HTML reference extraction using `golang.org/x/net v0.61.0`.
- Added `--redact-query` for page, redirect, asset, and evidence report URLs.
- Blocked HTTPS-to-HTTP page redirects by default; added `--allow-http-downgrade`.
- Removed Referer on cross-origin redirects and raw rejected URLs from diagnostics.
- Added explicit encoding validation and `--max-encoded-body` (4 MiB default).
- Hardened terminal text handling for Unicode bidi and line/paragraph controls.
- Tightened nginx/Apache banner patterns.
- Added mixed-stack, fetch-failure, privacy, combined JS/CSS and independent
  frontend-finding regressions, including Angular/ReactDOM coexistence,
  split indicators, oversized captures and report-provenance redaction.
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
