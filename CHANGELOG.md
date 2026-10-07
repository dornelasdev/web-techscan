# Changelog

## Unreleased

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
