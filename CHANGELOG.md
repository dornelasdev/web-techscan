# Changelog

## Unreleased

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
