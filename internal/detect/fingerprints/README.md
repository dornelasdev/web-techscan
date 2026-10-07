# Fingerprint format

JSON files in this directory are embedded at build time. Each file contains
`schema_version: 1` and a `technologies` array. Files are loaded together, so
inference relationships may reference technology IDs in another file.

The catalog is split across `servers.json`, `frameworks.json`, `cms.json`,
`languages.json`, and `cdn.json`. See [coverage and sources](SOURCES.md) for the supported
technologies, rule rationale, and limitations. Synthetic examples live under
`../testdata/` and are never embedded.

## Example

This illustrates the format, not a real detection rule:

```json
{
  "schema_version": 1,
  "technologies": [
    {
      "id": "example-framework",
      "name": "Example Framework",
      "category": "framework",
      "rules": [
        {
          "id": "combined-markers",
          "state": "detected",
          "description": "Framework header and cookie-name markers",
          "all": [
            {"source": "header", "name": "X-Framework", "pattern": "^Example$"},
            {"source": "cookie", "pattern": "^example_session$"}
          ]
        }
      ],
      "implies": ["example-language"]
    },
    {
      "id": "example-language",
      "name": "Example Language",
      "category": "language"
    }
  ]
}
```

## Matching rules

- Technology IDs are unique across files. Rule IDs are unique within a
  technology. IDs use lowercase letters, digits, and single separating hyphens.
- Categories are `framework`, `web_server`, `cms`, `language`, and `cdn` (CDN/edge).
- Every rule needs an ID, a description, an explicit `detected` or `inferred`
  state, and at least one matcher in `all`. Every matcher must succeed for the
  rule to match. Any matching rule produces a finding for its technology.
- Sources are `header`, `cookie`, and `html`. Header matchers require a header
  `name` and inspect each value independently. Header names are case insensitive.
  Cookie matchers inspect cookie names only. HTML matchers inspect raw HTML,
  including asset URL references; they do not parse a DOM or execute scripts.
- Patterns use Go regular expressions and are case sensitive unless they
  include `(?i)`. Use anchors and explicit boundaries where appropriate.
  Invalid patterns and patterns matching empty input are rejected.
- An absent signal cannot match. Multiple occurrences of a signal produce
  one piece of evidence per matching rule, rather than duplicate findings.
- The CLI supplies HTML only for `text/html` or `application/xhtml+xml`. It
  sniffs the body only when Content-Type is absent. Explicit non-HTML types
  are excluded from HTML matching; headers and cookie names remain available.
- `Set-Cookie` and `Cookie` header matchers are rejected. Use the `cookie`
  source to avoid matching cookie values.

## Evidence and inference

Descriptions explain why a rule supports a finding. Evidence includes the rule
ID and signal locations, not captured response values. There are no confidence
percentages or automatic version extraction in this format.

`implies` lists supported technology relationships. Targets must exist in the
catalog. A technology without rules must be the target of an inference.
Duplicate edges, self-references, and longer inference cycles are rejected.

All direct matches are collected before inference. Relationships may chain,
but their results always remain `inferred` unless the target has its own
matching `detected` rule. A direct detection retains that state even when
other technologies also imply it. Every supporting relationship records its
immediate source technology ID so a chain can be traced through the findings.

Results are ordered by technology ID. Matching rules are ordered by rule ID;
inference processing also uses a stable order. The engine does not retain
page data or findings between scans.

## Adding coverage

Add a technology entry (or another JSON catalog file), review the specificity
of its signals, and add positive and near-miss fixtures before the user runs
tests. Rules that rely on indirect signals should use `inferred`; generic
markers should not become findings without sufficient supporting conditions.
Raw HTML regexes can also match comments or examples, so choose distinctive
patterns and document those limitations when reviewing coverage.

Unknown JSON fields, unsupported schema versions, and invalid relationships
fail catalog loading instead of silently reducing coverage. Changes to this
directory require rebuilding the binary; there is no automatic update service.
