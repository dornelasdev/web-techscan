# Coverage and sources

Reviewed on 2026-10-05. These rules were authored for this project from
documented behavior and upstream source. No third-party fingerprint dataset
was imported. The HTML fixtures are synthetic, not captured website content.
Upstream branch links may change; revisit the behavior when updating a rule.

| Technology | Rule | Evidence and state | Source |
| --- | --- | --- | --- |
| nginx | `server-header` | `Server` starts with the nginx product token: detected | [nginx server_tokens](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens) |
| Apache HTTP Server | `server-header` | `Server` starts with the Apache product token: detected | [Apache ServerTokens examples](https://httpd.apache.org/docs/2.4/mod/core.html#servertokens) |
| Microsoft IIS | `server-header` | `Server` identifies Microsoft-IIS: detected | [Microsoft IIS support: response headers](https://techcommunity.microsoft.com/blog/iis-support-blog/remove-unwanted-http-response-headers/369710) |
| Express | `powered-by-header` | `X-Powered-By` identifies Express: detected | [Express response implementation](https://github.com/expressjs/express/blob/master/lib/application.js), [header configuration](https://expressjs.com/en/advanced/best-practice-security/#reduce-fingerprinting) |
| Next.js | `powered-by-header` | `X-Powered-By` identifies Next.js: detected | [Next.js response implementation](https://github.com/vercel/next.js/blob/canary/packages/next/src/server/send-payload.ts), [header configuration](https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader) |
| Next.js | `pages-html-markers` | Both a `__NEXT_DATA__` script ID and a `/_next/static/` script URL occur in HTML: inferred | [Pages document source](https://github.com/vercel/next.js/blob/canary/packages/next/src/pages/_document.tsx), [asset prefixes](https://nextjs.org/docs/app/api-reference/config/next-config-js/assetPrefix) |
| Laravel | `default-cookie-pair` | Both `laravel_session` and `XSRF-TOKEN` cookie names: inferred | [Session configuration](https://github.com/laravel/framework/blob/13.x/config/session.php), [CSRF cookie documentation](https://laravel.com/framework/docs/13.x/csrf#x-xsrf-token) |
| PHP | `powered-by-header` | `X-Powered-By` identifies PHP: detected | [PHP expose_php](https://www.php.net/manual/en/ini.core.php#ini.expose-php) |

## Interpretation and limits

- Server headers identify the exposed responding software, which can be an
  intermediary. They do not prove the origin stack. Product boundaries avoid
  treating Apache-Coyote as Apache HTTP Server or nginx-proxy as nginx.
- Header rules accept product spelling case variations. Cookie names, HTML
  marker values, and asset paths remain case sensitive. Versions help match
  a product token but are not extracted or reported as findings.
- Header removal and customization cause false negatives. A header can also
  be spoofed, so `detected` means direct evidence, not absolute confirmation.
- The Laravel cookie combination is our heuristic, not an upstream guarantee
  of uniqueness. Both names must occur. The session name is configurable and
  normally derives from the application name; custom names will be missed.
  `XSRF-TOKEN`, generic `*_session` cookies, and `PHPSESSID` alone produce no
  findings. The cookie combination remains `inferred`.
- Laravel implies PHP because it is a PHP framework; this inference inherits
  uncertainty from the Laravel finding. The configured relationship records
  Laravel as its source. A PHP header upgrades PHP to `detected` without
  discarding inference evidence.
- The Next.js HTML rule requires both script markers and supports quoted
  attributes, changed attribute order, whitespace, and CDN/base-path prefixes.
  Each marker must be a real attribute token on a complete `script` opening
  tag: `script-widget`, truncated tags, and marker assignments inside another
  quoted attribute do not suffice. Extra attributes are consumed as whole tokens.
  Asset URLs support HTTP(S), scheme-relative, root-relative, and prefixed
  relative paths (such as `./_next/static/…`). The `/_next/static/` marker must
  occur in the path, not the authority, query, or fragment, with a nonempty
  path remainder. Query/fragment suffixes after a valid asset path are allowed.
  It is deliberately limited to the documented Pages Router shape. App Router
  pages without these markers and without the identifying header can be missed.
  These are conservative literal URL patterns, not URL parsing/resolution:
  backslashes, other schemes, empty prefix segments, entity/percent-encoded
  markers, and unquoted target attributes are not supported. Dot segments are
  not normalized and URLs are not checked for reachability.
- Next.js HTML can be statically exported. Its presence does not establish a
  running Node.js server or the application's source language. The initial
  catalog makes no JavaScript/TypeScript language inference from Next.js or
  Express. IIS does not imply C# and nginx does not imply C.
- Raw HTML regular expressions do not understand document structure. Copied
  markup, comments, or quoted examples containing both complete Next.js script
  markers can still produce an inferred match. Encoded examples, plain marker
  text, `data-src`/`data-id`, and either marker alone do not suffice. A future
  parser-based source can address the remaining ambiguity if needed.
- Only final-response data is inspected. A 403/block page may reveal the
  responding software without exposing the site's application. The CLI notes
  the scope of findings on HTTP error responses.

## Verification fixtures

`../coverage_test.go` covers every initial rule with positive and near-miss
cases, including language inference and direct-evidence precedence.
`../nextjs_test.go` adds script-tag/attribute boundaries and asset URL path cases
across both quote styles. HTML
documents live in `../testdata/coverage/`. CLI coverage tests additionally
exercise fetching, cookie-name extraction, HTML content-type filtering,
error-page scope, and redirect isolation using local HTTP servers.

Tests are authored checks, not measurements of real-world detection accuracy.
The user runs them; the agent does not execute tests or scan live sites.

## CMS additions — reviewed 2026-10-06

| Technology | Rule | Evidence and state | Source |
| --- | --- | --- | --- |
| WordPress | `generator-meta` | Generator meta markup naming WordPress, optionally with a numeric version: inferred | [WordPress generator implementation](https://developer.wordpress.org/reference/functions/get_the_generator/) |
| Drupal | `generator-meta` | Generator meta markup naming Drupal with a numeric version and optional official-site URL: inferred | [Drupal default metadata](https://api.drupal.org/api/drupal/core%21lib%21Drupal%21Core%21Render%21BareHtmlPageRenderer.php/11.x) |
| Drupal | `generator-header` | Anchored `X-Generator` value naming Drupal with a numeric version and optional official-site URL: detected | [Drupal response subscriber](https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Core/EventSubscriber/ResponseGeneratorSubscriber.php) |
| Joomla | `generator-meta` | Generator meta markup with Joomla's standard product phrase and optional version suffix: inferred | [Joomla site metadata](https://github.com/joomla/joomla-cms/blob/5.4-dev/libraries/src/Application/SiteApplication.php), [meta renderer](https://github.com/joomla/joomla-cms/blob/5.4-dev/libraries/src/Document/Renderer/Html/MetasRenderer.php) |

These are intentionally narrow first rules, not full coverage of each CMS.
No upstream implementation or third-party fingerprint dataset was imported.

- All HTML rules require the `name` and `content` attributes on the same complete
  meta tag, in either order. Relevant values must be single- or double-quoted.
  Tag/attribute names and the generator keyword are case-insensitive; CMS product
  values use their upstream spelling. Extra attributes are consumed as complete
  tokens so quoted examples inside another attribute do not become attributes.
- Patterns have a common shape: a meta opening, optional attribute tokens, the
  generator-name/content pair in either order, remaining attributes, and a close.
  Product expressions occupy only the content value. Keep both order alternatives
  equivalent when editing these patterns; tests exercise each ordering.
- Full tags copied into comments, script strings, or quoted examples can still
  match: these are raw HTML regexes, not parsed DOM observations. Duplicate
  attributes and malformed HTML are not interpreted with browser semantics.
  HTML-only findings therefore stay inferred, even for explicit generator text.
- Hidden/customized metadata, unquoted target values, HTML entities in product
  names, and unrecognized generator variants can be missed. WordPress.com-only
  branding, generic CMS cookies, asset directory names, and product names in
  ordinary text are not sufficient for these rules. No asset or API fetching.
- Drupal's direct header can upgrade its HTML inference, retaining both evidence
  entries. Header spelling is case-insensitive; trailing unrelated text and
  lookalike product/domain names are rejected. Header removal causes misses and
  spoofing remains possible, just as with existing identifying-header rules.
- No PHP inference is added for these CMSs. Generator artifacts can survive
  export, caching, or copying; they do not establish a currently running backend.
  An independently observed PHP identification header still works as before.
- Version strings constrain matches but are not extracted. The fixture version
  numbers are synthetic examples, not a claim about latest upstream versions.
- WordPress and Joomla accept only numeric versions optionally followed by a
  numbered `-alpha`, `-beta`, or `-rc` suffix (case-insensitive). Arbitrary suffixes
  such as `-compatible` are rejected. Other development/custom version forms are
  deliberately omitted until supported by a separate reviewed case.

`../cms_test.go` covers positive variants, near misses, HTML limitations, evidence
deduplication, and Drupal direct-state precedence. Three synthetic `.html` files
under `../testdata/coverage/` are also served by CLI integration checks, which
cover both output formats, content-type filtering, error scope, and redirects.

## Catalog audit — 2026-10-06

Reviewed all ten technologies, state assignments, implications, and existing
near-miss coverage. The actionable issues were in Next.js HTML matching:
tag/attribute boundaries and URL authorities being mistaken for paths. Hardened
those two matchers without changing the engine, schema, evidence, or collection
behavior. The [HTML start-tag syntax](https://html.spec.whatwg.org/multipage/syntax.html#start-tags)
informs the conservative token boundaries; this is still not a DOM parser.
HTML inference and the raw-markup limitations above remain intentional.
This source-level audit and authored regressions are not a passing test result
or a claim that every possible false positive has been eliminated.
