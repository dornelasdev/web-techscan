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

## Ruby on Rails addition

Reviewed on 2026-10-07. `csrf-meta-pair` requires two complete HTML meta tags:
`name="csrf-param" content="authenticity_token"` and
`name="csrf-token" content="..."`, with a nonempty, whitespace-free token value.
Both must occur in the final HTML response. The finding is always inferred.

Authored from Rails' [CSRF helper documentation and implementation](https://api.rubyonrails.org/classes/ActionView/Helpers/CsrfHelper.html)
and [Rails 8.0.2 request-forgery protection defaults](https://github.com/rails/rails/blob/v8.0.2/actionpack/lib/action_controller/metal/request_forgery_protection.rb).
The helper emits the two metadata entries when forgery protection is active;
the default parameter is `authenticity_token`. Requiring the pair is our heuristic,
not an upstream uniqueness guarantee. No third-party fingerprint dataset or
Rails source code was imported.

- Each name/content pair must be on the same complete `meta` tag, in either
  attribute order and with quoted target values. Tag/attribute names are
  case-insensitive; marker values and the default parameter are case-sensitive.
  Extra attributes are consumed as whole tokens. Lookalike tags/attributes,
  split attributes, truncated tags, and markers inside other attributes do not
  suffice. Either meta tag alone produces no finding.
- Token content is checked only for a nonempty whitespace-free shape, not its
  encoding, length, validity, or relationship to cookies/forms. It is never
  included in evidence. This is not a CSRF-protection or security-posture check.
- Generic session-cookie names, `X-Request-ID`, `X-Runtime`, Turbo assets, or
  hidden `authenticity_token` fields do not independently identify Rails.
  Cookie names are configurable ([CookieStore](https://github.com/rails/rails/blob/v8.0.2/actionpack/lib/action_dispatch/middleware/session/cookie_store.rb));
  request IDs can come from upstream infrastructure ([RequestId](https://github.com/rails/rails/blob/v8.0.2/actionpack/lib/action_dispatch/middleware/request_id.rb)).
- Apps without these tags, custom CSRF parameter names, API-only responses,
  unquoted/encoded marker values, and runtime-injected tags can be missed.
  Regex matching is not DOM parsing: copied/commented markup or duplicate
  attributes can still yield an inference. Other stacks can reproduce the pair.
- No Ruby/runtime implication, version extraction, cookie replay, form submission,
  asset fetching, or extra requests. Error-page evidence describes that response,
  not a hidden origin application; redirect-hop HTML is not combined.

`../rails_test.go` covers pairs, boundaries, deduplication, weak standalone
signals, and Django coexistence. `../../cli/rails_test.go` uses the synthetic
`../testdata/coverage/rails-csrf.html` fixture for both output formats, content-type
filtering, error scope, redirect isolation, raw-token privacy, and request counts.
Offline catalog checks cover framework grouping and stable metadata.

## Django addition

`csrf-cookie-and-input` requires the exact, case-sensitive cookie name
`csrftoken` and a complete HTML `input` tag with `type="hidden"` and
`name="csrfmiddlewaretoken"`. Both signals must belong to the final response;
neither alone produces a finding. State is always inferred.

Authored from Django's [CSRF documentation](https://docs.djangoproject.com/en/5.2/ref/csrf/),
[5.2 default cookie settings](https://github.com/django/django/blob/5.2/django/conf/global_settings.py),
and [5.2 CSRF template renderer](https://github.com/django/django/blob/5.2/django/template/defaulttags.py).
The pair is our conservative fingerprint policy, not an upstream uniqueness
guarantee. No third-party fingerprint dataset or Django code was imported.

- The HTML matcher requires both attributes on the same complete input tag,
  in either order. Target values must be quoted; other attributes are consumed
  as whole tokens. Tag/attribute names and the hidden type are case-insensitive;
  the field name is case-sensitive. Reject lookalike tags/attributes, split tags,
  truncated tags, quoted attribute examples, and suffix/prefix variations.
- Cookie and form token values are not validated, compared, or reported.
  Cookie values are discarded by fetching; HTML evidence contains no raw token.
  A token value, enclosing form, or POST method is not a matching requirement.
  This is not a check of CSRF protection, token validity, or security posture.
- Keep the existing `sessionid`/`csrftoken` cookie-only negative. Session cookies
  are not required: the default CSRF mechanism can work without a session.
  No generic X-Powered-By, WSGIServer, debug/error text, cookie-value, or header
  fallback is introduced. No Python relationship is added for these potentially
  copied/cached artifacts.
- Customized cookie names, session-backed CSRF, a cookie not set on this
  response, omitted/JS-generated forms, and unquoted/encoded target attributes
  can cause misses. Explicit non-HTML responses do not supply HTML evidence.
- These remain raw HTML patterns, not DOM observations. Comments, script strings,
  or copied full tags can still match with a qualifying cookie name. Duplicate
  attributes and malformed HTML are not interpreted with browser semantics.
  Duplicated valid signals produce one rule evidence entry; redirect signals
  cannot be combined. No form submissions, asset requests, or cookie replay.

`../django_test.go` covers pairs, missing/near-miss signals, same-tag boundaries,
case/order/quote variations, raw-HTML limitations, and mixed-stack isolation.
`../../cli/django_test.go` serves the synthetic `django-csrf.html` fixture with
controlled Set-Cookie headers and checks both formats, content types, error
scope, redirects, raw-value omission, and exact GET-only request counts.
Serving the fixture with plain `python3 -m http.server` alone will not identify
Django because that server does not set the required cookie. Offline catalog
tests check framework grouping/metadata. Tests are user-run, not accuracy metrics.

## Nuxt additions

| Rule | Evidence and state | Source |
| --- | --- | --- |
| `powered-by-header` | Exact X-Powered-By value Nuxt, case-insensitive with outer spaces/tabs: detected | [Nuxt v3.17.5 HTML renderer](https://github.com/nuxt/nuxt/blob/v3.17.5/packages/nuxt/src/core/runtime/nitro/handlers/renderer.ts) |
| `payload-html-markers` | A script with ID __NUXT_DATA__ and a script source containing the /_nuxt/ path segment: inferred | [Nuxt v3.17.5 payload renderer](https://github.com/nuxt/nuxt/blob/v3.17.5/packages/nuxt/src/core/runtime/nitro/utils/renderer/payload.ts), [asset configuration](https://nuxt.com/docs/3.x/api/nuxt-config#buildassetsdir) |

The tagged renderer documents the reviewed response shapes, not an exhaustive
version range. No upstream code or external fingerprint dataset was imported.
Requiring the pair is this project's conservative heuristic, not an assertion
that every Nuxt page exposes both markers.

- Header matching rejects Nuxt.js, version suffixes, lookalikes, and combined
  values. Repeated values produce one evidence entry. A direct header upgrades
  HTML inference while retaining both rules. It works independently of HTML
  content type, including on error responses; spoofing/removal remains possible.
- HTML matching reuses the hardened script-tag and literal URL boundaries of
  the Next.js rules, with Nuxt-specific markers. Attributes must occur on complete
  script opening tags with quoted target values. Marker values and paths are
  case-sensitive; tag/attribute names are not. The two signals may occur on
  separate tags, but must be in the same final response.
- Match HTTP(S), scheme-relative, root-relative, or prefixed-relative asset
  paths, including base-path/CDN variants. A host, query, fragment, stylesheet
  link, plain text, or data-src/data-id attribute alone is insufficient.
- The rule checks the ID and script-source shape, not the payload's JSON
  contents, script MIME type, runtime execution, or asset reachability.
  The sample fixture includes additional upstream attributes for realism;
  they are not additional match conditions.
- Single-app JSON-payload markup is the initial HTML coverage. Legacy inline
  window.__NUXT__ assignments, a __nuxt root alone, multi-app/custom IDs, renamed
  buildAssetsDir, and pages without both scripts can be missed without a header.
  No generic Vue/Nitro/header/cookie fallback or inferred JS/TS/Node.js is added.
- As with existing HTML rules, comments/copied markup can match. This is raw
  text, not a DOM parser or URL resolver: unquoted/encoded markers, dot-segment
  normalization, and browser semantics remain outside scope. Artifacts may be
  static/cached; they do not prove a currently running Nuxt origin server.

`../nuxt_test.go` covers positives, near misses, attribute/URL boundaries,
deduplication, state upgrades, raw-HTML limits, and separation from Next.js.
`../../cli/nuxt_test.go` serves the synthetic `nuxt-payload.html` fixture and
checks both formats, HTML filtering, errors, redirects, privacy, and exact request
paths. Offline catalog tests cover Nuxt's framework grouping and metadata.
Tests are authored for user execution, not a measured accuracy claim.

## Server-banner hardening — 2026-10-07

Replaced the permissive nginx/Apache version and trailing-text patterns with
conservative complete-banner shapes. IIS's existing matcher is unchanged.
The rules retain their IDs, detected states, header-only evidence, and warnings
that the exposed server may be an intermediary. Catalog size is unchanged.

- nginx accepts its product name, an optional numeric dot-separated version,
  and at most one whitespace-separated parenthesized build/OS comment.
  [server_tokens](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens)
  documents version suppression and build-name emission.
- Apache accepts its product name, an optional numeric dot-separated version
  with optional `-dev`, and whitespace-separated comments or module/version
  tokens. Preserve product-only, major, minor, minimal, OS, and full-style
  banners from [ServerTokens](https://httpd.apache.org/docs/2.4/mod/core.html#servertokens).
  The `-dev` suffix follows the upstream
  [release definitions](https://github.com/apache/httpd/blob/2.4.x/include/ap_release.h).
- Comments in these two rules allow printable ASCII and tabs, but not nested
  parentheses or backslash escapes. Apache module names start with an ASCII
  letter and continue with letters/digits/dot/underscore/plus/hyphen; their
  required version starts alphanumeric and additionally permits tilde.
  Module text is accepted only as banner structure, not as independent evidence
  of a language or another technology.
- IIS still accepts Microsoft-IIS with an optional numeric dot-separated
  version and outer spaces/tabs; no extra comments or module text.
- Reject empty version components, arbitrary product-version suffixes,
  free-form trailing words, broken comments, controls, and comma-combined
  banners. Values from repeated header fields are inspected independently:
  valid values survive unrelated/invalid siblings, duplicates yield one rule
  evidence entry, and distinct servers may coexist without implying topology.
- This is deliberately not a general HTTP Server-field parser. Custom version
  suffixes (except Apache `-dev`), non-ASCII/nested/escaped comments, unusual
  module tokens, and hidden/rewritten banners can be missed. Generic text or
  default error-page footers are not fallback evidence. Header spoofing remains
  possible; stricter syntax is not proof of the origin or measured accuracy.

`../servers_test.go` adds positive/negative boundary, wrong-source, repeated-field,
and evidence checks. `../../cli/servers_test.go` covers all three servers in both
formats, HTML/non-HTML and error responses, final-response isolation, raw-value
omission, absence of automatic language inference, and bounded request counts.
These are authored regressions for user execution, not passing-test claims.

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

## CDN/edge additions — reviewed 2026-10-07

| Technology | Rule | Evidence and state | Source |
| --- | --- | --- | --- |
| Cloudflare | `ray-header` | CF-Ray with a 16-hex-digit ID and three-letter location suffix: detected | [Cloudflare response headers and Ray format](https://developers.cloudflare.com/fundamentals/reference/http-headers/) |
| Amazon CloudFront | `via-header` | Standalone Via value with HTTP version, alphanumeric cloudfront.net host, and CloudFront comment: detected | [CloudFront response header behavior](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html) |

These are intentionally narrow first rules, authored from documented response
shapes rather than imported from another fingerprint dataset. Header names and
these patterns are case-insensitive; outer spaces/tabs are accepted. Both values
are anchored to reject lookalike domains, product suffixes, and unrelated text.

- The Ray length restriction follows the documented example, not a promise that
  all future Ray formats have that length. No-suffix or changed formats are missed.
- CloudFront accepts a numeric HTTP version (such as `1.1` or `2`), a single
  alphanumeric hostname label, and the exact `(CloudFront)` product comment.
  Repeated header fields are examined independently. Comma-combined Via chains
  are deliberately omitted; this is not a general Via parser, and substring
  matching could misread quoted comments as proxy entries.
- Server names, CF-Cache-Status, X-Cache, X-Amz-Cf-Id, and X-Amz-Cf-Pop do not
  independently match these first rules. Additional signals need their own review.
- These are observations on the final response, including non-HTML/error pages.
  Headers can be copied, cached, removed, or spoofed. Multiple provider findings
  do not establish their order or the live network topology. Absence is not proof
  that a provider is unused.
- No WAF, bot-protection, load-balancer, cache-hit, origin-hosting, or language
  inference is made. There are no implication edges from these providers.
  Raw Ray IDs and Via values are not included in evidence or output.
- No DNS enrichment, special probes, asset fetching, or collection changes.

`../cdn_test.go` covers valid shapes, near misses, unsupported signals, repeated
values, mixed stacks, and absence of extra inferences. CLI tests exercise both
output formats, non-HTML responses, error scope, redirect isolation, and request
counts using local servers. Catalog tests cover the new category and offline
listing. The user runs the tests; these additions are not measured accuracy claims.

## Load-balancer additions — reviewed 2026-10-07

| Technology | Rule | Evidence and state | Source |
| --- | --- | --- | --- |
| AWS Application Load Balancer | `stickiness-cookie-pair` | Both AWSALB and AWSALBCORS cookie names: inferred | [ALB stickiness](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html) |
| AWS Classic Load Balancer | `stickiness-cookie-pair` | Both AWSELB and AWSELBCORS cookie names: inferred | [Classic Load Balancer stickiness](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-sticky-sessions.html) |

AWS documents these names for load-balancer stickiness and its CORS companion
cookies. Requiring the pair is our conservative fingerprint policy, not a claim
that every deployment or response must expose both. In particular, the Classic
documentation describes its companion cookie in the CORS context. Single-cookie
responses and disabled/other stickiness configurations can be missed.

- Match exact, case-sensitive names from the final response only. Duplicate
  names do not create extra evidence; pairs cannot be assembled across redirects.
- Cookie names are indirect evidence and can be copied or chosen by applications.
  Findings remain inferred even with both names. No cookie values, payload shapes,
  expiration, or cookie attributes are evaluated. Cookie values are discarded by
  fetching and never appear in evidence; the rule description names the pair.
- Application-based ALB cookies, target-group cookies, generic affinity names,
  and single names are deliberately outside this first batch. There is no NLB
  detection or inference from an AWS/CDN identity or a generic server header.
- No implications are added: these findings do not establish WAF usage, backend
  language, backend count, routing behavior, network order, or hidden origin.
  Both load-balancer findings may coexist if both pairs appear; that does not
  reconstruct the infrastructure. No additional requests or cookie replay.

`../loadbalancer_test.go` covers paired-name inference, near misses, wrong signal
locations, mixed stacks, and evidence isolation. CLI tests exercise real Set-Cookie
extraction, value-only decoys, duplicate names, split/redirect-only pairs, privacy,
error responses, both output formats, and no cookie replay using local servers.
Catalog tests include category ordering and offline listing. Tests are authored
for user execution, not evidence of real-world accuracy.

## WAF addition — reviewed 2026-10-07

| Technology | Rule | Evidence and state | Source |
| --- | --- | --- | --- |
| AWS WAF | `action-header` | X-Amzn-Waf-Action value challenge or captcha: detected | [AWS WAF action behavior](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html) |

AWS documents `challenge` with HTTP 202 and `captcha` with HTTP 405. The rule
matches the explicit header, not the status. Header names are case-insensitive;
values must be the documented lowercase tokens, with optional outer spaces/tabs.
Other actions, case variants, prefixes/suffixes, and comma-combined values are
not accepted. Repeated matching fields yield one evidence entry.

Allowed traffic or ordinary blocks may expose no such header. AWS/CDN identity,
load-balancer cookies, generic status codes, and challenge text do not establish
WAF presence. No implication edges are added. Headers can be spoofed or copied;
`detected` remains observed response evidence, not a guarantee about the origin,
protection quality, or rule configuration.

No status matcher, collection changes, script execution, CAPTCHA solving, special
probes, or bypass attempts. Evidence records the rule and canonical header name,
not raw values. Existing response-scope semantics remain: a 202 challenge is a
`final_response`, which does not prove the origin application was reached.

Detector tests cover exact values, near misses, deduplication, wrong locations,
and independent WAF evidence in a mixed stack. Local CLI cases cover both output
formats, status-only negatives, non-HTML responses, redirects, privacy, and request
counts. Catalog tests cover WAF grouping and offline listing. Tests are user-run.
