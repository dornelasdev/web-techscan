# Fingerprints

[README](../README.md) · [Usage](usage.md) · [Policies](policies.md)

Rules are embedded in the binary. Use `webscan --techs` to list its catalog.
The development catalog contains 19 technologies; v0.2.0 contains 10.

## Evidence

- `detected`: a distinctive direct signal matches a rule.
- `inferred`: an indirect signal or supported relationship matches a rule.
- All conditions in a rule must match. Any matching rule can identify its technology.
- Page rules use only the final response. Redirect signals are not combined.
- Asset rules require `--assets` and all markers within one accepted body.
- Direct detections take precedence while retaining other supporting evidence.
- Evidence records rule IDs and signal locations; asset evidence includes its URL.
- Versions constrain some patterns but are not extracted or reported.
- Laravel → PHP is the only configured language relationship.

Header names are case-insensitive. Cookie names and JS/CSS identifiers are
case-sensitive. HTML rules require complete tags with quoted target values;
tag/attribute names are case-insensitive. Exact matching details remain in the
[JSON catalogs](../internal/detect/fingerprints).

Raw HTML, JS, and CSS patterns can match copied/commented examples. They do not
parse DOM/CSS/JS, interpret duplicate attributes with browser semantics, or
establish runtime use. Headers can be removed or spoofed.
Missing signals do not prove absence; exposed signals do not identify a hidden
origin or the complete stack.

Rules and synthetic fixtures are authored for this project. No external
fingerprint dataset or application bundle is imported. Review dates below
record existing source reviews; this documentation rework did not revalidate
upstream behavior. Branch links may change.

## Web servers

Category: `web_server`. All three use `server-header`, with `detected` state.
Reviewed 2026-10-05; banner hardening reviewed 2026-10-07.

| Technology | Accepted Server value |
| --- | --- |
| nginx | Product token; optional numeric dot-separated version; at most one whitespace-separated build/OS comment. |
| Apache HTTP Server | Product token; optional numeric dot-separated version and `-dev`; whitespace-separated comments or module/version tokens. |
| Microsoft IIS | Microsoft-IIS token; optional numeric dot-separated version. |

Product spelling is case-insensitive; outer spaces/tabs are accepted. nginx and
Apache comments permit printable ASCII/tabs, excluding nested parentheses and
backslash escapes. Apache module names start with an ASCII letter and permit
letters, digits, dot, underscore, plus, and hyphen; module versions start
alphanumeric and additionally permit tilde.

Reject malformed versions, unrelated trailing words, broken comments, controls,
and comma-combined banners. Repeated header values are inspected independently;
duplicates yield one rule evidence entry. Custom suffixes/comments may be missed.
Apache-Coyote, nginx-proxy, generic error text, and language module tokens do
not create these server or language findings. Server identity may be an intermediary.

Sources: [nginx server_tokens](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens),
[Apache ServerTokens](https://httpd.apache.org/docs/2.4/mod/core.html#servertokens),
[Apache release definitions](https://github.com/apache/httpd/blob/2.4.x/include/ap_release.h),
[IIS response headers](https://techcommunity.microsoft.com/blog/iis-support-blog/remove-unwanted-http-response-headers/369710).

## Frameworks

Category: `framework`.

### Express

`powered-by-header`: X-Powered-By equals Express, case-insensitive with outer
spaces/tabs. State: `detected`. No language/runtime implication.

Reviewed 2026-10-05. Sources:
[response implementation](https://github.com/expressjs/express/blob/master/lib/application.js),
[header configuration](https://expressjs.com/en/advanced/best-practice-security/#reduce-fingerprinting).

### Next.js

| Rule | Required evidence | State |
| --- | --- | --- |
| `powered-by-header` | X-Powered-By equals Next.js, case-insensitive with outer spaces/tabs. | detected |
| `pages-html-markers` | A script ID of __NEXT_DATA__ and a script URL path containing /_next/static/ with a nonempty remainder. | inferred |
| `asset-build-manifest` | self.__BUILD_MANIFEST assignment plus its guarded __BUILD_MANIFEST_CB invocation in one JS capture. | inferred |
| `asset-ssg-manifest` | self.__SSG_MANIFEST Set assignment plus its guarded __SSG_MANIFEST_CB invocation in one JS capture. | inferred |

HTML markers must occur as real attributes on complete script opening tags.
Allow quoted values, either quote style, changed attribute order, and extra
attribute tokens. URL patterns support HTTP(S), scheme-relative, root-relative,
and prefixed relative paths with CDN/base-path variants. Queries/fragments may
follow valid paths; authorities, queries, and fragments cannot supply the marker.
These are literal URL patterns: no URL resolution, dot-segment normalization,
entity/percent decoding, backslashes, or unquoted target values.

The build manifest accepts an object or anonymous-function expression start,
including one wrapping parenthesis. SSG accepts `new Set(` or empty `new Set;`.
Allow whitespace around JS dots/operators. Bracket notation, renamed globals,
other serializers, filename-only clues, inline scripts, CSS, and split-file
markers are outside these asset rules.

HTML coverage targets the Pages Router shape. App Router or customized output
can be missed. Static exports and cached artifacts can match; no Node.js,
JavaScript, or TypeScript backend inference is made. A header match upgrades
Next.js while preserving HTML/asset evidence.

HTML/header review: 2026-10-05; HTML boundaries: 2026-10-06; asset review: 2026-10-10.
Sources: [response implementation](https://github.com/vercel/next.js/blob/canary/packages/next/src/server/send-payload.ts),
[header configuration](https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader),
[Pages document](https://github.com/vercel/next.js/blob/canary/packages/next/src/pages/_document.tsx),
[asset prefixes](https://nextjs.org/docs/app/api-reference/config/next-config-js/assetPrefix),
[v15.5.0 build manifest generator](https://github.com/vercel/next.js/blob/v15.5.0/packages/next/src/build/webpack/plugins/build-manifest-plugin.ts#L312-L323),
[SSG manifest writer](https://github.com/vercel/next.js/blob/v15.5.0/packages/next/src/build/index.ts#L538-L566),
[empty SSG manifest](https://github.com/vercel/next.js/blob/v15.5.0/packages/next/src/build/webpack/plugins/build-manifest-plugin.ts#L27-L30),
[MIT license](https://github.com/vercel/next.js/blob/canary/license.md).

### Laravel

`default-cookie-pair`: exact `laravel_session` and `XSRF-TOKEN` cookie names on
the final response. State: `inferred`. Implies PHP, preserving Laravel as the source.

Session names are configurable and commonly derive from the app name. Custom
names are missed. Either name alone, generic *_session names, and PHPSESSID
do not identify Laravel. The pair is a heuristic, not a uniqueness guarantee.

Reviewed 2026-10-05. Sources:
[session configuration](https://github.com/laravel/framework/blob/13.x/config/session.php),
[CSRF cookie](https://laravel.com/framework/docs/13.x/csrf#x-xsrf-token).

### Nuxt

| Rule | Required evidence | State |
| --- | --- | --- |
| `powered-by-header` | X-Powered-By equals Nuxt, case-insensitive with outer spaces/tabs. | detected |
| `payload-html-markers` | Script ID __NUXT_DATA__ and a script path containing /_nuxt/ in the final HTML. | inferred |

HTML follows the quoted-attribute and literal-path boundaries described for
Next.js. Markers may be on separate tags in the same response. Payload JSON,
script MIME, and asset reachability are not checked. Nuxt.js/version-suffixed
headers, a __nuxt root alone, legacy window.__NUXT__, custom/multi-app IDs, and
renamed build paths are outside coverage. No Vue/Nitro/runtime/language implication.

Sources: [v3.17.5 renderer](https://github.com/nuxt/nuxt/blob/v3.17.5/packages/nuxt/src/core/runtime/nitro/handlers/renderer.ts),
[payload renderer](https://github.com/nuxt/nuxt/blob/v3.17.5/packages/nuxt/src/core/runtime/nitro/utils/renderer/payload.ts),
[asset configuration](https://nuxt.com/docs/3.x/api/nuxt-config#buildassetsdir).
The tag records the reviewed shape, not an exhaustive supported version range.

### Django

`csrf-cookie-and-input`: exact `csrftoken` cookie name plus a complete input tag
containing quoted `type="hidden"` and `name="csrfmiddlewaretoken"` values on
the final response. State: `inferred`.

Both attributes must be on the same tag, in either order. The hidden type is
case-insensitive; the field/cookie names are case-sensitive. No token value,
form, POST method, or session cookie is required. Token/cookie values are not
compared or reported. The sessionid/csrftoken cookie pair alone does not match.

Custom cookie names, session-backed CSRF, missing Set-Cookie, JS-generated forms,
and unquoted/encoded marker values can be missed. No Python implication, debug
text fallback, token validation, or security-posture assessment.

Sources: [Django 5.2 CSRF](https://docs.djangoproject.com/en/5.2/ref/csrf/),
[default settings](https://github.com/django/django/blob/5.2/django/conf/global_settings.py),
[template renderer](https://github.com/django/django/blob/5.2/django/template/defaulttags.py).

### Ruby on Rails

`csrf-meta-pair`: complete meta tags for `csrf-param` with content
`authenticity_token` and `csrf-token` with nonempty whitespace-free content in
the final HTML. State: `inferred`.

Each name/content pair must be on one tag, in either order, with quoted values.
Marker values are case-sensitive. Tokens are neither validated nor reported.
Either tag alone, generic session cookies, X-Request-ID, X-Runtime, Turbo assets,
and hidden authenticity_token fields do not independently match. Custom CSRF
parameters, API-only responses, omitted tags, and runtime-injected tags can be missed.
No Ruby implication or security-posture assessment.

Reviewed 2026-10-07. Sources:
[CSRF helper](https://api.rubyonrails.org/classes/ActionView/Helpers/CsrfHelper.html),
[8.0.2 defaults](https://github.com/rails/rails/blob/v8.0.2/actionpack/lib/action_controller/metal/request_forgery_protection.rb),
[configurable cookies](https://github.com/rails/rails/blob/v8.0.2/actionpack/lib/action_dispatch/middleware/session/cookie_store.rb),
[request IDs](https://github.com/rails/rails/blob/v8.0.2/actionpack/lib/action_dispatch/middleware/request_id.rb).

## UI frameworks

### Bootstrap

Category: `ui_framework`. Rule: `asset-css-banner-and-buttons`. State: `inferred`.
Requires both markers in one CSS capture:

- A closed `/*!` banner starting with Bootstrap, a stable `v5.2.x`/`v5.3.x` version,
  and the exact `https://getbootstrap.com/` project URL.
- A standalone `.btn` block declaring `--bs-btn-padding-x` before
  `padding: var(--bs-btn-padding-y) var(--bs-btn-padding-x)` in the same closed block.

Allow CSS whitespace, intervening declarations, and custom values. Matching is
case-sensitive. Readable/compact styles retaining this shape are supported.
Colors and dimensions do not identify Bootstrap.

Banner-only, filename-only, generic `.btn` classes, a bare `--bs-` prefix, and
split-file/block markers do not match. Stripped banners, older/prerelease/other
version families, changed prefixes/selectors, escaped identifiers, reordered
declarations, and component-only grid/reboot builds can be missed. No separate
RTL coverage claim. Forks retaining the markers can match.

The rule does not establish applied styles, Bootstrap JS use, or a backend.
Same-origin and asset budgets apply; off-origin CDN stylesheets are not fetched.

Reviewed 2026-10-10. Sources:
[v5.2.3 CSS](https://github.com/twbs/bootstrap/blob/v5.2.3/dist/css/bootstrap.css),
[v5.3.3 CSS](https://github.com/twbs/bootstrap/blob/v5.3.3/dist/css/bootstrap.css),
[button variables](https://getbootstrap.com/docs/5.3/components/buttons/#variables),
[prefix customization](https://getbootstrap.com/docs/5.3/customize/css-variables/#prefix),
[MIT license](https://github.com/twbs/bootstrap/blob/v5.3.3/LICENSE).

## CMSs

Category: `cms`. Reviewed 2026-10-06.

| Technology | Rule | Required evidence | State |
| --- | --- | --- | --- |
| WordPress | generator-meta | Complete generator meta tag naming WordPress, with optional numeric version. | inferred |
| Drupal | generator-meta | Complete generator meta tag naming Drupal, with numeric version and optional official-site URL. | inferred |
| Drupal | generator-header | Anchored X-Generator value naming Drupal, with numeric version and optional official-site URL. | detected |
| Joomla | generator-meta | Complete generator meta tag with Joomla's standard product phrase and optional version. | inferred |

Meta name/content must occur on the same tag, in either order, with quoted
target values. Tag/attribute names and the generator keyword are case-insensitive;
product values use upstream spelling. WordPress/Joomla versions permit numbered
alpha/beta/rc suffixes, not arbitrary suffixes such as -compatible.

Hidden/customized metadata, unquoted values, entities in product names, and
unsupported generator variants can be missed. Product names in ordinary text,
WordPress.com branding, generic cookies, and asset directory names do not match.
Drupal's header can upgrade HTML inference while retaining both entries.
No PHP implication from CMS artifacts.

Sources: [WordPress generator](https://developer.wordpress.org/reference/functions/get_the_generator/),
[Drupal metadata](https://api.drupal.org/api/drupal/core%21lib%21Drupal%21Core%21Render%21BareHtmlPageRenderer.php/11.x),
[Drupal response subscriber](https://github.com/drupal/drupal/blob/11.x/core/lib/Drupal/Core/EventSubscriber/ResponseGeneratorSubscriber.php),
[Joomla site metadata](https://github.com/joomla/joomla-cms/blob/5.4-dev/libraries/src/Application/SiteApplication.php),
[Joomla meta renderer](https://github.com/joomla/joomla-cms/blob/5.4-dev/libraries/src/Document/Renderer/Html/MetasRenderer.php).

## Languages

### PHP

Category: `language`. `powered-by-header` matches PHP with an optional
digit-starting version suffix in X-Powered-By, case-insensitive with outer
spaces/tabs. State: `detected`. Laravel also implies PHP as `inferred`; the
header upgrades it while preserving the relationship evidence.

PHPSESSID alone and PHP text in Apache module banners do not match.
No languages are inferred from web-server implementation languages or client JS.

Reviewed 2026-10-05. Source:
[expose_php](https://www.php.net/manual/en/ini.core.php#ini.expose-php).

## CDN and edge providers

Category: `cdn`. Reviewed 2026-10-07. Headers and product patterns are
case-insensitive; outer spaces/tabs are accepted.

| Technology | Rule | Required evidence | State |
| --- | --- | --- | --- |
| Cloudflare | ray-header | CF-Ray: 16 hex digits, a hyphen, and a three-letter location suffix. | detected |
| Amazon CloudFront | via-header | Standalone Via: numeric HTTP version, one alphanumeric cloudfront.net host label, and (CloudFront). | detected |

Repeated fields are inspected independently. Comma-combined Via chains and
other Ray formats are outside coverage. Server names, CF-Cache-Status, X-Cache,
X-Amz-Cf-Id, and X-Amz-Cf-Pop do not independently match.
Provider findings do not establish WAF/LB features, cache hits, origin hosting,
or provider ordering. Amazon S3 has no fingerprint in this catalog.

Sources: [Cloudflare response headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/),
[CloudFront response behavior](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html).

## Load balancers

Category: `load_balancer`. Reviewed 2026-10-07.

| Technology | Rule | Required cookie names | State |
| --- | --- | --- | --- |
| AWS Application Load Balancer | stickiness-cookie-pair | AWSALB and AWSALBCORS | inferred |
| AWS Classic Load Balancer | stickiness-cookie-pair | AWSELB and AWSELBCORS | inferred |

Require exact case-sensitive pairs on the final response. Single cookies,
cross-redirect pairs, generic affinity names, application-based/target-group
ALB cookies, disabled stickiness, and other configurations can be missed.
No cookie-value/attribute checks or NLB detection. Names are reproducible by
applications. Findings do not establish backend counts, routing, WAF use, or topology.

Sources: [ALB stickiness](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html),
[Classic LB stickiness](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-sticky-sessions.html).

## WAFs

### AWS WAF

Category: `waf`. `action-header` requires X-Amzn-Waf-Action with exact lowercase
`challenge` or `captcha`, allowing outer spaces/tabs. State: `detected`.

Status is not a matcher. AWS documents 202 for challenge and 405 for captcha;
status alone, AWS identity, generic cookies, and challenge text do not match.
Other actions, case variants, and combined values are rejected. Allowed traffic
or ordinary blocks can expose no action header. Findings do not assess protection
quality or prove which rules are enabled. No challenge execution or bypass requests.

Reviewed 2026-10-07. Source:
[CAPTCHA and challenge actions](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html).

## Authoring and checks

- [Fingerprint format](../internal/detect/fingerprints/README.md).
- [Synthetic fixtures](../internal/detect/testdata/coverage).
- [Development checks](usage.md#development-checks).
- [HTML start-tag syntax](https://html.spec.whatwg.org/multipage/syntax.html#start-tags), used for conservative attribute boundaries.

Tests cover positive and near-miss rules, partial/split signals, source isolation,
inference upgrades, deterministic evidence, redirects, mixed application/network
stacks, optional asset failures, and privacy. Multiple technologies in a synthetic
fixture do not model a real network topology. Tests are not accuracy percentages.
