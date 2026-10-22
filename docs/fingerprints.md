# Fingerprints

[README](../README.md) · [Usage](usage.md) · [Policies](policies.md)

Rules are embedded in the binary. Use `webscan --techs` to list its catalog.
The development catalog contains 38 technologies across ten categories.
The v0.3.0 release baseline contains 23.

## Evidence

- `detected`: a distinctive direct signal matches a rule.
- `inferred`: an indirect signal or supported relationship matches a rule.
- All conditions in a rule must match. Any matching rule can identify its technology.
- Page rules use only the final response. Redirect signals are not combined.
- Optional status ranges constrain page rules using the final HTTP status;
  a status code alone never identifies a technology.
- Asset rules require `--assets` and all markers within one accepted body.
- Direct detections take precedence while retaining other supporting evidence.
- Evidence records rule IDs and signal locations; asset evidence includes its URL.
- Versions constrain some patterns but are not extracted or reported.
- Language relationships: Laravel → PHP, Django → Python, Rails → Ruby.

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
identify provenance baselines, not exhaustive version coverage. Branch links may change.

## Web servers

Category: `web_server`. All eleven have a detected `server-header` rule.
Tomcat additionally has a header rule and status-gated HTML inference.
Caddy additionally has a standalone Via-header inference rule.
nginx/Apache/IIS reviewed 2026-10-05; banner hardening reviewed 2026-10-07.
Jetty, Kestrel and Tomcat reviewed 2026-10-18.

| Technology | Accepted Server value |
| --- | --- |
| nginx | Product token; optional numeric dot-separated version; at most one whitespace-separated build/OS comment. |
| Apache HTTP Server | Product token; optional numeric dot-separated version and `-dev`; whitespace-separated comments. Module/version tokens require an Apache version. |
| Microsoft IIS | Microsoft-IIS token; optional numeric dot-separated version. |
| Caddy | Complete unversioned `Caddy` token; ASCII case-insensitive. |
| Gunicorn | Complete unversioned `gunicorn` token; ASCII case-insensitive. |
| Jetty | `Jetty(major.minor.patch)`; optional `.v` followed by eight digits inside the parentheses. |
| Kestrel | Complete unversioned `Kestrel` token; ASCII case-insensitive. |
| LiteSpeed | Bare `LiteSpeed`, or `LiteSpeed/major.minor.patch Open`. Family identity only. |
| OpenResty | Bare `openresty`, or `openresty/major.minor.patch.release`; ASCII case-insensitive. |
| Apache Tomcat | `Apache Tomcat`; optional `/major.minor.patch`. |
| Uvicorn | Complete unversioned `uvicorn` token; ASCII case-insensitive. |

Product spelling is case-insensitive; outer spaces/tabs are accepted. nginx and
Apache comments permit printable ASCII/tabs, excluding nested parentheses and
backslash escapes. Apache module names start with an ASCII letter and permit
letters, digits, dot, underscore, plus, and hyphen; module versions start
alphanumeric and additionally permit tilde.
Without an Apache version, only comments may follow its product token.
`Apache Tomcat/version` is not an Apache HTTP Server module combination.

Reject malformed versions, unrelated trailing words, broken comments, controls,
and comma-combined banners. Repeated header values are inspected independently;
duplicates yield one rule evidence entry. Custom suffixes/comments may be missed.
Apache-Coyote, nginx-proxy, generic error text, and language module tokens do
not create these server or language findings. Server identity may be an intermediary.

Sources: [nginx server_tokens](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens),
[Apache ServerTokens](https://httpd.apache.org/docs/2.4/mod/core.html#servertokens),
[Apache release definitions](https://github.com/apache/httpd/blob/2.4.x/include/ap_release.h),
[IIS response headers](https://techcommunity.microsoft.com/blog/iis-support-blog/remove-unwanted-http-response-headers/369710).

### Caddy

| Rule | Required final-response evidence | State |
| --- | --- | --- |
| `server-header` | Complete unversioned `Caddy` Server value. | detected |
| `via-header` | Standalone Via value: `1.0`, `1.1`, `2.0` or `3.0`, whitespace, and `Caddy`. | inferred |

Allow ASCII product-name case variations, outer spaces/tabs, and spaces/tabs
between the Via protocol and recipient. Reject version suffixes, trailers,
comments, combined lists, ports, host suffixes, controls and Unicode lookalikes.
No explicit `HTTP/` prefix or other protocol forms. Repeated values are checked
independently and yield one evidence entry per rule. Server evidence upgrades
Via inference to detected while retaining both rules. No fallback from HTML,
cookies, other headers, redirect hops, or asset headers/bodies.

Reviewed Caddy 2.8.4/2.10.2 defaults emit `Server: Caddy`. In the reviewed
2.11.0/2.11.7 normal reverse-proxy response path, Caddy removes its own Server
header and adds Via instead; an upstream Server header can still be forwarded.
Via names can be arbitrary recipient pseudonyms, so the rule is inferred.
Its numeric prefix describes HTTP, not the Caddy version. Neither rule proves
the software's authenticity, backend language, hidden origin or proxy topology.
No Go/framework, CDN, WAF or load-balancer implication.

Customized/removed headers, intermediaries, combined Via lists and comments
can cause misses. Spoofed Server/Via values or another recipient named Caddy
can mislead. No probes or additional requests.

Reviewed 2026-10-19 against pinned sources:
[2.8.4 identity](https://github.com/caddyserver/caddy/blob/v2.8.4/modules/caddyhttp/server.go),
[2.10.2 identity](https://github.com/caddyserver/caddy/blob/v2.10.2/modules/caddyhttp/server.go),
[2.11.7 identity](https://github.com/caddyserver/caddy/blob/v2.11.7/modules/caddyhttp/server.go),
[2.11.0 proxy response](https://github.com/caddyserver/caddy/blob/v2.11.0/modules/caddyhttp/reverseproxy/reverseproxy.go),
[2.11.7 proxy response](https://github.com/caddyserver/caddy/blob/v2.11.7/modules/caddyhttp/reverseproxy/reverseproxy.go),
[header configuration](https://caddyserver.com/docs/caddyfile/directives/header),
[Via semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3).
Own-authored rules and tests; no upstream code or fingerprint dataset imported.
These are provenance baselines, not an exhaustive supported-version range.

### Uvicorn and Gunicorn

Each uses `server-header`: a complete unversioned product token in the final
response's Server header, state `detected`. Allow ASCII case variations and
outer spaces/tabs. Reject versions, comments, trailers, combined values,
internal whitespace, controls and Unicode lookalikes. Repeated matching values
yield one evidence entry. No alternate-header, HTML, cookie, redirect or asset
fallback; no version extraction or additional requests.

Reviewed Uvicorn defaults emit `Server: uvicorn`. `--no-server-header` disables
the default; custom Server headers can replace it. Reviewed Gunicorn WSGI
responses use the unversioned `SERVER` identity (`gunicorn`), not the versioned
`SERVER_SOFTWARE` environment value. Versioned/custom banners are not covered.
Removed, replaced or intermediary headers can cause misses; spoofed values can
mislead. Neither finding identifies a hidden origin, Python, Flask, FastAPI,
another framework, or the other server. Independent page markers can still
identify frameworks alongside either server.

Reviewed 2026-10-20 against pinned sources:
[Uvicorn 0.35.0 configuration](https://github.com/encode/uvicorn/blob/0.35.0/uvicorn/config.py),
[0.54.0 configuration](https://github.com/Kludex/uvicorn/blob/0.54.0/uvicorn/config.py),
[0.54.0 response headers](https://github.com/Kludex/uvicorn/blob/0.54.0/uvicorn/protocols/http/h11_impl.py),
[header settings](https://uvicorn.dev/settings/),
[Gunicorn 23.0.0 identity](https://github.com/benoitc/gunicorn/blob/23.0.0/gunicorn/__init__.py),
[23.0.0 response headers](https://github.com/benoitc/gunicorn/blob/23.0.0/gunicorn/http/wsgi.py),
[26.2.2 identity](https://github.com/benoitc/gunicorn/blob/26.2.2/gunicorn/__init__.py),
[26.2.2 response headers](https://github.com/benoitc/gunicorn/blob/26.2.2/gunicorn/http/wsgi.py).
These are provenance baselines, not an exhaustive supported-version range.
Own-authored rules/tests; no upstream code or fingerprint dataset imported.

### Jetty boundaries

Examples: `Jetty(12.0.16)` and `Jetty(9.4.57.v20241219)`. Require three numeric
version components; the optional build suffix uses lowercase `v` and eight
digits, without calendar-date validation. Product spelling is case-insensitive;
only outer spaces/tabs are allowed. Versions constrain matching but are not reported.

Bare `Jetty`, slash-style banners, prerelease/custom suffixes, internal spaces,
comments and comma-combined values do not match. No fallback from error-page
text, X-Powered-By, JSESSIONID or asset contents. An omitted/customized Server
header may be missed. A finding does not imply Java, a JVM runtime finding,
an application framework, or a hidden origin's identity.

Reviewed upstream banner construction and configurable header emission:
[12.0.16 HttpConfiguration](https://github.com/jetty/jetty.project/blob/jetty-12.0.16/jetty-core/jetty-server/src/main/java/org/eclipse/jetty/server/HttpConfiguration.java),
[9.4.57 HttpConfiguration](https://github.com/jetty/jetty.project/blob/jetty-9.4.57.v20241219/jetty-server/src/main/java/org/eclipse/jetty/server/HttpConfiguration.java),
[9.4.57 version resolution](https://github.com/jetty/jetty.project/blob/jetty-9.4.57.v20241219/jetty-util/src/main/java/org/eclipse/jetty/util/Jetty.java).
These are provenance baselines, not an exhaustive supported-version range.

### Kestrel

`server-header`: complete `Kestrel` value in the final response's Server header.
State: `detected`. Allow ASCII case variations and outer spaces/tabs only.
Reject version suffixes, comments, trailers, comma-combined values, internal
whitespace and Unicode lookalikes. Repeated matching values yield one evidence.
No fallback from HTML, cookies, alternate headers, redirects or asset headers.

The reviewed default banner is unversioned. It can be disabled or overridden,
and an intermediary can hide, replace or expose it. A finding does not establish
the hidden origin, ASP.NET Core, C#, another .NET language, or a runtime/version
finding. No additional requests or security-posture assessment.

Reviewed 2026-10-18 against pinned 8.0.0/10.0.0 sources:
[8.0.0 identity](https://github.com/dotnet/aspnetcore/blob/v8.0.0/src/Servers/Kestrel/Core/src/Internal/Infrastructure/Constants.cs),
[10.0.0 identity](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Servers/Kestrel/Core/src/Internal/Infrastructure/Constants.cs),
[8.0.0 header emission](https://github.com/dotnet/aspnetcore/blob/v8.0.0/src/Servers/Kestrel/Core/src/Internal/Http/HttpProtocol.cs),
[10.0.0 header emission](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Servers/Kestrel/Core/src/Internal/Http/HttpProtocol.cs),
[8.0.0 configuration](https://github.com/dotnet/aspnetcore/blob/v8.0.0/src/Servers/Kestrel/Core/src/KestrelServerOptions.cs),
[10.0.0 configuration](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Servers/Kestrel/Core/src/KestrelServerOptions.cs).
These are provenance baselines, not an exhaustive supported-version range.

### LiteSpeed

`server-header`, state `detected`: final-page Server value of `LiteSpeed` or
`LiteSpeed/major.minor.patch Open`. Product name and Open suffix accept ASCII
case variations. Allow outer spaces/tabs and spaces/tabs before Open; numeric
components use ASCII digits. Repeated bare/detailed values yield one rule evidence.
The initial versioned form requires exactly three numeric components; other
version formats remain unsupported. No version extraction or edition field.

The bare banner does not distinguish Enterprise from OpenLiteSpeed. Reviewed
OpenLiteSpeed sources use the bare name when details are hidden and append a
version plus Open when shown. This catalog reports one LiteSpeed-family finding,
not separate Enterprise/Open findings or a hidden origin's identity. Headers
can be hidden, replaced or spoofed; absence does not establish absence of LiteSpeed.

Reject standalone `OpenLiteSpeed`, `LiteSpeed Open`, version-only suffixes,
Enterprise/custom suffixes, comments, combined values, controls and lookalikes.
Unreviewed banners can miss. No fallback from X-Turbo-Charged-By, cache headers,
cookies, HTML, redirects or assets. No PHP/framework/cache/WAF implications,
probes or additional requests. Independent language/framework rules still apply.

Reviewed 2026-10-21 against official configuration documentation and pinned sources:
[Server Signature settings](https://download.litespeedtech.com/docs/webserver/config/general#showVersionNumber),
[OpenLiteSpeed 1.8.4 identity](https://github.com/litespeedtech/openlitespeed/blob/v1.8.4/src/http/httpserverversion.cpp),
[1.9.3 identity](https://github.com/litespeedtech/openlitespeed/blob/v1.9.3/src/http/httpserverversion.cpp),
[1.9.3 response headers](https://github.com/litespeedtech/openlitespeed/blob/v1.9.3/src/http/httprespheaders.cpp).
These are provenance baselines, not an exhaustive supported-version range.
Own-authored rule/tests; no upstream code or fingerprint dataset imported.

### OpenResty

`server-header`, state `detected`: complete final-page Server value of
`openresty` or `openresty/major.minor.patch.release`. Allow ASCII product-name
case variations and outer spaces/tabs. Versioned banners require exactly four
ASCII numeric components. Repeated bare/versioned values yield one rule evidence.
Versions constrain matching but are not extracted or reported.

Reviewed release assembly produces the four-part versioned identity; the nginx
core header filter selects it when version details are enabled. With
`server_tokens off`, the product name remains. The headers-more module can
replace or clear Server. Removed/customized headers and intermediaries can
cause misses; spoofed values can mislead or identify an intermediary rather
than the hidden origin.

Initially reject three/five-part versions, `.unknown`, prerelease/custom
suffixes, build comments, combined values, internal whitespace, controls and
Unicode lookalikes. Build-comment banners can be legitimate but are outside
this initial rule. No fallback from HTML, cookies, other headers, redirects
or assets; no path probes or extra requests. OpenResty does not automatically
add nginx, Lua, LuaJIT or an application framework. Separate supported nginx
header values can produce an independent nginx finding, without a topology claim.

Reviewed 2026-10-21 against pinned sources:
[1.25.3.2 header patch](https://github.com/openresty/openresty/blob/v1.25.3.2/patches/nginx-1.25.3-server_header.patch),
[1.27.1.2 header patch](https://github.com/openresty/openresty/blob/v1.27.1.2/patches/nginx-1.27.1-server_header.patch),
[1.27.1.2 release assembly](https://github.com/openresty/openresty/blob/v1.27.1.2/util/mirror-tarballs),
[1.27.1.2 version fields](https://github.com/openresty/openresty/blob/v1.27.1.2/util/ver),
[nginx 1.27.1 header filter](https://github.com/nginx/nginx/blob/release-1.27.1/src/http/ngx_http_header_filter_module.c),
[server_tokens](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens),
[headers-more 0.37](https://github.com/openresty/headers-more-nginx-module/tree/v0.37#description).
These are provenance baselines, not an exhaustive supported-version range.
Own-authored rule/tests; no upstream code or fingerprint dataset imported.

### Apache Tomcat

| Rule | Required evidence | State |
| --- | --- | --- |
| `server-header` | Complete Server value of Apache Tomcat, with an optional three-part numeric version. | detected |
| `powered-by-header` | Complete Servlet/JSP X-Powered-By banner containing Apache Tomcat/version and Java/vendor/runtime fields. | detected |
| `error-report-html` | Final HTTP 400–599 response, an English HTTP Status error title and h1, and an Apache Tomcat/version h3 footer. | inferred |

Headers allow outer spaces/tabs and case-insensitive product names. Servlet/JSP
versions have two numeric components; Tomcat versions have three. Java vendor
and runtime fields have bounded ASCII syntax; custom vendor strings, prereleases
and modified banners may be missed. These values are not extracted or reported.
Repeated fields do not duplicate rule evidence. Direct evidence upgrades an
HTML inference while retaining all matching rules.

The HTML rule requires complete attribute-free title, h1 and h3 tags. Tag case
is ignored; text uses `HTTP Status 4xx/5xx – reason` and `Apache Tomcat/version`.
The separator is a literal en dash. Custom/localized pages, encoded markers,
modified tags and hidden server information may be missed. The status condition
checks a range; it does not compare the numbers in HTML to each other or to the
response status. Copied/commented markers can still match on an error response.
No markers from redirects, non-HTML responses or assets complete the HTML rule.

Tomcat does not set a Server header by default unless configured or supplied
by the application. Its Servlet/JSP X-Powered-By header is opt-in. Header-only
coverage is therefore limited. Generic Servlet/JSP banners, Apache-Coyote,
JSESSIONID and a Tomcat mention alone do not identify it. No guessed error paths,
Java/JVM/framework implication, or hidden-origin attribution.

Reviewed 2026-10-18. Sources:
[HTTP connector](https://tomcat.apache.org/tomcat-11.0-doc/config/http.html),
[error report configuration](https://tomcat.apache.org/tomcat-11.0-doc/config/valve.html#Error_Report_Valve),
[11.0.x header construction](https://github.com/apache/tomcat/blob/11.0.x/java/org/apache/catalina/connector/CoyoteAdapter.java),
[11.0.x error renderer](https://github.com/apache/tomcat/blob/11.0.x/java/org/apache/catalina/valves/ErrorReportValve.java),
[English status text](https://github.com/apache/tomcat/blob/main/java/org/apache/catalina/valves/LocalStrings.properties),
[server identity](https://github.com/apache/tomcat/blob/main/java/org/apache/catalina/util/ServerInfo.properties).
Branch links are review baselines, not exhaustive version coverage.

## Web frameworks

Category: `framework`. Includes web/full-stack frameworks; category names do
not establish rendering mode or backend language.

### ASP.NET Core

`antiforgery-cookie-and-input`: a final-response cookie name matching
`.AspNetCore.Antiforgery.` plus exactly 11 ASCII Base64url characters
(`A–Z`, `a–z`, `0–9`, `_`, `-`), paired with a complete input tag containing
quoted `type="hidden"` and `name="__RequestVerificationToken"` attributes.
State: `inferred`.

Cookie and field names are case-sensitive. Input tag/attribute names and the
hidden type are case-insensitive; both attributes must be on one tag, in either
order. Token values, a surrounding form and a POST method are not required.
No token decoding, comparison, validation or security-posture assessment.
The cookie suffix is a name-shape check, not validation of its hash or encoding.
Neither cookie names/suffixes nor token values are reported.

Neither marker alone, classic ASP.NET cookie names, generic session/authentication
cookies, `X-Powered-By: ASP.NET`, IIS or Kestrel completes this rule. No language,
runtime or server finding is implied. Redirect and asset markers do not complete
the final-page pair; additional requests or form submissions are not made.

Customized names, absent Set-Cookie, pages without the hidden input, runtime-only
forms and encoded/unquoted markers can be missed. Raw HTML can match copied or
commented tags; independent cookies and markup do not establish their association
or backend execution. Headers/cookies can be spoofed or exposed by intermediaries.

Reviewed 2026-10-18. Pinned defaults and cookie construction:
[8.0.0 options](https://github.com/dotnet/aspnetcore/blob/v8.0.0/src/Antiforgery/src/AntiforgeryOptions.cs),
[10.0.0 options](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Antiforgery/src/AntiforgeryOptions.cs),
[8.0.0 cookie naming](https://github.com/dotnet/aspnetcore/blob/v8.0.0/src/Antiforgery/src/Internal/AntiforgeryOptionsSetup.cs),
[10.0.0 cookie naming](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Antiforgery/src/Internal/AntiforgeryOptionsSetup.cs),
[10.0.0 input rendering](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/Mvc/Mvc.ViewFeatures/src/AntiforgeryExtensions.cs).
The shared field name also appears in
[classic ASP.NET](https://github.com/aspnet/AspNetWebStack/blob/main/src/System.Web.WebPages/Helpers/AntiForgeryConfig.cs);
it is not a Core-only marker. Pinned sources are provenance baselines, not an
exhaustive supported-version range; the classic reference follows its main branch.

### Django

`csrf-cookie-and-input`: exact `csrftoken` cookie name plus a complete input tag
containing quoted `type="hidden"` and `name="csrfmiddlewaretoken"` values on
the final response. State: `inferred`.

Both attributes must be on the same tag, in either order. The hidden type is
case-insensitive; the field/cookie names are case-sensitive. No token value,
form, POST method, or session cookie is required. Token/cookie values are not
compared or reported. The sessionid/csrftoken cookie pair alone does not match.

Custom cookie names, session-backed CSRF, missing Set-Cookie, JS-generated forms,
and unquoted/encoded marker values can be missed. A Django finding implies
Python as `inferred`, preserving Django as its source. No debug text fallback,
token validation, or security-posture assessment.

Sources: [Django 5.2 CSRF](https://docs.djangoproject.com/en/5.2/ref/csrf/),
[default settings](https://github.com/django/django/blob/5.2/django/conf/global_settings.py),
[template renderer](https://github.com/django/django/blob/5.2/django/template/defaulttags.py).

### Express

`powered-by-header`: X-Powered-By equals Express, case-insensitive with outer
spaces/tabs. State: `detected`. No language/runtime implication.

Reviewed 2026-10-05. Sources:
[response implementation](https://github.com/expressjs/express/blob/master/lib/application.js),
[header configuration](https://expressjs.com/en/advanced/best-practice-security/#reduce-fingerprinting).

### FastAPI

Category: `framework`. Both rules are `inferred` and require three markers in
the same final-page HTML capture:

| Rule | Required evidence |
| --- | --- |
| `swagger-ui-html` | Default FastAPI favicon link, empty `div` with `id="swagger-ui"`, and a complete inline script with the default-shaped `const ui = SwaggerUIBundle(...)` initializer. |
| `redoc-html` | Default FastAPI favicon link, empty `redoc` element with a nonempty quoted `spec-url`, and a complete jsDelivr ReDoc script tag. |

Favicon: complete `link` with quoted `rel="shortcut icon"` and quoted
`https://fastapi.tiangolo.com/img/favicon.png` href, in either attribute order.
HTML tag/attribute names and rel value are case-insensitive; URL schemes/hosts
allow ASCII case variations. URL paths, JS identifiers and target IDs are
case-sensitive. Attribute whitespace, single/double quotes and supported extra
attributes are accepted. URLs have no query/fragment, credentials, explicit
ports or host suffixes; URL text is inspected, not fetched.

Swagger requires a bare inline script tag, `const ui`, a quoted nonempty `url`
property first, then quoted `dom_id: "#swagger-ui"`, a comma and a closed call.
The remaining configuration stays within that script; JS syntax is not parsed
or executed. ReDoc's external script URL is
`https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js` or the reviewed
`@next` variant. ReDoc schema URLs are not fixed to `/openapi.json` and are not
followed. Titles are not used; customized documentation paths/titles can match.

Either marker alone, partial or cross-viewer combinations, generic viewer
pages, FastAPI text/titles, JSON errors, Uvicorn/Werkzeug headers and session
cookies do not identify FastAPI. Redirect or asset content cannot complete the
page rule. Duplicate markers yield one evidence entry per rule; both matching
rules retain separate evidence on one inferred finding. No Python/server/runtime
implication or version extraction; viewer package versions are not FastAPI versions.

These are documentation-template clues, not proof that the API backend uses
FastAPI. Copied, commented or statically hosted markup can match. Customized
favicons, hosts, viewer URLs, markup or initializer structure may miss. No
automatic `/docs`, `/redoc`, OAuth or schema discovery. Supply the documentation
URL explicitly, or scan a URL that redirects there. Page-only matching performs
no favicon, viewer or schema requests; `--assets` retains its existing policy.

Reviewed 2026-10-20:
[0.115.12 templates](https://github.com/fastapi/fastapi/blob/0.115.12/fastapi/openapi/docs.py),
[0.116.1 templates](https://github.com/fastapi/fastapi/blob/0.116.1/fastapi/openapi/docs.py),
[0.116.1 route/title setup](https://github.com/fastapi/fastapi/blob/0.116.1/fastapi/applications.py),
[current template reference](https://fastapi.tiangolo.com/reference/openapi/docs/),
[customization](https://fastapi.tiangolo.com/how-to/custom-docs-ui-assets/),
[generic Swagger UI page](https://github.com/swagger-api/swagger-ui/blob/v5.17.14/dist/index.html).
Own-authored rules/minimal fixtures; no upstream template or dataset imported.
These are provenance baselines, not an exhaustive supported-version range.

### Fiber

`server-header`: complete unversioned `Fiber` value in the final response's
Server header. State: `detected`; category: `framework`, not `web_server`.
Allow ASCII case variations and outer spaces/tabs only. Reject versions,
comments, trailers, combined values, internal whitespace, controls and Unicode
lookalikes. Repeated matching values yield one evidence entry.

The Server header is disabled by default in the reviewed Fiber versions.
`ServerHeader: "Fiber"` is an explicit configuration example, not automatic
identity disclosure. Default/custom-header deployments can therefore be missed.
Headers can be spoofed, forwarded, replaced or hidden by intermediaries.
No Go language/runtime or server implication and no hidden-origin attribution.

No fallback from X-Powered-By, Via, cookies, HTML, redirect hops or assets.
`fasthttp`, `Go`, `Cannot GET /`, `404 page not found` and generic JSON errors
do not identify Fiber. No path probes, additional requests or version extraction.

Reviewed 2026-10-20 against pinned
[2.52.9 configuration and server setup](https://github.com/gofiber/fiber/blob/v2.52.9/app.go)
and [3.0.0 configuration and server setup](https://github.com/gofiber/fiber/blob/v3.0.0/app.go).
Both default to an empty ServerHeader and suppress the default server banner.
The [configuration reference](https://docs.gofiber.io/api/fiber/) documents the
opt-in header. Own-authored rule/tests; no upstream code or dataset imported.
These are provenance baselines, not an exhaustive supported-version range.

### Laravel

`default-cookie-pair`: exact `laravel_session` and `XSRF-TOKEN` cookie names on
the final response. State: `inferred`. Implies PHP, preserving Laravel as the source.

Session names are configurable and commonly derive from the app name. Custom
names are missed. Either name alone, generic *_session names, and PHPSESSID
do not identify Laravel. The pair is a heuristic, not a uniqueness guarantee.

Reviewed 2026-10-05. Sources:
[session configuration](https://github.com/laravel/framework/blob/13.x/config/session.php),
[CSRF cookie](https://laravel.com/framework/docs/13.x/csrf#x-xsrf-token).

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

### Ruby on Rails

`csrf-meta-pair`: complete meta tags for `csrf-param` with content
`authenticity_token` and `csrf-token` with nonempty whitespace-free content in
the final HTML. State: `inferred`.

Each name/content pair must be on one tag, in either order, with quoted values.
Marker values are case-sensitive. Tokens are neither validated nor reported.
Either tag alone, generic session cookies, X-Request-ID, X-Runtime, Turbo assets,
and hidden authenticity_token fields do not independently match. Custom CSRF
parameters, API-only responses, omitted tags, and runtime-injected tags can be missed.
A Rails finding implies Ruby as `inferred`, preserving Rails as its source.
No security-posture assessment.

Reviewed 2026-10-07. Sources:
[CSRF helper](https://api.rubyonrails.org/classes/ActionView/Helpers/CsrfHelper.html),
[8.0.2 defaults](https://github.com/rails/rails/blob/v8.0.2/actionpack/lib/action_controller/metal/request_forgery_protection.rb),
[configurable cookies](https://github.com/rails/rails/blob/v8.0.2/actionpack/lib/action_dispatch/middleware/session/cookie_store.rb),
[request IDs](https://github.com/rails/rails/blob/v8.0.2/actionpack/lib/action_dispatch/middleware/request_id.rb).

### Spring Boot

Category: `framework`. No Java/Kotlin/JVM, Spring Framework, server or additional
Actuator technology finding is implied.

| Rule | Required evidence | State |
| --- | --- | --- |
| `actuator-media-type` | Complete Content-Type of `application/vnd.spring-boot.actuator.v2+json` or `v3+json`. | detected |
| `whitelabel-error-html` | Final HTTP 400–599 response with a Whitelabel h1, a reviewed fallback paragraph and structured error details in a div. | inferred |

The media-type rule is case-insensitive and permits outer spaces/tabs, plus one
optional UTF-8 charset parameter (quoted or unquoted). Other parameters, charsets,
API versions, suffixes and comma-combined values are outside coverage. Repeated
header values are inspected independently and do not duplicate rule evidence.
The v2/v3 marker is an API representation version, not a Spring Boot software
version. Neither it nor the response JSON contents are extracted or reported.

HTML requires complete attribute-free h1/p/div tags. Tag case is ignored; text
is case-sensitive. Require the reviewed servlet explanation about no explicit
mapping for /error, or the reactive explanation about no configured error view.
The error div requires a nonempty type and a 4xx/5xx status; an optional bracketed
ASCII request ID prefix is accepted. Timestamps, messages and traces are not
required or reported. HTML status numbers are not compared with the response code.
Partial markers, generic JSON errors, cookies, X-Application-Context, and markers
in redirects or assets do not complete these rules.

This is opportunistic coverage: only inspect the supplied URL's final response.
No `/error` or Actuator path probes or extra requests. Default page requests omit
Accept; the reviewed WebFlux handler requires explicit HTML acceptance, so its
default JSON response will not satisfy the HTML rule. Optional
[`--prefer-html`](usage.md#html-preference) requests an HTML representation but
does not guarantee one. A response using generic `application/json` does not
satisfy the media-type rule either. Customized/disabled views, modified markup
and other versions can be missed; copied/commented HTML and spoofed headers
remain limitations.

Reviewed 2026-10-18. Sources:
[2.7.18 servlet renderer](https://github.com/spring-projects/spring-boot/blob/v2.7.18/spring-boot-project/spring-boot-autoconfigure/src/main/java/org/springframework/boot/autoconfigure/web/servlet/error/ErrorMvcAutoConfiguration.java),
[3.5.0 servlet renderer](https://github.com/spring-projects/spring-boot/blob/v3.5.0/spring-boot-project/spring-boot-autoconfigure/src/main/java/org/springframework/boot/autoconfigure/web/servlet/error/ErrorMvcAutoConfiguration.java),
[2.7.18 reactive renderer](https://github.com/spring-projects/spring-boot/blob/v2.7.18/spring-boot-project/spring-boot-autoconfigure/src/main/java/org/springframework/boot/autoconfigure/web/reactive/error/AbstractErrorWebExceptionHandler.java),
[3.5.0 reactive renderer](https://github.com/spring-projects/spring-boot/blob/v3.5.0/spring-boot-project/spring-boot-autoconfigure/src/main/java/org/springframework/boot/autoconfigure/web/reactive/error/AbstractErrorWebExceptionHandler.java),
[HTML negotiation](https://github.com/spring-projects/spring-boot/blob/v3.5.0/spring-boot-project/spring-boot-autoconfigure/src/main/java/org/springframework/boot/autoconfigure/web/reactive/error/DefaultErrorWebExceptionHandler.java),
[Actuator media types](https://docs.spring.io/spring-boot/api/rest/actuator/mappings.html).
Renderer tags are provenance baselines, not an exhaustive supported-version range.

## JavaScript frameworks

Category: `javascript_framework`. Groups Angular, React, and Vue for catalog
organization; it does not establish execution or client-side use.

### Angular

`server-host-attributes`: a complete opening tag containing both quoted
`ng-version` and `ng-server-context` attributes. State: `inferred`.

- Version: stable `major.minor.patch`, major 2 or later, no leading zeros.
- Server context: one or more ASCII letters, digits, or hyphens; case-sensitive.
- Both attributes must be on the same tag, in either order. Tag and attribute
  names are case-insensitive; unrelated attributes and whitespace are allowed.
- Evidence has one HTML signal location because one compound matcher binds
  the pair. Attribute values are not extracted or reported.

Either attribute alone, separate tags, unquoted/empty/malformed values,
`data-ng-*` lookalikes, a generic `app-root`, AngularJS `ng-app`, headers,
cookie values and asset bodies do not satisfy this HTML rule.
Prerelease/custom versions, source placeholders, encoded values and removed
attributes are outside this initial rule. Duplicate pairs yield one evidence item.

Coverage targets server-rendered/prerendered HTML exposing both markers.
Client-rendered shells can lack them until JavaScript runs; the tool does not
execute it. The pair does not establish a particular rendering mode or server
implementation. Copied/commented tags and string examples can match because
HTML detection is raw-text matching, not DOM parsing.

`asset-component-runtime`: all three code-shaped indicators in one captured
JavaScript body. State: `inferred`.

- An ASCII identifier assigned the exact quoted `__ngContext__` key, optionally
  declared with `var`, `let`, or `const`, at a statement/declaration boundary.
- A dot-property `ɵcmp` assignment (literal or `\u0275cmp`) on an ASCII identifier
  receiver, including `this`. The value is an identifier/member call whose object
  argument starts with `type: <identifier>` followed by a comma or closing brace.
- A two-element array containing exact quoted `ng-version` and a quoted stable
  `major.minor.patch` version, major 2 or later, without leading zeros.

Single/double quotes, whitespace and renamed ASCII identifiers are supported.
Reads, comparisons, directive-only `ɵdir`, bracket/static-field definitions,
generic API names, filenames and partial/split-file triples are insufficient.
Only the reviewed `\u0275cmp` escape is supported, not arbitrary JS escapes.
The matchers do not validate full JS syntax, scope or linkage between variables.
Copied/commented code can match; execution and application use are not established.

JS review used Angular 20.3.0 package modules and a user-downloaded minified
Ryanair main bundle whose bytes matched its page integrity hash. That bundle
retains escaped component assignments and multiple host-version arrays; it is
not evidence of one site-wide version or coverage across all Angular releases.
The 3,151,142-byte main exceeds the standard 512 KiB per-asset and 2 MiB combined
decoded budgets; expanded budgets accommodate that decoded size, but successful
collection/detection still depends on encoded input, response policies and time.
Its small loader lacks the triple. Larger, split, off-origin,
tree-shaken or differently compiled bundles can be missed; imports are not followed.

Both rules produce one Angular finding with independent HTML/asset evidence.
Neither reports versions, identifies AngularJS, implies a backend language,
or executes JavaScript. Fixtures are authored scaffolds, not imported runtimes
or website captures. Reviewed 2026-10-12.
Sources:
[host attributes](https://github.com/angular/angular/blob/20.3.0/packages/core/src/render3/component_ref.ts),
[runtime context](https://github.com/angular/angular/blob/20.3.0/packages/core/src/render3/context_discovery.ts),
[published runtime module](https://unpkg.com/@angular/core@20.3.0/fesm2022/debug_node.mjs),
[server context and serialization](https://github.com/angular/angular/blob/20.3.0/packages/platform-server/src/utils.ts),
[rendering modes](https://angular.dev/guide/ssr),
[MIT license](https://angular.dev/license).

### React

`asset-client-runtime`: paired markers in one accepted JavaScript capture.
State: `inferred`. Requires both:

- A dot-property assignment to
  `__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE`.
- An exact `Symbol.for("react.transitional.element")` call, with either quote style.

Allow whitespace and renamed ASCII identifier receivers. The assignment accepts
an identifier value followed by a semicolon, comma, closing brace, or end of body,
or an object-literal start. Reads, comparisons, bare names, generic hooks, root
elements, filenames, and either marker alone do not match. The Symbol call must
be unqualified; bracket notation, escaped identifiers/strings, changed export
shapes, and markers split across captures are outside this rule.

The reviewed baseline is React 19.1.0's published client production runtime.

`asset-dom-runtime`: five markers in one accepted JavaScript capture.
State: `inferred`. Requires all five:

- Identifier assignments constructing `__reactFiber$`, `__reactProps$`, and
  `__reactContainer$` keys, each as a quoted prefix plus an identifier suffix.
- The exact quoted `https://reactjs.org/docs/error-decoder.html?invariant=` or
  `https://react.dev/errors/` URL concatenated with an identifier-shaped error code.
- The exact quoted `Minified React error #` string concatenated with an
  identifier-shaped code, then the quoted `; visit ` string.

Allow whitespace, either quote style, and renamed ASCII identifiers. Key
assignments start at body start or after a semicolon, comma, or brace, optionally
with `var`, `let`, or `const`. They and the URL/code concatenation end with a
semicolon, comma, closing brace, or end of body. Bare strings, reads/comparisons,
qualified key assignment targets, function-call suffixes/codes, generic ReactDOM APIs, partial
marker sets, and split captures do not match. The engine does not verify shared
suffix variables, function scope, or execution. Escaped literals, changed
serializers and development builds are outside this rule. No requirement that
the separate React client rule also match. Both URL alternatives use the same
rule ID and five signal locations; multiple matching forms in one capture do not
duplicate rule/URL evidence.

Reviewed renderer baselines: ReactDOM 18.3.1's published minified UMD build
(131,835 bytes) and ReactDOM 19.1.0's published client production CJS build.
Both contain the three key constructions and message shape, with legacy and
modern error URLs respectively. The latter reads the client internals export;
that read alone does not satisfy the separate client-assignment rule. CJS is a
package-build reference, not a claim of direct browser execution. None of the
key/error markers occur in the reviewed Preact 10.26.4 compatibility UMD build.
The older internals export plus `react.element` occurs in the reviewed ReactDOM
18 and Preact artifacts and is not a fallback.
This comparison does not establish every compatibility library or build form.
Readable/compact fixtures are authored scaffolds, not full upstream bundles.
Neither rule reports a version or establishes an entire React major-version range.
Both rules produce one React finding with separate supporting evidence when present.

Inline scripts, off-origin assets, oversized/unselected bundles, and tree-shaken
or split runtime output can be missed. Copied/commented code and forks retaining
the marker sets can match; runtime execution/use is not established. Next.js
does not automatically imply React. No backend language implication.

The ReactDOM 19 reference is listed at about 515 kB, close to the standard 512 KiB decoded
asset cap; the exact byte count was not verified. Site bundles can differ in
size and shape, and oversized captures remain rejected. Collection limits are
unchanged; no imports are followed or package dependencies executed.

Reviewed 2026-10-10. Sources:
[v19.1.0 client exports](https://github.com/facebook/react/blob/v19.1.0/packages/react/src/ReactClient.js),
[element symbols](https://github.com/facebook/react/blob/v19.1.0/packages/shared/ReactSymbols.js),
[published production runtime](https://app.unpkg.com/react@19.1.0/files/cjs/react.production.js),
[v18.3.1 DOM keys](https://github.com/facebook/react/blob/v18.3.1/packages/react-dom/src/client/ReactDOMComponentTree.js),
[production error formatter](https://github.com/facebook/react/blob/v18.3.1/packages/shared/formatProdErrorMessage.js),
[ReactDOM production UMD build](https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js),
[v19.1.0 DOM keys](https://github.com/facebook/react/blob/v19.1.0/packages/react-dom-bindings/src/client/ReactDOMComponentTree.js),
[ReactDOM client production CJS build](https://app.unpkg.com/react-dom@19.1.0/files/cjs/react-dom-client.production.js),
[Preact compatibility UMD build](https://unpkg.com/preact@10.26.4/compat/dist/compat.umd.js),
[Preact 10.26.4 compatibility exports](https://github.com/preactjs/preact/blob/10.26.4/compat/src/index.js),
[React 18 MIT license](https://github.com/facebook/react/blob/v18.3.1/LICENSE),
[React 19 MIT license](https://github.com/facebook/react/blob/v19.1.0/LICENSE).

### Vue

`asset-renderer-runtime`: three markers in one accepted JavaScript capture.
State: `inferred`. Requires all three:

- A dot-property assignment of `__VUE__` to `true` or minified `!0`.
- A dot-property assignment of `__vue_app__` to an identifier-shaped value.
- An exact `Symbol.for("v-fgt")` call, with either quote style.

Allow whitespace and renamed ASCII identifiers. The runtime flag receiver may
be an identifier or a zero-argument identifier call, such as `getTarget()`.
The app receiver is an identifier. Assignments must end with a semicolon,
comma, closing brace, or end of body. Bare names, reads/deletes, comparisons,
generic Vue APIs, filenames, and partial or split-file triples do not match.
Bracket notation, escaped identifiers/strings, other receiver/value shapes,
and changed serializers are outside this rule.

The reviewed baseline is Vue 3.5.13's minified runtime global and runtime
ESM-browser production builds. All three markers survive in both; devtools
hooks are absent and are not required. Readable/compact fixtures are authored
scaffolds, not imported bundles. This does not establish all Vue 3 build forms
or versions; no Vue 2 fallback or version reporting is included.

Inline scripts, off-origin assets, oversized/unselected bundles, tree-shaken
code and runtime markers split across imports/chunks can be missed. Copied or
commented code and forks retaining the markers can match; execution, mounting
and browser DOM use are not established. Nuxt does not automatically imply Vue.
No language/runtime implication or collection-policy change.

Reviewed 2026-10-10. Sources:
[v3.5.13 renderer](https://github.com/vuejs/core/blob/v3.5.13/packages/runtime-core/src/renderer.ts#L333-L337),
[app mount](https://github.com/vuejs/core/blob/v3.5.13/packages/runtime-core/src/apiCreateApp.ts#L375-L378),
[vnode symbols](https://github.com/vuejs/core/blob/v3.5.13/packages/runtime-core/src/vnode.ts#L61-L69),
[build forms](https://github.com/vuejs/core/blob/v3.5.13/packages/vue/README.md),
[runtime global production build](https://unpkg.com/vue@3.5.13/dist/vue.runtime.global.prod.js),
[runtime ESM-browser production build](https://unpkg.com/vue@3.5.13/dist/vue.runtime.esm-browser.prod.js),
[MIT license](https://github.com/vuejs/core/blob/v3.5.13/LICENSE).

## JavaScript libraries

### jQuery

Category: `javascript_library`. Rule: `asset-core-runtime`. State: `inferred`.
Require both code-shaped indicators in one accepted JavaScript capture:

- A dot-property chain assigning `fn` and `prototype` to an object whose first
  fields are unquoted `jquery: <identifier>`, `constructor: <identifier>` and
  `length: 0`, in that order.
- An unquoted `expando` field constructing the exact quoted `jQuery` prefix plus
  a parenthesized identifier + zero-argument `Math.random()` expression, followed
  by `.replace(/\D/g, "")` with an empty replacement.

Allow whitespace, single/double string quotes and renamed ASCII identifiers.
The engine does not check identifier equality, scope, version-variable values or
execution. Copied/commented code and forks retaining the pair can match.

Banner/filename-only clues, `$` usage, generic APIs, plugin-style assignments,
either indicator alone and split-file pairs do not match. Quoted/bracket keys,
reordered properties, escaped product strings, comments between required tokens,
different initialization/serialization shapes and tree-shaken/split builds can be missed.
There is no version reporting, full/slim classification or backend implication.
Off-origin, inline, oversized and unselected assets remain outside coverage.

Reviewed full/slim minified distributions for 3.7.1 and 4.0.0; both indicators
occur in all four, independently of their banners. These are provenance baselines,
not a claim of coverage across every release/build. Fixtures are authored compact
and whitespace-formatted scaffolds, not imported library bundles.

Reviewed 2026-10-14. Sources:
[3.7.1 core](https://github.com/jquery/jquery/blob/3.7.1/src/core.js),
[4.0.0 core](https://github.com/jquery/jquery/blob/4.0.0/src/core.js),
[3.7.1 full production build](https://code.jquery.com/jquery-3.7.1.min.js),
[3.7.1 slim production build](https://code.jquery.com/jquery-3.7.1.slim.min.js),
[4.0.0 full production build](https://code.jquery.com/jquery-4.0.0.min.js),
[4.0.0 slim production build](https://code.jquery.com/jquery-4.0.0.slim.min.js),
[MIT license](https://jquery.com/license/).

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

### Tailwind CSS

Category: `ui_framework`. State: `inferred`. Requires `--assets` and all markers
for either rule in one accepted CSS capture:

| Rule | Required markers |
| --- | --- |
| `asset-css-v3-banner-and-preflight` | Closed official-shaped `/*! tailwindcss v3.4.x \| MIT License \| https://tailwindcss.com */` banner plus a closed before/after pseudo-element rule declaring empty `--tw-content`. |
| `asset-css-v4-banner-and-translate` | Corresponding stable `v4.1.x` banner; closed `@property --tw-translate-x` registration with `syntax: "*"`, `inherits: false`, `initial-value: 0`; and a closed rule declaring `--tw-translate-x` before `translate: var(--tw-translate-x) var(--tw-translate-y)`. |

Matching is case-sensitive. Allow whitespace and empty single/double quotes in
v3 preflight; both pseudo-element selector orders and single/double colons are
supported. The v3 block contains only the empty content declaration. The v4
registration retains the listed declaration order; translate blocks allow other
declarations and custom translation values. Final semicolons are optional.

Banner-only, class names, filenames, generic utility CSS, bare `--tw-` prefixes,
inline styles, JavaScript bodies, split-file markers and mismatched banner/rule
families do not suffice. Neither rule establishes applied styles, execution,
backend technology, Radix UI or shadcn/ui use. No versions are reported.

Initial baselines are upstream v3.4.17 preflight/banner generation and v4.1.0
compiler snapshots, not every build in either family. Stripped/changed banners,
prereleases, other version families, custom serialization/identifiers, disabled
preflight in v3, and absence of the selected translate output in v4 can miss.
Off-origin, imported-only, failed, incomplete and over-budget styles are not
inspected. Copied/commented CSS or forks retaining the markers can match.

Reviewed 2026-10-22. Own-authored rules and minimal synthetic fixtures; no
upstream distribution or third-party fingerprint dataset imported. Sources:
[v3.4.17 preflight](https://github.com/tailwindlabs/tailwindcss/blob/v3.4.17/src/css/preflight.css),
[v3.4.17 banner generation](https://github.com/tailwindlabs/tailwindcss/blob/v3.4.17/src/corePlugins.js),
[v4.1.0 compiler/banner](https://github.com/tailwindlabs/tailwindcss/blob/v4.1.0/packages/tailwindcss/src/index.ts),
[v4.1.0 compiled translate snapshots](https://github.com/tailwindlabs/tailwindcss/blob/v4.1.0/packages/tailwindcss/src/index.test.ts),
[v3.4.17 MIT license](https://github.com/tailwindlabs/tailwindcss/blob/v3.4.17/LICENSE).

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

Category: `language`. No languages are inferred from web-server implementation
languages, client JS, generic filenames, or session cookies alone.

### PHP

`powered-by-header` matches PHP with an optional
digit-starting version suffix in X-Powered-By, case-insensitive with outer
spaces/tabs. State: `detected`. Laravel also implies PHP as `inferred`; the
header upgrades it while preserving the relationship evidence.

PHPSESSID alone and PHP text in Apache module banners do not match.

Reviewed 2026-10-05. Source:
[expose_php](https://www.php.net/manual/en/ini.core.php#ini.expose-php).

### Python and Ruby

Inference-only catalog entries, reviewed 2026-10-18:

| Language | Required finding | Evidence |
| --- | --- | --- |
| Python (`python`) | Django (`django`) | `inferred_from: django` |
| Ruby (`ruby`) | Ruby on Rails (`rails`) | `inferred_from: rails` |

Both remain `inferred`. They have no direct matchers; relationship evidence
has no rule ID or signal locations. The source framework finding retains the
observed evidence. Partial framework markers produce neither finding.

These relationships inherit the framework rules' limitations: copied,
commented, cached or spoofed markers can support an inference. They do not
independently observe the language or prove backend execution on the target.
Python/Ruby header text and server implementation banners do not match.

Sources: the Django and Rails references above describe the framework markers;
[Django FAQ](https://docs.djangoproject.com/en/5.2/faq/general/) describes its
Python basis, and the Rails references use its Ruby implementation.

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
stacks, independent frontend combinations, optional asset failures, and privacy.
Multiple technologies in a synthetic fixture do not model a real network topology.
Tests are not accuracy percentages.
