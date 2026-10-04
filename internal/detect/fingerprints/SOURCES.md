# Initial coverage and sources

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
  It is deliberately limited to the documented Pages Router shape. App Router
  pages without these markers and without the identifying header can be missed.
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
cases, including language inference and direct-evidence precedence. HTML
documents live in `../testdata/coverage/`. CLI coverage tests additionally
exercise fetching, cookie-name extraction, HTML content-type filtering,
error-page scope, and redirect isolation using local HTTP servers.

Tests are authored checks, not measurements of real-world detection accuracy.
The user runs them; the agent does not execute tests or scan live sites.
