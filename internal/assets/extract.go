// Package assets extracts static references and optionally collects bounded,
// same-origin assets. It never executes scripts or follows nested references.
package assets

import (
	"bytes"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"

	"webscan/internal/fetch"
)

type Kind string

const (
	JavaScript Kind = "javascript"
	Stylesheet Kind = "stylesheet"
)

type Reference struct {
	URL  string
	Kind Kind // Declaration hint only; later collection must validate the response.
}

type Options struct {
	MaxHTMLBytes  int64
	MaxReferences int
}

func DefaultOptions() Options {
	return Options{MaxHTMLBytes: 2 << 20, MaxReferences: 5}
}

type Result struct {
	References []Reference // Unique eligible URLs in parsed document order.
	Truncated  bool        // At least one more eligible URL exceeded MaxReferences.
	Skipped    int         // Unsupported, invalid, off-origin or self references.
	Duplicates int         // Repeated eligible URLs among the retained candidates.
}

var (
	ErrHTMLLimit   = errors.New("asset extraction HTML limit exceeded")
	ErrInvalidHTML = errors.New("asset extraction requires UTF-8 HTML")
	ErrHTMLParse   = errors.New("asset extraction could not parse HTML")
)

// Extract is bounded, deterministic and network-free. No references are returned
// on input/parser failure. Excluded declarations are counted, not echoed in errors.
func Extract(finalURL string, body []byte, options Options) (Result, error) {
	if options.MaxHTMLBytes <= 0 || options.MaxReferences <= 0 {
		return Result{}, errors.New("asset extraction limits must be positive")
	}
	page, err := fetch.ParseURL(finalURL)
	if err != nil {
		return Result{}, err // ParseURL diagnostics never echo the input URL.
	}
	if int64(len(body)) > options.MaxHTMLBytes {
		return Result{}, ErrHTMLLimit
	}
	if !utf8.Valid(body) {
		return Result{}, ErrInvalidHTML
	}
	// Scripting-enabled parsing treats noscript as fallback content. This only
	// controls tree construction: nothing is executed.
	doc, err := html.ParseWithOptions(bytes.NewReader(body), html.ParseOptionEnableScripting(true))
	if err != nil {
		return Result{}, ErrHTMLParse
	}
	base := page
	baseFound := false
	walk(doc, func(n *html.Node) bool {
		if inert(n) {
			return false
		}
		if n.Type == html.ElementNode && n.Data == "base" && !baseFound {
			if href, ok := attribute(n, "href"); ok {
				baseFound = true // Do not let a later base override an unusable first one.
				base = resolve(page, href)
			}
		}
		return true
	})
	result := Result{References: make([]Reference, 0)}
	seen := make(map[string]bool)
	pageKey := urlKey(page)
	walk(doc, func(n *html.Node) bool {
		if inert(n) {
			return false
		}
		raw, kind, declared := declaration(n)
		if !declared {
			return true
		}
		raw = trimSpace(raw)
		u := resolve(base, raw)
		if kind == "" || raw == "" || strings.HasPrefix(raw, "#") || u == nil || !fetch.SameOrigin(page, u) || urlKey(u) == pageKey {
			result.Skipped++
			return true
		}
		key := urlKey(u)
		if seen[key] {
			result.Duplicates++
			return true
		}
		if len(result.References) == options.MaxReferences {
			result.Truncated = true
			return true // Do not grow seen or retain extra URLs beyond the limit.
		}
		seen[key] = true
		result.References = append(result.References, Reference{URL: u.String(), Kind: kind})
		return true
	})
	return result, nil
}

func declaration(n *html.Node) (string, Kind, bool) {
	if n.Type != html.ElementNode {
		return "", "", false
	}
	switch n.Data {
	case "script":
		src, ok := attribute(n, "src")
		if !ok {
			return "", "", false
		}
		typ, hasType := attribute(n, "type")
		if !hasType {
			language, _ := attribute(n, "language")
			switch strings.ToLower(trimSpace(language)) {
			case "", "javascript", "ecmascript":
			default:
				return src, "", true
			}
		}
		switch strings.ToLower(trimSpace(typ)) {
		case "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript":
			// Treat nomodule as a static reference too, without emulating browser
			// feature support or deciding which script would actually execute.
			return src, JavaScript, true
		default:
			return src, "", true // JSON data, import maps, and unknown script types.
		}
	case "link":
		rel, _ := attribute(n, "rel")
		stylesheet := false
		for _, token := range strings.FieldsFunc(rel, asciiSpace) {
			if strings.ToLower(token) == "stylesheet" {
				stylesheet = true
			}
		}
		if !stylesheet {
			return "", "", false
		}
		href, ok := attribute(n, "href")
		typ, _ := attribute(n, "type")
		if typ = strings.ToLower(trimSpace(typ)); typ != "" && typ != "text/css" {
			return href, "", ok
		}
		return href, Stylesheet, ok
	}
	return "", "", false
}

func resolve(base *url.URL, raw string) *url.URL {
	raw = trimSpace(raw)
	// Go and browser URL parsers differ on backslashes and embedded whitespace.
	// Reject these ambiguous references rather than guessing a browser URL.
	if strings.ContainsAny(raw, "\\\x00\t\r\n\f") {
		return nil
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	if base != nil {
		ref = base.ResolveReference(ref)
	} else if !ref.IsAbs() {
		return nil
	}
	clean, err := fetch.ParseURL(ref.String())
	if err != nil {
		return nil
	}
	return clean
}

// urlKey normalizes origin spelling only. Query order, empty queries, and escaped
// path bytes remain meaningful; fragments have already been removed by ParseURL.
func urlKey(u *url.URL) string {
	key := *u
	host := strings.ToLower(u.Hostname())
	port, _ := strconv.Atoi(u.Port())
	if port != 0 && !(u.Scheme == "https" && port == 443) && !(u.Scheme == "http" && port == 80) {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	key.Host = host
	if key.Path == "" {
		key.Path = "/"
	}
	return key.String()
}

func attribute(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == name {
			return a.Val, true // First duplicate attribute wins.
		}
	}
	return "", false
}

func inert(n *html.Node) bool {
	return n.Type == html.ElementNode && (n.Namespace != "" || n.Data == "template" || n.Data == "noscript")
}

func asciiSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '\f'
}

func trimSpace(s string) string { return strings.TrimFunc(s, asciiSpace) }

// walk visits nodes in tree order, skipping subtrees whose visitor returns false.
// Iteration avoids adding a recursive traversal on top of parser nesting limits.
func walk(root *html.Node, visit func(*html.Node) bool) {
	for n := root; n != nil; {
		if visit(n) && n.FirstChild != nil {
			n = n.FirstChild
			continue
		}
		for n != root && n.NextSibling == nil {
			n = n.Parent
		}
		if n == root {
			return
		}
		n = n.NextSibling
	}
}
