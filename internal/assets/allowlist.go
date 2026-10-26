package assets

import (
	"errors"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"webscan/internal/fetch"
)

// MaxAllowedOrigins bounds configured scope independently of discovery metadata.
const MaxAllowedOrigins = 20

// NormalizeOrigins validates explicit origin-only inputs, deduplicates using
// the existing origin comparison and returns an independent canonical slice.
// Diagnostics never echo input, which may contain rejected credentials/queries.
func NormalizeOrigins(rawOrigins []string) ([]string, error) {
	origins := make([]string, 0)
	parsed := make([]*url.URL, 0)
	for _, raw := range rawOrigins {
		if !utf8.ValidString(raw) || strings.ContainsAny(raw, "?#\\*") || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return nil, invalidOrigin()
		}
		u, err := fetch.ParseURL(raw)
		if err != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
			return nil, invalidOrigin()
		}
		duplicate := false
		for _, previous := range parsed {
			if fetch.SameOrigin(previous, u) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(origins) == MaxAllowedOrigins {
			return nil, errors.New("asset-origin accepts at most 20 distinct origins")
		}
		parsed = append(parsed, u)
		origins = append(origins, originKey(u))
	}
	return origins, nil
}

func invalidOrigin() error {
	return errors.New("asset-origin must be an HTTP(S) origin without credentials, paths, queries, fragments, wildcards or whitespace")
}

func originKey(u *url.URL) string {
	// A fresh URL prevents paths, queries and credentials entering metadata.
	return strings.TrimSuffix(urlKey(&url.URL{Scheme: u.Scheme, Host: u.Host}), "/")
}

func eligibleOrigin(page, asset *url.URL, allowed []*url.URL) bool {
	// Page redirect downgrade permission never relaxes asset selection.
	if page.Scheme == "https" && asset.Scheme == "http" {
		return false
	}
	if fetch.SameOrigin(page, asset) {
		return true
	}
	for _, origin := range allowed {
		if fetch.SameOrigin(origin, asset) {
			return true
		}
	}
	return false
}
