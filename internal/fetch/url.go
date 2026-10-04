package fetch

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ErrInvalidURL identifies invalid input rather than a network failure.
var ErrInvalidURL = errors.New("invalid URL")

// ParseURL accepts explicit HTTP(S) URLs without embedded credentials.
// Fragments are removed because they are not part of an HTTP request.
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		// Do not echo potentially embedded credentials from the parser's error.
		return nil, fmt.Errorf("%w: malformed URL", ErrInvalidURL)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: include an http:// or https:// scheme", ErrInvalidURL)
	}
	if u.Hostname() == "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: a hostname is required", ErrInvalidURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: embedded credentials are not supported", ErrInvalidURL)
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("%w: port must not be empty", ErrInvalidURL)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%w: port must be between 1 and 65535", ErrInvalidURL)
		}
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u, nil
}
