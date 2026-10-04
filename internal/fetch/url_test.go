package fetch_test

import (
	"errors"
	"testing"

	"webscan/internal/fetch"
)

func TestParseURL(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"https://example.com/path?q=go#section", "https://example.com/path?q=go"},
		{"HTTP://example.com", "http://example.com"},
		{"http://localhost:8080/", "http://localhost:8080/"},
		{"http://[::1]:8080/", "http://[::1]:8080/"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := fetch.ParseURL(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tc.want {
				t.Errorf("URL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRejectInvalidURL(t *testing.T) {
	for _, input := range []string{
		"", "example.com", "//example.com", "ftp://example.com", "https:///path",
		"https://", "http:example.com", "http://user:secret@example.com",
		"http://example.com:0", "http://example.com:65536", "http://example.com:",
		"http://example.com:abc", "http://bad host/", "http://example.com/%zz",
	} {
		t.Run(input, func(t *testing.T) {
			_, err := fetch.ParseURL(input)
			if !errors.Is(err, fetch.ErrInvalidURL) {
				t.Errorf("error = %v, want invalid URL", err)
			}
		})
	}
}
