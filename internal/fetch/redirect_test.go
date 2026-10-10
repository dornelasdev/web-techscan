package fetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"http://example.test/a?q=one", "http://example.test/b?q=two", true},
		{"https://EXAMPLE.test/", "https://example.test:443/", true},
		{"http://example.test/", "http://example.test:080/", true},
		{"http://[::1]/", "http://[::1]:80/", true},
		{"http://example.test/", "https://example.test/", false},
		{"http://example.test:443/", "https://example.test:443/", false},
		{"http://example.test:8000/", "http://example.test:8001/", false},
		{"https://example.test/", "https://sub.example.test/", false},
		{"https://example.test/", "https://example.test.evil.invalid/", false},
		{"http://localhost/", "http://127.0.0.1/", false},
	} {
		t.Run(tc.a+"->"+tc.b, func(t *testing.T) {
			a, err := ParseURL(tc.a)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ParseURL(tc.b)
			if err != nil {
				t.Fatal(err)
			}
			if got := SameOrigin(a, b); got != tc.want {
				t.Errorf("sameOrigin=%t want=%t", got, tc.want)
			}
		})
	}
}

func TestSafeRequestErrorPreservesCause(t *testing.T) {
	const secret = "private-value"
	for _, tc := range []struct {
		name   string
		cause  error
		reason string
	}{
		{"unknown", errors.New("invalid Location http://user:" + secret + "@example.test/?token=" + secret), "network error or invalid HTTP response"},
		{"canceled", fmt.Errorf(secret+": %w", context.Canceled), "request canceled"},
		{"deadline", fmt.Errorf(secret+": %w", context.DeadlineExceeded), "request timed out"},
		{"certificate", &tls.CertificateVerificationError{Err: errors.New(secret)}, "TLS certificate verification failed"},
		{"dns", &net.DNSError{Name: secret, Err: secret}, "DNS lookup failed"},
		{"dns-timeout", &net.DNSError{Name: secret, Err: secret, IsTimeout: true}, "request timed out"},
		{"connection", &net.OpError{Op: "dial", Net: secret, Err: errors.New(secret)}, "network connection failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &url.Error{Op: "Get", URL: "http://user:" + secret + "@example.test/?token=" + secret, Err: tc.cause}
			got := safeRequestError(original)
			if !strings.Contains(got.Error(), tc.reason) || strings.Contains(got.Error(), secret) || strings.Contains(got.Error(), "example.test") {
				t.Errorf("unsafe or unhelpful diagnostic: %s", got)
			}
			if !errors.Is(got, tc.cause) || !errors.Is(got, original) {
				t.Error("error identity lost")
			}
			var underlying *url.Error
			if !errors.As(got, &underlying) || underlying != original {
				t.Error("typed cause lost")
			}
		})
	}
}
