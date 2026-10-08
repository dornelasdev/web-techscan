package fetch

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
)

// requestError separates printable diagnostics from underlying errors, which
// can contain credentials, query strings, or raw Location/header values.
// Unwrap preserves errors.Is/As for callers; do not log the unwrapped error.
type requestError struct {
	message string
	cause   error
}

func (e *requestError) Error() string { return e.message }
func (e *requestError) Unwrap() error { return e.cause }

func safeRequestError(err error) error {
	// Unknown failures (including malformed Location values parsed by Go before
	// CheckRedirect) deliberately get a generic reason, not err.Error().
	reason := "request failed (network error or invalid HTTP response)"
	var certificate *tls.CertificateVerificationError
	var dns *net.DNSError
	var network net.Error
	var operation *net.OpError
	switch {
	case errors.Is(err, context.Canceled):
		reason = "request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		reason = "request timed out"
	case errors.As(err, &certificate):
		reason = "TLS certificate verification failed"
	case errors.As(err, &network) && network.Timeout():
		reason = "request timed out"
	case errors.As(err, &dns):
		reason = "DNS lookup failed"
	case errors.As(err, &operation):
		reason = "network connection failed"
	}
	return &requestError{message: "fetch page: " + reason, cause: err}
}
