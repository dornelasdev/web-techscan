package fetch

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// ErrContentEncoding means the final response declares an unsupported or
// ambiguous content encoding. Its message never includes raw header values.
var ErrContentEncoding = errors.New("unsupported or ambiguous response content encoding")

// ErrEncodedBodyLimit means the final response exceeded its byte budget before
// content decoding. This is distinct from the decoded-output ErrBodyLimit.
var ErrEncodedBodyLimit = errors.New("encoded response body limit exceeded")

func readBody(resp *http.Response, limit, encodedLimit int64) ([]byte, error) {
	// These statuses have no message body. Their encoding fields may describe
	// a representation rather than an attached payload (notably a 304).
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return []byte{}, nil
	}
	encoding := "identity"
	values := resp.Header.Values("Content-Encoding")
	if len(values) > 0 {
		if len(values) != 1 {
			return nil, ErrContentEncoding
		}
		encoding = strings.ToLower(strings.Trim(values[0], " \t"))
		if encoding != "identity" && encoding != "gzip" {
			return nil, ErrContentEncoding
		}
	}
	// Bound input before even parsing a gzip header. Do not turn budget exhaustion
	// into EOF: a complete gzip member at the boundary may hide later members.
	var reader io.Reader = &encodedBodyReader{reader: resp.Body, remaining: encodedLimit}
	if encoding == "gzip" {
		decoded, err := gzip.NewReader(reader)
		if err != nil {
			return nil, safeBodyError(err)
		}
		defer decoded.Close() // The caller separately owns and closes resp.Body.
		reader = decoded
	}
	// The budget applies to decoded bytes, including concatenated gzip members.
	// Reading to EOF within the budget also validates the gzip checksum/trailer.
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, safeBodyError(err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w (maximum %d bytes)", ErrBodyLimit, limit)
	}
	if encoding == "gzip" {
		// Preserve the previous snapshot semantics of transparently decoded gzip.
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
	}
	return body, nil
}

// encodedBodyReader passes at most remaining bytes to its consumer. At the
// boundary it reads one extra byte only to distinguish exact EOF from overflow.
// It bounds response payload reads, not HTTP framing or transport buffering.
type encodedBodyReader struct {
	reader    io.Reader
	remaining int64
	exceeded  bool
}

func (r *encodedBodyReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.exceeded {
		return 0, ErrEncodedBodyLimit
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			r.exceeded = true
			return 0, ErrEncodedBodyLimit
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func safeBodyError(err error) error {
	reason := "invalid or incomplete response body"
	var network net.Error
	switch {
	case errors.Is(err, context.Canceled):
		reason = "request canceled"
	case errors.Is(err, context.DeadlineExceeded):
		reason = "request timed out"
	case errors.As(err, &network) && network.Timeout():
		reason = "request timed out"
	case errors.Is(err, ErrEncodedBodyLimit):
		reason = ErrEncodedBodyLimit.Error()
	case errors.Is(err, gzip.ErrHeader):
		reason = "invalid gzip header"
	case errors.Is(err, gzip.ErrChecksum):
		reason = "invalid gzip checksum"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		reason = "incomplete response body"
	}
	return &requestError{message: "read response body: " + reason, cause: err}
}
