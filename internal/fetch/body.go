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

func readBody(resp *http.Response, limit int64) ([]byte, error) {
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
	var reader io.Reader = resp.Body
	if encoding == "gzip" {
		decoded, err := gzip.NewReader(resp.Body)
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
	case errors.Is(err, gzip.ErrHeader):
		reason = "invalid gzip header"
	case errors.Is(err, gzip.ErrChecksum):
		reason = "invalid gzip checksum"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		reason = "incomplete response body"
	}
	return &requestError{message: "read response body: " + reason, cause: err}
}
