package assets

import (
	"context"
	"errors"
	"mime"
	"net"
	"net/http"
	"strings"

	"webscan/internal/fetch"
)

const (
	MaxAttempts                = 5
	MaxAssetDecodedBytes int64 = 512 << 10
	MaxAssetEncodedBytes int64 = 1 << 20
	MaxTotalDecodedBytes int64 = 2 << 20
	MaxTotalEncodedBytes int64 = 4 << 20
)

type Fetcher interface {
	FetchAsset(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error)
}

// Item contains only safe metadata. Reason values are fixed codes, never raw
// error strings, response headers, cookie values or redirect destinations.
type Item struct {
	Reference
	Status     string // collected, failed, or skipped (no request attempted).
	Reason     string
	HTTPStatus int
	Usage      fetch.BodyUsage
}

type Capture struct {
	Reference
	Body []byte
}

type Collection struct {
	Status              string // complete within the bounded scope, incomplete, or skipped.
	Reason              string
	Truncated           bool
	SkippedDeclarations int
	Duplicates          int
	Attempted           int
	Collected           int
	Usage               fetch.BodyUsage
	Items               []Item
	Captures            []Capture // Never included in reports or passed as page HTML.
}

// Collect selects references only from the final HTML page. ctx must carry the
// same deadline used for page fetching; it is never reset per asset. Failures
// remain metadata, so valid page findings can still be reported.
func Collect(ctx context.Context, client Fetcher, page fetch.Snapshot) Collection {
	result := Collection{Status: "complete", Items: make([]Item, 0), Captures: make([]Capture, 0)}
	if ctx.Err() != nil {
		result.Status, result.Reason = "skipped", failureReason(ctx.Err())
		return result
	}
	if !extractableHTML(page) {
		result.Status, result.Reason = "skipped", "unsupported_page_type"
		return result
	}
	options := DefaultOptions()
	options.MaxReferences = MaxAttempts
	refs, err := Extract(page.FinalURL, page.Body, options)
	if err != nil {
		result.Status, result.Reason = "skipped", "extraction_failed"
		if errors.Is(err, ErrHTMLLimit) {
			result.Reason = "html_limit"
		} else if errors.Is(err, ErrInvalidHTML) {
			result.Reason = "invalid_utf8_html"
		}
		return result
	}
	result.Truncated, result.SkippedDeclarations, result.Duplicates = refs.Truncated, refs.Skipped, refs.Duplicates
	if refs.Truncated {
		result.Status, result.Reason = "incomplete", "reference_limit"
	}
	for _, ref := range refs.References {
		item := Item{Reference: ref, Status: "skipped"}
		decodedLeft := MaxTotalDecodedBytes - result.Usage.Decoded
		encodedLeft := MaxTotalEncodedBytes - result.Usage.Encoded
		switch {
		case ctx.Err() != nil:
			item.Reason = failureReason(ctx.Err())
		case decodedLeft <= 1 || encodedLeft <= 1:
			item.Reason = "total_byte_limit"
		default:
			mediaTypes := []string{"text/css"}
			if ref.Kind == JavaScript {
				mediaTypes = []string{"text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"}
			}
			// Reserve one byte in each remaining aggregate budget for the
			// overflow probe. Even failed reads cannot exceed combined caps.
			response, err := client.FetchAsset(ctx, ref.URL, fetch.AssetOptions{
				MaxBodyBytes:        min(MaxAssetDecodedBytes, decodedLeft-1),
				MaxEncodedBodyBytes: min(MaxAssetEncodedBytes, encodedLeft-1),
				MediaTypes:          mediaTypes,
			})
			result.Attempted++
			item.HTTPStatus, item.Usage = response.StatusCode, response.Usage
			result.Usage.Decoded += response.Usage.Decoded
			result.Usage.Encoded += response.Usage.Encoded
			if err != nil {
				item.Status, item.Reason = "failed", failureReason(err)
			} else {
				item.Status = "collected"
				result.Collected++
				result.Captures = append(result.Captures, Capture{Reference: ref, Body: response.Body})
			}
		}
		if item.Status != "collected" {
			result.Status = "incomplete"
			if result.Reason == "" {
				result.Reason = "asset_failures_or_skips"
			}
		}
		result.Items = append(result.Items, item)
	}
	return result
}

func extractableHTML(page fetch.Snapshot) bool {
	values := page.Headers.Values("Content-Type")
	if len(values) > 1 {
		return false
	}
	contentType := page.Headers.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(page.Body)
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	// XHTML requires different parsing semantics; do not interpret it as HTML5.
	if err != nil || mediaType != "text/html" {
		return false
	}
	charset := strings.ToLower(params["charset"])
	return charset == "" || charset == "utf-8" || charset == "us-ascii"
}

func failureReason(err error) string {
	var network net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &network) && network.Timeout():
		return "timeout"
	case errors.Is(err, fetch.ErrAssetRedirect):
		return "redirect_not_allowed"
	case errors.Is(err, fetch.ErrAssetStatus):
		return "unsuccessful_status"
	case errors.Is(err, fetch.ErrAssetMediaType):
		return "unsuitable_content_type"
	case errors.Is(err, fetch.ErrBodyLimit):
		return "decoded_body_limit"
	case errors.Is(err, fetch.ErrEncodedBodyLimit):
		return "encoded_body_limit"
	case errors.Is(err, fetch.ErrContentEncoding):
		return "unsupported_content_encoding"
	default:
		return "request_or_body_error"
	}
}
