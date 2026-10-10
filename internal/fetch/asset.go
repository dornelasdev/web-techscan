package fetch

import (
	"context"
	"errors"
	"math"
	"mime"
	"net/http"
)

var (
	ErrAssetRedirect  = errors.New("asset redirects are not followed")
	ErrAssetStatus    = errors.New("asset response is not successful")
	ErrAssetMediaType = errors.New("asset response has an unsuitable content type")
)

// AssetOptions bounds a single asset. The caller owns origin selection, the
// shared scan deadline and aggregate budgets. MediaTypes is an explicit allowlist.
type AssetOptions struct {
	MaxBodyBytes        int64
	MaxEncodedBodyBytes int64
	MediaTypes          []string
}

// AssetResponse keeps asset content separate from page detection inputs. Usage
// and status are returned even on failure; Body is populated only on success.
type AssetResponse struct {
	StatusCode int
	Usage      BodyUsage
	Body       []byte
}

// FetchAsset performs a GET without redirects, cookies or referrers. There is no
// application retry loop; the shared transport retains normal connection handling.
// Page redirect/downgrade settings do not relax this policy. All bodies are closed.
func (c *Client) FetchAsset(ctx context.Context, rawURL string, options AssetOptions) (result AssetResponse, err error) {
	if options.MaxBodyBytes <= 0 || options.MaxBodyBytes == math.MaxInt64 || options.MaxEncodedBodyBytes <= 0 || options.MaxEncodedBodyBytes == math.MaxInt64 || len(options.MediaTypes) == 0 {
		return result, errors.New("invalid asset body limits or media types")
	}
	target, err := ParseURL(rawURL)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return result, safeRequestError(err)
	}
	req.Header.Set("User-Agent", "webscan")
	req.Header.Set("Accept-Encoding", "gzip")
	client := &http.Client{
		Transport:     c.transport,
		Timeout:       c.options.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return result, safeRequestError(err)
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return result, ErrAssetRedirect
	}
	// Partial representations must not masquerade as complete assets.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != "" {
		return result, ErrAssetStatus
	}
	values := resp.Header.Values("Content-Type")
	if len(values) != 1 {
		return result, ErrAssetMediaType
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	if err != nil {
		return result, ErrAssetMediaType
	}
	accepted := false
	for _, allowed := range options.MediaTypes {
		accepted = accepted || mediaType == allowed
	}
	if !accepted {
		return result, ErrAssetMediaType
	}
	result.Body, result.Usage, err = readBodyMeasured(resp, options.MaxBodyBytes, options.MaxEncodedBodyBytes)
	return result, err
}
