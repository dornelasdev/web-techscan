// Package fetch retrieves a bounded HTTP response for offline inspection.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

var (
	ErrRedirectLimit = errors.New("redirect limit exceeded")
	ErrBodyLimit     = errors.New("response body limit exceeded")
)

// Options bounds a complete fetch, including redirects and body reading.
type Options struct {
	Timeout      time.Duration
	MaxRedirects int
	MaxBodyBytes int64
}

func DefaultOptions() Options {
	return Options{
		Timeout:      15 * time.Second,
		MaxRedirects: 5,
		MaxBodyBytes: 2 << 20,
	}
}

// Redirect records a followed hop without mixing its headers into the final page.
type Redirect struct {
	FromURL    string
	ToURL      string
	StatusCode int
}

// Snapshot contains only the final response's detection inputs. Set-Cookie
// headers are excluded; CookieNames holds their deduplicated names instead.
type Snapshot struct {
	OriginalURL string
	FinalURL    string
	StatusCode  int
	Headers     http.Header
	CookieNames []string
	Body        []byte
	Redirects   []Redirect
}

// Client reuses connections while keeping each fetch's redirect state separate.
type Client struct {
	options   Options
	transport *http.Transport
}

func New(options Options) (*Client, error) {
	if options.Timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	if options.MaxRedirects < 0 {
		return nil, errors.New("max-redirects must not be negative")
	}
	if options.MaxBodyBytes <= 0 || options.MaxBodyBytes == math.MaxInt64 {
		return nil, errors.New("max-body must be positive and less than 9223372036854775807")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 1 << 20
	return &Client{options: options, transport: transport}, nil
}

func (c *Client) CloseIdleConnections() {
	c.transport.CloseIdleConnections()
}

// Fetch issues GET requests only. HTTP error statuses still produce snapshots;
// network failures and exceeded limits return an error without partial results.
func (c *Client) Fetch(ctx context.Context, rawURL string) (*Snapshot, error) {
	target, err := ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "webscan")

	var redirects []Redirect
	client := &http.Client{
		Transport: c.transport,
		Timeout:   c.options.Timeout,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) > c.options.MaxRedirects {
				return fmt.Errorf("%w (maximum %d)", ErrRedirectLimit, c.options.MaxRedirects)
			}
			clean, err := ParseURL(next.URL.String())
			if err != nil {
				// A server's bad redirect is an execution error, not bad CLI input.
				return fmt.Errorf("invalid redirect target: %s", err)
			}
			next.URL = clean
			redirects = append(redirects, Redirect{
				FromURL:    via[len(via)-1].URL.String(),
				ToURL:      clean.String(),
				StatusCode: next.Response.StatusCode,
			})
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch page: %w", err)
	}
	defer resp.Body.Close()

	// Read one extra byte to distinguish an exact fit from an oversized body.
	// This also bounds chunked responses and transparently decompressed gzip.
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.options.MaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > c.options.MaxBodyBytes {
		return nil, fmt.Errorf("%w (maximum %d bytes)", ErrBodyLimit, c.options.MaxBodyBytes)
	}

	var cookieNames []string
	seen := make(map[string]bool)
	for _, cookie := range resp.Cookies() {
		if !seen[cookie.Name] {
			cookieNames = append(cookieNames, cookie.Name)
			seen[cookie.Name] = true
		}
	}
	headers := resp.Header.Clone()
	headers.Del("Set-Cookie")

	return &Snapshot{
		OriginalURL: target.String(),
		FinalURL:    resp.Request.URL.String(),
		StatusCode:  resp.StatusCode,
		Headers:     headers,
		CookieNames: cookieNames,
		Body:        body,
		Redirects:   redirects,
	}, nil
}
