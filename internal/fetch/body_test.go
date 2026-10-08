package fetch

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func gzipBytes(t *testing.T, text string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := io.WriteString(w, text); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestBodyEncodingAndIntegrity(t *testing.T) {
	plain := strings.Repeat("x", 32)
	compressed := gzipBytes(t, plain)
	badCRC := append([]byte(nil), compressed...)
	badCRC[len(badCRC)-8] ^= 1
	for _, tc := range []struct {
		name     string
		encoding []string
		wire     []byte
		want     string
		wantErr  error
	}{
		{"plain", nil, []byte(plain), plain, nil},
		{"identity", []string{"Identity"}, []byte(plain), plain, nil},
		{"gzip", []string{"gzip"}, compressed, plain, nil},
		{"gzip-case-space", []string{" GZip\t"}, compressed, plain, nil},
		{"empty-gzip", []string{"gzip"}, gzipBytes(t, ""), "", nil},
		{"two-members", []string{"gzip"}, append(gzipBytes(t, "one"), gzipBytes(t, "two")...), "onetwo", nil},
		{"expanded-limit", []string{"gzip"}, gzipBytes(t, strings.Repeat("x", 16384)), "", ErrBodyLimit},
		{"members-limit", []string{"gzip"}, append(compressed, compressed...), "", ErrBodyLimit},
		{"plain-limit", nil, []byte(plain + "x"), "", ErrBodyLimit},
		{"br", []string{"br"}, []byte(plain), "", ErrContentEncoding},
		{"deflate", []string{"deflate"}, []byte(plain), "", ErrContentEncoding},
		{"stacked", []string{"gzip, br"}, compressed, "", ErrContentEncoding},
		{"repeated", []string{"gzip", "br"}, compressed, "", ErrContentEncoding},
		{"duplicate-gzip", []string{"gzip", "gzip"}, compressed, "", ErrContentEncoding},
		{"empty-field", []string{""}, []byte(plain), "", ErrContentEncoding},
		{"private-unknown", []string{"private-encoding"}, []byte(plain), "", ErrContentEncoding},
		{"bad-header", []string{"gzip"}, []byte("private-not-gzip-data"), "", gzip.ErrHeader},
		{"missing-stream", []string{"gzip"}, nil, "", io.EOF},
		{"truncated-trailer", []string{"gzip"}, compressed[:len(compressed)-4], "", io.ErrUnexpectedEOF},
		{"checksum-at-exact-limit", []string{"gzip"}, badCRC, "", gzip.ErrChecksum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := bytes.NewReader(tc.wire)
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": {"123"}}, Body: io.NopCloser(raw)}
			if tc.encoding != nil {
				resp.Header["Content-Encoding"] = tc.encoding
			}
			body, err := readBody(resp, 32)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || body != nil {
					t.Fatalf("body=%q err=%v want=%v", body, err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "private-") {
					t.Errorf("raw value exposed: %v", err)
				}
				if tc.wantErr == ErrContentEncoding && raw.Len() != len(tc.wire) {
					t.Error("unsupported encoding body was read")
				}
				return
			}
			if err != nil || string(body) != tc.want {
				t.Fatalf("body=%q err=%v want=%q", body, err, tc.want)
			}
			if len(tc.encoding) == 1 && strings.EqualFold(strings.TrimSpace(tc.encoding[0]), "gzip") {
				if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Length") != "" {
					t.Error("encoded-body headers retained after decoding")
				}
			}
		})
	}
}

func TestNoBodyStatusesIgnoreRepresentationEncoding(t *testing.T) {
	for _, status := range []int{204, 304} {
		resp := &http.Response{StatusCode: status, Header: http.Header{"Content-Encoding": {"gzip"}}, Body: http.NoBody}
		body, err := readBody(resp, 32)
		if err != nil || len(body) != 0 {
			t.Fatalf("status=%d body=%q err=%v", status, body, err)
		}
	}
}

func TestBodyErrorDoesNotExposeRawCause(t *testing.T) {
	cause := errors.New("private-response-data")
	err := safeBodyError(cause)
	if strings.Contains(err.Error(), "private-response-data") || !errors.Is(err, cause) {
		t.Fatalf("unsafe diagnostic or lost cause: %v", err)
	}
}
