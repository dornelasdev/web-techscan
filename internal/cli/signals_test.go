package cli

import (
	"net/http"
	"testing"
)

func TestHTMLResponseSelection(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		wantHTML                bool
	}{
		{"html", "text/html; charset=utf-8", "<html>marker</html>", true},
		{"xhtml", "application/xhtml+xml", "<html/>", true},
		{"sniffed html", "", "<!doctype html><html>marker</html>", true},
		{"explicit plain text", "text/plain", "<html>marker</html>", false},
		{"json", "application/json", `{"example":"<html>marker</html>"}`, false},
		{"script", "application/javascript", `var html = "<html>marker</html>"`, false},
		{"binary", "application/octet-stream", "<html>marker</html>", false},
		{"invalid type", "not a type", "<html>marker</html>", false},
		{"empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(http.Header)
			if tc.contentType != "" {
				headers.Set("Content-Type", tc.contentType)
			}
			got := htmlForDetection(headers, []byte(tc.body))
			if (got != nil) != tc.wantHTML {
				t.Fatalf("selected HTML = %q, want HTML = %t", got, tc.wantHTML)
			}
			if tc.wantHTML && string(got) != tc.body {
				t.Errorf("body changed: %q", got)
			}
		})
	}
}
