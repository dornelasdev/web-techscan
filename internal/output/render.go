package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// JSON writes one document followed by a newline, with no terminal styling.
func JSON(w io.Writer, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return write(w, append(data, '\n'))
}

// Terminal formats a complete report before writing it. State is communicated
// by symbols and a legend even when colors are disabled.
func Terminal(w io.Writer, report Report, color bool) error {
	var text strings.Builder
	fmt.Fprintf(&text, "URL: %s\nHTTP status: %d\nRedirects: %d\nBody: %d bytes\n\n",
		plain(report.FinalURL), report.HTTPStatus, len(report.Redirects), report.BodyBytes)
	if report.ResponseScope == "http_error_response" {
		fmt.Fprintln(&text, "Findings describe the returned HTTP error page.")
	}
	if report.CatalogSize == 0 {
		fmt.Fprintln(&text, "No fingerprints bundled; technology detection coverage is unavailable.")
	} else if len(report.Findings) == 0 {
		fmt.Fprintln(&text, "No technologies detected.")
	} else {
		for _, finding := range report.Findings {
			category := finding.Category
			if category == "web_server" {
				category = "web server"
			} else if category == "cms" {
				category = "CMS"
			} else if category == "cdn" {
				category = "CDN/edge"
			} else if category == "load_balancer" {
				category = "load balancer"
			} else if category == "waf" {
				category = "WAF"
			}
			fmt.Fprintf(&text, "%s %s [%s]\n", marker(finding.State, color), plain(finding.Name), plain(category))
			for _, evidence := range finding.Evidence {
				fmt.Fprintf(&text, "  - %s\n", plain(evidence.Description))
			}
		}
		fmt.Fprintf(&text, "\n%s Detected  %s Inferred\n", marker("detected", color), marker("inferred", color))
	}
	return write(w, []byte(text.String()))
}

func marker(state string, color bool) string {
	symbol, code := "?", "33"
	if state == "detected" {
		symbol, code = "✓", "32"
	}
	if color {
		return "\x1b[" + code + "m" + symbol + "\x1b[0m"
	}
	return symbol
}

// Keep response-derived text from inserting terminal controls or extra lines.
func plain(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, value)
}

func write(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
