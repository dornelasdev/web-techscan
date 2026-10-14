package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"webscan/internal/detect"
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
	if report.QueryRedacted {
		fmt.Fprintln(&text, "Query strings redacted in this report.")
	}
	if report.ResponseScope == "http_error_response" {
		fmt.Fprintln(&text, "Findings describe the returned HTTP error page.")
	}
	if assets := report.Assets; assets != nil {
		fmt.Fprintf(&text, "Assets: %s — %d collected / %d attempted (direct same-origin scope)\n",
			plain(assets.Status), assets.Collected, assets.Attempted)
		budget := assets.Budget
		fmt.Fprintf(&text, "  Budget: %s; per asset %d decoded / %d encoded bytes; combined %d decoded / %d encoded bytes\n",
			plain(budget.Profile), budget.MaxAssetDecodedBytes, budget.MaxAssetEncodedBytes, budget.MaxTotalDecodedBytes, budget.MaxTotalEncodedBytes)
		if assets.Reason != "" {
			fmt.Fprintf(&text, "  Reason: %s\n", plain(assets.Reason))
		}
		fmt.Fprintf(&text, "  Payload read: %d decoded / %d encoded bytes (includes failed reads/probes)\n", assets.DecodedBytes, assets.EncodedBytes)
		fmt.Fprintf(&text, "  Excluded declarations: %d; retained duplicates: %d; reference limit reached: %t\n",
			assets.SkippedDeclarations, assets.Duplicates, assets.Truncated)
		for _, item := range assets.Items {
			fmt.Fprintf(&text, "  - %s [%s] %s", plain(item.Status), plain(item.Kind), plain(item.URL))
			if item.Reason != "" {
				fmt.Fprintf(&text, " (%s)", plain(item.Reason))
			}
			fmt.Fprintln(&text)
		}
		fmt.Fprintln(&text, "  Captured assets are checked against supported content fingerprints; scripts are not executed.")
		fmt.Fprintln(&text)
	}
	if report.CatalogSize == 0 {
		fmt.Fprintln(&text, "No fingerprints bundled; technology detection coverage is unavailable.")
	} else if len(report.Findings) == 0 {
		fmt.Fprintln(&text, "No technologies detected.")
	} else {
		for _, finding := range report.Findings {
			info, _ := detect.Category(finding.Category).Info()
			fmt.Fprintf(&text, "%s %s [%s]\n", marker(finding.State, color), plain(finding.Name), plain(info.Label))
			for _, evidence := range finding.Evidence {
				fmt.Fprintf(&text, "  - %s\n", plain(evidence.Description))
				if evidence.AssetURL != "" {
					fmt.Fprintf(&text, "    Asset: %s\n", plain(evidence.AssetURL))
				}
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

// Keep displayed values from inserting terminal controls, explicit bidi controls,
// or extra lines. Do not strip all Unicode format characters: joiners used in
// ordinary scripts and emoji remain intact. This is not a homoglyph defense.
func plain(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == '\u2028' || r == '\u2029' {
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
