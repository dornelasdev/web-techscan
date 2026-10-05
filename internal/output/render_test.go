package output_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"webscan/internal/detect"
	"webscan/internal/fetch"
	"webscan/internal/output"
)

func sampleReport() output.Report {
	return output.NewReport(fetch.Snapshot{
		OriginalURL: "http://example.test/", FinalURL: "https://example.test/", StatusCode: 200,
		Body: []byte("secret-body"), Headers: http.Header{"Set-Cookie": {"session=secret-cookie"}},
		Redirects: []fetch.Redirect{{FromURL: "http://example.test/", ToURL: "https://example.test/", StatusCode: 301}},
	}, []detect.Finding{
		{ID: "nginx", Name: "nginx", Category: detect.WebServer, State: detect.Detected,
			Evidence: []detect.Evidence{{RuleID: "server-header", Description: "Server header reports nginx", Signals: []detect.Signal{{Source: detect.Header, Name: "Server"}}}}},
		{ID: "php", Name: "PHP", Category: detect.Language, State: detect.Inferred,
			Evidence: []detect.Evidence{{Description: "Inferred from Laravel", InferredFrom: "laravel"}}},
	}, 7)
}

func TestJSONContract(t *testing.T) {
	want, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := output.JSON(&out, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("JSON contract changed:\n%s\nwant:\n%s", out.Bytes(), want)
	}
	for _, absent := range []string{"secret-body", "secret-cookie", "\x1b", "✓"} {
		if strings.Contains(out.String(), absent) {
			t.Errorf("JSON contains unexpected value %q", absent)
		}
	}
}

func TestTerminalMarkersAndColor(t *testing.T) {
	want := "URL: https://example.test/\nHTTP status: 200\nRedirects: 1\nBody: 11 bytes\n\n" +
		"✓ nginx [web server]\n  - Server header reports nginx\n" +
		"? PHP [language]\n  - Inferred from Laravel\n\n✓ Detected  ? Inferred\n"
	var plain, colored bytes.Buffer
	if err := output.Terminal(&plain, sampleReport(), false); err != nil {
		t.Fatal(err)
	}
	if plain.String() != want {
		t.Errorf("terminal output=%q, want %q", plain.String(), want)
	}
	if err := output.Terminal(&colored, sampleReport(), true); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"\x1b[32m✓\x1b[0m", "\x1b[33m?\x1b[0m"} {
		if !strings.Contains(colored.String(), marker) {
			t.Errorf("missing color marker %q", marker)
		}
	}
	if strings.Contains(plain.String(), "\x1b") {
		t.Error("plain output contains ANSI escapes")
	}
}

func TestEmptyReportsAndErrorScope(t *testing.T) {
	for _, size := range []int{0, 7} {
		report := output.NewReport(fetch.Snapshot{StatusCode: 403}, nil, size)
		if report.ResponseScope != "http_error_response" {
			t.Errorf("scope=%q", report.ResponseScope)
		}
		var terminal, json bytes.Buffer
		if err := output.Terminal(&terminal, report, false); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(terminal.String(), "Findings describe the returned HTTP error page.") {
			t.Error("missing error-page scope")
		}
		want := "No technologies detected."
		if size == 0 {
			want = "No fingerprints bundled"
		}
		if !strings.Contains(terminal.String(), want) {
			t.Errorf("missing empty-state message %q: %s", want, &terminal)
		}
		if err := output.JSON(&json, report); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{`"redirects": []`, `"findings": []`} {
			if !strings.Contains(json.String(), field) {
				t.Errorf("missing empty array %s: %s", field, &json)
			}
		}
	}
}

func TestReportOwnsEvidence(t *testing.T) {
	findings := []detect.Finding{{ID: "one", Evidence: []detect.Evidence{{Signals: []detect.Signal{{Source: detect.Header, Name: "Server"}}}}}}
	report := output.NewReport(fetch.Snapshot{}, findings, 1)
	findings[0].Evidence[0].Signals[0].Name = "Changed"
	if report.Findings[0].Evidence[0].Signals[0].Name != "Server" {
		t.Error("report shares mutable evidence with detection results")
	}
}

func TestTerminalControlsAreNeutralized(t *testing.T) {
	report := sampleReport()
	report.FinalURL = "https://example.test/\x1b[31m\nforged line"
	report.Findings[0].Name = "bad\rname"
	var out bytes.Buffer
	if err := output.Terminal(&out, report, false); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"\x1b", "\r", "\nforged line"} {
		if strings.Contains(out.String(), absent) {
			t.Errorf("terminal control escaped sanitization: %q", absent)
		}
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriterFailures(t *testing.T) {
	failure := errors.New("output closed")
	for _, render := range []func(io.Writer) error{
		func(w io.Writer) error { return output.JSON(w, sampleReport()) },
		func(w io.Writer) error { return output.Terminal(w, sampleReport(), false) },
	} {
		if err := render(failingWriter{failure}); !errors.Is(err, failure) {
			t.Errorf("error=%v, want writer failure", err)
		}
		if err := render(failingWriter{}); !errors.Is(err, io.ErrShortWrite) {
			t.Errorf("error=%v, want short write", err)
		}
	}
}
