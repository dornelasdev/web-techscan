package output_test

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestCatalogOrderingAndRendering(t *testing.T) {
	items := []detect.TechnologyInfo{
		{ID: "php", Name: "PHP", Category: detect.Language},
		{ID: "nginx", Name: "nginx", Category: detect.WebServer},
		{ID: "nextjs", Name: "Next.js", Category: detect.Framework},
		{ID: "bootstrap", Name: "Bootstrap", Category: detect.UIFramework},
		{ID: "apache", Name: "Apache HTTP Server", Category: detect.WebServer},
		{ID: "wordpress", Name: "WordPress", Category: detect.CMS},
		{ID: "cloudflare", Name: "Cloudflare", Category: detect.CDN},
		{ID: "cloudfront", Name: "Amazon CloudFront", Category: detect.CDN},
	}
	report := output.NewCatalogReport(items)
	items[0].Name = "changed"
	wantIDs := []string{"apache", "nginx", "nextjs", "bootstrap", "wordpress", "php", "cloudfront", "cloudflare"}
	var ids []string
	for _, item := range report.Technologies {
		ids = append(ids, item.ID)
	}
	if !reflect.DeepEqual(ids, wantIDs) || report.Technologies[5].Name != "PHP" {
		t.Fatalf("unexpected ordering or shared metadata: %+v", report)
	}
	var terminal, json bytes.Buffer
	if err := output.CatalogTerminal(&terminal, report); err != nil {
		t.Fatal(err)
	}
	want := "Supported technologies (8)\n\nWeb servers\n  Apache HTTP Server\n  nginx\n\nFrameworks\n  Next.js\n\nUI frameworks\n  Bootstrap\n\nCMS\n  WordPress\n\nLanguages\n  PHP\n\nCDN/edge\n  Amazon CloudFront\n  Cloudflare\n\nCoverage depends on exposed signals; identification is not guaranteed.\n"
	if terminal.String() != want {
		t.Errorf("terminal=%q, want %q", terminal.String(), want)
	}
	if err := output.CatalogJSON(&json, output.NewCatalogReport([]detect.TechnologyInfo{{ID: "php", Name: "PHP", Category: detect.Language}})); err != nil {
		t.Fatal(err)
	}
	wantJSON := "{\n  \"schema_version\": 1,\n  \"catalog_size\": 1,\n  \"technologies\": [\n    {\n      \"id\": \"php\",\n      \"name\": \"PHP\",\n      \"category\": \"language\"\n    }\n  ]\n}\n"
	if json.String() != wantJSON {
		t.Errorf("JSON=%s, want %s", &json, wantJSON)
	}
}

func TestInfrastructureCatalogOrdering(t *testing.T) {
	report := output.NewCatalogReport([]detect.TechnologyInfo{
		{ID: "aws-waf", Name: "AWS WAF", Category: detect.WAF},
		{ID: "aws-clb", Name: "AWS Classic Load Balancer", Category: detect.LoadBalancer},
		{ID: "aws-alb", Name: "AWS Application Load Balancer", Category: detect.LoadBalancer},
		{ID: "cloudflare", Name: "Cloudflare", Category: detect.CDN},
	})
	var ids []string
	for _, item := range report.Technologies {
		ids = append(ids, item.ID)
	}
	if !reflect.DeepEqual(ids, []string{"cloudflare", "aws-alb", "aws-clb", "aws-waf"}) {
		t.Fatalf("unexpected category/name order: %v", ids)
	}
	var terminal bytes.Buffer
	if err := output.CatalogTerminal(&terminal, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(terminal.String(), "\nLoad balancers\n  AWS Application Load Balancer\n  AWS Classic Load Balancer\n") {
		t.Errorf("missing load balancer group: %s", &terminal)
	}
	if !strings.Contains(terminal.String(), "\nWAFs\n  AWS WAF\n") {
		t.Errorf("missing WAF group: %s", &terminal)
	}
}

func TestCatalogEmptyAndSafeTerminal(t *testing.T) {
	var terminal, json bytes.Buffer
	if err := output.CatalogTerminal(&terminal, output.NewCatalogReport(nil)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(terminal.String(), "Supported technologies (0)") || !strings.Contains(terminal.String(), "No technologies bundled.") {
		t.Errorf("unexpected empty catalog: %s", &terminal)
	}
	if err := output.CatalogJSON(&json, output.NewCatalogReport(nil)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(json.String(), `"technologies": []`) {
		t.Errorf("empty collection must be an array: %s", &json)
	}
	terminal.Reset()
	report := output.NewCatalogReport([]detect.TechnologyInfo{{ID: "unsafe", Name: "bad\x1b[31m\nname", Category: detect.Framework}})
	if err := output.CatalogTerminal(&terminal, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(terminal.String(), "\x1b") || strings.Contains(terminal.String(), "\nname") {
		t.Errorf("unsafe terminal output: %q", terminal.String())
	}
}

func TestCatalogWriterFailures(t *testing.T) {
	failure := errors.New("output closed")
	for _, render := range []func(io.Writer, output.CatalogReport) error{output.CatalogJSON, output.CatalogTerminal} {
		if err := render(failingWriter{failure}, output.NewCatalogReport(nil)); !errors.Is(err, failure) {
			t.Errorf("error=%v, want writer failure", err)
		}
		if err := render(failingWriter{}, output.NewCatalogReport(nil)); !errors.Is(err, io.ErrShortWrite) {
			t.Errorf("error=%v, want short write", err)
		}
	}
}
