package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func TestCDNHeaders(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		id, header, rule   string
		positive, negative []string
	}{
		{"cloudflare", "CF-Ray", "ray-header",
			[]string{"230b030023ae2822-SJC", " ABCDEF0123456789-lis\t"},
			[]string{"", " ", "cloudflare", "230b030023ae2822", "230b030023ae282-SJC", "230b030023ae28222-SJC", "230b030023ae282g-SJC", "230b030023ae2822-SJ", "230b030023ae2822-SJC-extra", "prefix 230b030023ae2822-SJC", "230b030023ae2822-SJC\n", "230b030023ae2822-SJC, 230b030023ae2822-LIS"}},
		{"cloudfront", "Via", "via-header",
			[]string{"1.1 fixture123.cloudfront.net (CloudFront)", " 2 ABC123.CLOUDFRONT.NET\t(cloudfront) "},
			[]string{"", "1.1 proxy", "CloudFront", "1.1 fixture.cloudfront.net", "1.1 fixture.cloudfront.net (Other)", "1.1 fixture.cloudfront.net (CloudFrontish)", "1.1 fixture.cloudfront.net.example.test (CloudFront)", "1.1 fixture.notcloudfront.net (CloudFront)", "1.1 cloudfront.net (CloudFront)", "1.1 fixture.cloudfrontXnet (CloudFront)", "x fixture.cloudfront.net (CloudFront)", "1.1 fixture.cloudfront.net (CloudFront) extra", "1.1 proxy (example 1.1 fixture.cloudfront.net (CloudFront))", "1.1 fixture.cloudfront.net (CloudFront)\n",
				// Combined Via lists are deliberately outside this first rule.
				"1.1 proxy, 1.1 fixture.cloudfront.net (CloudFront)"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			for _, value := range tc.positive {
				// Repeated fields still yield exactly one evidence entry.
				got := engine.Detect(detect.Input{Headers: http.Header{strings.ToLower(tc.header): {"unrelated", value, value}}})
				if len(got) != 1 || got[0].ID != tc.id || got[0].Category != detect.CDN || got[0].State != detect.Detected {
					t.Fatalf("header=%q findings=%+v, want only detected %s", value, got, tc.id)
				}
				evidence := got[0].Evidence
				// The loader stores header names in Go's canonical form.
				wantHeader := http.CanonicalHeaderKey(tc.header)
				if len(evidence) != 1 || evidence[0].RuleID != tc.rule || evidence[0].InferredFrom != "" || !reflect.DeepEqual(evidence[0].Signals, []detect.Signal{{Source: detect.Header, Name: wantHeader}}) {
					t.Fatalf("unexpected evidence: %+v", evidence)
				}
				if strings.Contains(evidence[0].Description, strings.TrimSpace(value)) {
					t.Error("evidence must not expose raw header values")
				}
			}
			for _, value := range tc.negative {
				if got := engine.Detect(detect.Input{Headers: http.Header{tc.header: {value}}}); len(got) != 0 {
					t.Errorf("near miss %q produced %+v", value, got)
				}
			}
			for _, input := range []detect.Input{
				{Headers: http.Header{"X-Example": {tc.positive[0]}}},
				{HTML: []byte(tc.header + ": " + tc.positive[0])},
				{CookieNames: []string{tc.positive[0]}},
			} {
				if got := engine.Detect(input); len(got) != 0 {
					t.Errorf("wrong signal location produced %+v", got)
				}
			}
		})
	}
}

func TestCDNCoverageBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	// These may merit later rules, but are not enough for this initial coverage.
	for _, headers := range []http.Header{
		{"Server": {"cloudflare"}}, {"Server": {"CloudFront"}},
		{"CF-Cache-Status": {"HIT"}}, {"X-Cache": {"Hit from cloudfront"}},
		{"X-Amz-Cf-Id": {"example"}, "X-Amz-Cf-Pop": {"LIS50-P1"}},
		{"Via": {"1.1 proxy"}, "X-Cache": {"HIT"}},
	} {
		if got := engine.Detect(detect.Input{Headers: headers}); len(got) != 0 {
			t.Errorf("unsupported signals produced %+v", got)
		}
	}
	got := engine.Detect(detect.Input{Headers: http.Header{
		"CF-Ray": {"230b030023ae2822-SJC"},
		"Via":    {"1.1 fixture123.cloudfront.net (CloudFront)"},
		"Server": {"nginx"}, "X-Powered-By": {"Express"},
	}})
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
		if finding.State != detect.Detected || len(finding.Evidence) != 1 || finding.Evidence[0].InferredFrom != "" {
			t.Errorf("unexpected state or inferred relationship: %+v", finding)
		}
	}
	if !reflect.DeepEqual(ids, []string{"cloudflare", "cloudfront", "express", "nginx"}) {
		t.Fatalf("unexpected mixed stack or extra capability inference: %v", ids)
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Errorf("findings leaked between scans: %+v", got)
	}
}
