package detect_test

import (
	"net/http"
	"reflect"
	"testing"

	"webscan/internal/detect"
)

func TestAWSWAFActionHeader(t *testing.T) {
	engine := bundledEngine(t)
	for _, value := range []string{"challenge", "captcha", " challenge\t", "\tcaptcha "} {
		got := engine.Detect(detect.Input{Headers: http.Header{
			"x-amzn-waf-action": {"unrelated", value, value},
		}})
		if len(got) != 1 || got[0].ID != "aws-waf" || got[0].Category != detect.WAF || got[0].State != detect.Detected {
			t.Fatalf("value=%q findings=%+v, want only detected AWS WAF", value, got)
		}
		evidence := got[0].Evidence
		if len(evidence) != 1 || evidence[0].RuleID != "action-header" || evidence[0].InferredFrom != "" || !reflect.DeepEqual(evidence[0].Signals, []detect.Signal{{Source: detect.Header, Name: "X-Amzn-Waf-Action"}}) {
			t.Fatalf("unexpected action evidence: %+v", evidence)
		}
	}
	for _, value := range []string{
		"", " ", "block", "allow", "count", "CHALLENGE", "Captcha",
		"challenge-extra", "notcaptcha", "prefix challenge", "captcha suffix",
		"challenge,captcha", "challenge; mode=1", `"challenge"`, "challenge\n",
	} {
		if got := engine.Detect(detect.Input{Headers: http.Header{"X-Amzn-Waf-Action": {value}}}); len(got) != 0 {
			t.Errorf("near miss %q produced %+v", value, got)
		}
	}
	for _, input := range []detect.Input{
		{},
		{Headers: http.Header{"X-Waf-Action": {"challenge"}, "X-Amzn-Waf-Action-Example": {"captcha"}}},
		{HTML: []byte("AWS WAF X-Amzn-Waf-Action: challenge captcha access denied")},
		{CookieNames: []string{"aws-waf-token", "challenge", "captcha"}},
	} {
		if got := engine.Detect(input); len(got) != 0 {
			t.Errorf("unsupported signals produced %+v", got)
		}
	}
}

func TestWAFRequiresIndependentEvidence(t *testing.T) {
	engine := bundledEngine(t)
	input := detect.Input{
		Headers: http.Header{
			"Via":    {"1.1 fixture123.cloudfront.net (CloudFront)"},
			"CF-Ray": {"230b030023ae2822-SJC"}, "X-Powered-By": {"Express"},
		},
		CookieNames: []string{"AWSALB", "AWSALBCORS"},
	}
	for _, withWAF := range []bool{false, true} {
		if withWAF {
			input.Headers.Set("X-Amzn-Waf-Action", "challenge")
		}
		got := engine.Detect(input)
		var ids []string
		for _, finding := range got {
			ids = append(ids, finding.ID)
			wantState := detect.Detected
			if finding.ID == "aws-alb" {
				wantState = detect.Inferred
			}
			if finding.State != wantState || len(finding.Evidence) != 1 || finding.Evidence[0].InferredFrom != "" {
				t.Errorf("unexpected evidence/state: %+v", finding)
			}
		}
		want := []string{"aws-alb", "cloudflare", "cloudfront", "express"}
		if withWAF {
			want = []string{"aws-alb", "aws-waf", "cloudflare", "cloudfront", "express"}
		}
		if !reflect.DeepEqual(ids, want) {
			t.Fatalf("withWAF=%v IDs=%v want=%v", withWAF, ids, want)
		}
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Errorf("findings leaked between scans: %+v", got)
	}
}
