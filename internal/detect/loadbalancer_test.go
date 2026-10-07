package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func TestLoadBalancerCookiePairs(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct{ id, base, cors string }{
		{"aws-alb", "AWSALB", "AWSALBCORS"},
		{"aws-clb", "AWSELB", "AWSELBCORS"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			for _, names := range [][]string{
				{tc.base, tc.cors}, {tc.cors, "session", tc.base, tc.base, tc.cors},
			} {
				got := engine.Detect(detect.Input{CookieNames: names})
				if len(got) != 1 || got[0].ID != tc.id || got[0].Category != detect.LoadBalancer || got[0].State != detect.Inferred {
					t.Fatalf("cookies=%v findings=%+v, want only inferred %s", names, got, tc.id)
				}
				evidence := got[0].Evidence
				if len(evidence) != 1 || evidence[0].RuleID != "stickiness-cookie-pair" || evidence[0].InferredFrom != "" || !reflect.DeepEqual(evidence[0].Signals, []detect.Signal{{Source: detect.Cookie}, {Source: detect.Cookie}}) {
					t.Fatalf("unexpected paired-cookie evidence: %+v", evidence)
				}
				if !strings.Contains(evidence[0].Description, tc.base) || !strings.Contains(evidence[0].Description, tc.cors) {
					t.Error("description must identify both supporting cookie names")
				}
			}
			for _, names := range [][]string{
				nil, {tc.base}, {tc.cors}, {tc.base, tc.base},
				{strings.ToLower(tc.base), tc.cors}, {tc.base, strings.ToLower(tc.cors)},
				{"not" + tc.base, tc.cors}, {tc.base + "_extra", tc.cors},
				{tc.base, tc.cors + "_extra"}, {tc.base + " ", tc.cors},
				{tc.base, tc.cors + "\n"}, {tc.base + "=value", tc.cors + "=value"},
			} {
				if got := engine.Detect(detect.Input{CookieNames: names}); len(got) != 0 {
					t.Errorf("near miss %v produced %+v", names, got)
				}
			}
			// Marker text in HTML or raw headers is not cookie-name evidence.
			input := detect.Input{
				HTML:    []byte(tc.base + " " + tc.cors),
				Headers: http.Header{"Set-Cookie": {tc.base + "=value", tc.cors + "=value"}},
			}
			if got := engine.Detect(input); len(got) != 0 {
				t.Errorf("wrong signal locations produced %+v", got)
			}
		})
	}
}

func TestLoadBalancerCoverageBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, names := range [][]string{
		{"AWSALB", "AWSELBCORS"}, {"AWSELB", "AWSALBCORS"},
		{"AWSALBAPP-0", "AWSALBAPP-1"}, {"AWSALBTG", "AWSALBTGCORS"},
		{"session", "route", "SERVERID"},
	} {
		if got := engine.Detect(detect.Input{CookieNames: names}); len(got) != 0 {
			t.Errorf("unsupported pair %v produced %+v", names, got)
		}
	}
	got := engine.Detect(detect.Input{
		CookieNames: []string{"AWSALB", "AWSALBCORS", "AWSELB", "AWSELBCORS"},
		Headers:     http.Header{"CF-Ray": {"230b030023ae2822-SJC"}, "X-Powered-By": {"Express"}},
	})
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
		want := detect.Detected
		if finding.Category == detect.LoadBalancer {
			want = detect.Inferred
		}
		if finding.State != want || len(finding.Evidence) != 1 || finding.Evidence[0].InferredFrom != "" {
			t.Errorf("unexpected state or implication: %+v", finding)
		}
	}
	if !reflect.DeepEqual(ids, []string{"aws-alb", "aws-clb", "cloudflare", "express"}) {
		t.Fatalf("unexpected mixed stack or extra capability inference: %v", ids)
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Errorf("findings leaked between scans: %+v", got)
	}
}
