package detect_test

import (
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func fixtureEngine(t *testing.T) *detect.Engine {
	t.Helper()
	engine, err := detect.Load(os.DirFS("testdata"))
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestMatchingAndInference(t *testing.T) {
	engine := fixtureEngine(t)
	input := detect.Input{
		Headers: http.Header{
			"x-framework": {"unrelated", "Sample"},
			"SERVER":      {"samplehttp/1.2"},
			"X-Language":  {"SampleLang"},
			"Set-Cookie":  {"sample_session=do-not-leak-this"},
		},
		CookieNames: []string{"sample_session", "sample_session"},
		HTML:        []byte(`<script src="/sample/runtime.js"></script>`),
	}
	got := engine.Detect(input)
	wantIDs := []string{"sample-framework", "sample-language", "sample-runtime", "sample-server"}
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
		if len(finding.Evidence) == 0 {
			t.Errorf("missing evidence: %+v", finding)
		}
		wantState := detect.Detected
		if finding.ID == "sample-runtime" {
			wantState = detect.Inferred
		}
		if finding.State != wantState {
			t.Errorf("%s state=%s, want %s", finding.ID, finding.State, wantState)
		}
	}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("IDs=%v, want %v", ids, wantIDs)
	}
	if len(got[0].Evidence) != 2 {
		t.Errorf("expected both matching rules once: %+v", got[0].Evidence)
	}
	if len(got[0].Evidence[0].Signals) != 2 {
		t.Errorf("combined rule lost its signal locations: %+v", got[0].Evidence)
	}
	var parents []string
	for _, evidence := range got[1].Evidence {
		if evidence.InferredFrom != "" {
			parents = append(parents, evidence.InferredFrom)
		}
	}
	if !reflect.DeepEqual(parents, []string{"sample-framework", "sample-server"}) {
		t.Errorf("inference parents=%v", parents)
	}
	if got[2].Evidence[0].InferredFrom != "sample-language" {
		t.Errorf("inference chain lost its source: %+v", got[2])
	}
	if strings.Contains(fmt.Sprint(got), "do-not-leak-this") {
		t.Error("raw response value leaked into evidence")
	}
	if again := engine.Detect(input); !reflect.DeepEqual(got, again) {
		t.Error("results changed between equivalent scans")
	}
	// Results must not share mutable evidence with later calls.
	got[0].Evidence[0].Signals[0].Name = "modified"
	if engine.Detect(input)[0].Evidence[0].Signals[0].Name == "modified" {
		t.Error("result mutation leaked into the engine")
	}
}

func TestNoFindingsForMissingOrNearMissSignals(t *testing.T) {
	engine := fixtureEngine(t)
	for _, input := range []detect.Input{
		{},
		{Headers: http.Header{"X-Framework": {"Sample"}}},
		{CookieNames: []string{"sample_session"}},
		{Headers: http.Header{"X-Framework": {"Sample"}}, CookieNames: []string{"sample_session_extra"}},
		{Headers: http.Header{"X-Framework": {"Sample"}, "Set-Cookie": {"sample_session=secret"}}},
		{Headers: http.Header{"Server": {"NotSampleHTTP"}}},
		{HTML: []byte(`<script src="/another/runtime.js"></script>`)},
	} {
		if got := engine.Detect(input); got == nil || len(got) != 0 {
			t.Errorf("findings=%+v, want empty non-nil slice", got)
		}
	}
}

func TestIndirectRuleDoesNotBecomeDetected(t *testing.T) {
	got := fixtureEngine(t).Detect(detect.Input{HTML: []byte(`<script src="/sample/runtime.js"></script>`)})
	if len(got) != 3 {
		t.Fatalf("findings=%+v, want framework, language and runtime", got)
	}
	for _, finding := range got {
		if finding.State != detect.Inferred {
			t.Errorf("indirect signal became detected: %+v", finding)
		}
	}
}

func TestBundledCatalogLoads(t *testing.T) {
	if _, err := detect.LoadBundled(); err != nil {
		t.Fatal(err)
	}
}
