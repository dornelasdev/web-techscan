package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"webscan/internal/detect"
)

func withStatus(rule, bounds string) string {
	return strings.Replace(rule, `"all":`, `"http_status":`+bounds+`,"all":`, 1)
}

func TestHTTPStatusRangeValidation(t *testing.T) {
	for _, bounds := range []string{
		`null`, `{}`, `{"min":400}`, `{"max":599}`, `{"min":0,"max":599}`,
		`{"min":99,"max":599}`, `{"min":400,"max":600}`, `{"min":500,"max":400}`,
		`{"min":-1,"max":599}`, `{"min":400,"max":null}`,
		`{"min":400.5,"max":599}`, `{"min":"400","max":599}`,
		`{"min":400,"max":599,"typo":true}`, `[]`, `400`, `"400-599"`,
	} {
		t.Run(bounds, func(t *testing.T) {
			data := document(technology("example", withStatus(validRule, bounds), ""))
			_, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(data)}})
			if err == nil || !strings.Contains(err.Error(), "http_status") {
				t.Fatalf("error=%v, want invalid http_status", err)
			}
		})
	}
	assetRule := strings.Replace(validRule, `"source":"header","name":"Server"`, `"source":"asset_javascript"`, 1)
	data := document(technology("example", withStatus(assetRule, `{"min":400,"max":599}`), ""))
	if _, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(data)}}); err == nil || !strings.Contains(err.Error(), "only valid for page rules") {
		t.Fatalf("page status must not constrain asset rules: %v", err)
	}
	for _, bounds := range []string{`{"min":100,"max":599}`, `{"min":404,"max":404}`} {
		data := document(technology("example", withStatus(validRule, bounds), ""))
		engine, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(data)}})
		if err != nil {
			t.Fatal(err)
		}
		for _, status := range []int{0, 99, 100, 403, 404, 405, 599, 600} {
			want := status == 404
			if strings.Contains(bounds, `"min":100`) {
				want = status >= 100 && status <= 599
			}
			got := engine.Detect(detect.Input{HTTPStatus: status, Headers: http.Header{"Server": {"Example"}}})
			if (len(got) == 1) != want || len(got) > 1 {
				t.Errorf("bounds=%s status=%d findings=%+v want match=%t", bounds, status, got, want)
			}
		}
	}
}

func TestHTTPStatusGatesRulesAndTheirInferences(t *testing.T) {
	data := document(technology("gated", withStatus(validRule, `{"min":400,"max":599}`), `"language"`) + "," +
		technology("language", "", "") + "," + technology("ungated", validRule, ""))
	engine, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(data)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{-1, 0, 99, 100, 200, 302, 399, 400, 404, 500, 599, 600, 1000} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			input := detect.Input{HTTPStatus: status, Headers: http.Header{"Server": {"Example"}}}
			want := []string{"ungated"}
			if status >= 400 && status <= 599 {
				want = []string{"gated", "language", "ungated"}
			}
			got := engine.Detect(input)
			ids := []string{}
			for _, f := range got {
				ids = append(ids, f.ID)
			}
			if !reflect.DeepEqual(ids, want) {
				t.Fatalf("IDs=%v want=%v", ids, want)
			}
			if len(got) == 3 && (got[1].State != detect.Inferred || len(got[1].Evidence) != 1 || got[1].Evidence[0].InferredFrom != "gated") {
				t.Errorf("unexpected gated inference: %+v", got[1])
			}
			input.Headers = nil
			if missing := engine.Detect(input); len(missing) != 0 {
				t.Fatalf("status alone must not satisfy a rule: %+v", missing)
			}
		})
	}
}
