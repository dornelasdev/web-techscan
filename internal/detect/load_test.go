package detect_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"webscan/internal/detect"
)

const validRule = `{"id":"header","state":"detected","description":"Example header marker","all":[{"source":"header","name":"Server","pattern":"^Example$"}]}`

func document(technologies string) string {
	return `{"schema_version":1,"technologies":[` + technologies + `]}`
}

func technology(id, rules, implies string) string {
	return fmt.Sprintf(`{"id":%q,"name":"Example","category":"framework","rules":[%s],"implies":[%s]}`, id, rules, implies)
}

func TestCatalogValidation(t *testing.T) {
	validTech := technology("example", validRule, "")
	validDoc := document(validTech)
	for _, tc := range []struct{ name, data, want string }{
		{"invalid JSON", `{`, "unexpected EOF"},
		{"unknown field", strings.Replace(validDoc, `"name":"Example"`, `"name":"Example","typo":true`, 1), "unknown field"},
		{"unknown matcher field", strings.Replace(validDoc, `"pattern":`, `"value":"Example","pattern":`, 1), "unknown field"},
		{"multiple documents", validDoc + validDoc, "single JSON document"},
		{"schema version", strings.Replace(validDoc, `"schema_version":1`, `"schema_version":2`, 1), "unsupported schema_version"},
		{"missing technologies", `{"schema_version":1}`, "technologies must be an array"},
		{"null technologies", `{"schema_version":1,"technologies":null}`, "technologies must be an array"},
		{"invalid ID", document(technology("Bad ID", validRule, "")), "lowercase hyphenated ID"},
		{"missing name", strings.Replace(validDoc, `"name":"Example"`, `"name":" "`, 1), "nonempty name"},
		{"category", strings.Replace(validDoc, `"category":"framework"`, `"category":"anything"`, 1), "unknown category"},
		{"state", strings.Replace(validDoc, `"state":"detected"`, `"state":"confirmed"`, 1), "state must be"},
		{"description", strings.Replace(validDoc, `"description":"Example header marker"`, `"description":""`, 1), "description"},
		{"empty matchers", document(technology("example", `{"id":"empty","state":"detected","description":"Empty","all":[]}`, "")), "at least one"},
		{"pattern syntax", strings.Replace(validDoc, `"^Example$"`, `"["`, 1), "invalid pattern"},
		{"empty pattern", strings.Replace(validDoc, `"^Example$"`, `""`, 1), "empty input"},
		{"matches empty", strings.Replace(validDoc, `"^Example$"`, `".*"`, 1), "empty input"},
		{"unknown source", strings.Replace(validDoc, `"source":"header"`, `"source":"dns"`, 1), "unknown source"},
		{"missing header name", strings.Replace(validDoc, `"name":"Server",`, "", 1), "valid name"},
		{"invalid header name", strings.Replace(validDoc, `"name":"Server"`, `"name":"bad header"`, 1), "valid name"},
		{"cookie values", strings.Replace(validDoc, `"name":"Server"`, `"name":"set-cookie"`, 1), "cookie-name matchers"},
		{"cookie matcher name", strings.Replace(validDoc, `"source":"header"`, `"source":"cookie"`, 1), "name is only valid"},
		{"duplicate technology", document(validTech + "," + validTech), "duplicate technology ID"},
		{"duplicate rule", document(technology("example", validRule+","+validRule, "")), "duplicate rule ID"},
		{"missing rule ID", strings.Replace(validDoc, `"id":"header"`, `"id":""`, 1), "rule ID"},
		{"unknown inference", document(technology("example", validRule, `"missing"`)), "unknown technology"},
		{"self cycle", document(technology("example", validRule, `"example"`)), "inference cycle"},
		{"multi-node cycle", document(technology("one", validRule, `"two"`) + "," + technology("two", "", `"one"`)), "inference cycle"},
		{"orphan technology", document(technology("example", "", "")), "needs a rule"},
		{"duplicate inference", document(technology("one", validRule, `"two","two"`) + "," + technology("two", "", "")), "duplicate implication"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(tc.data)}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want to contain %q", err, tc.want)
			}
		})
	}
}

func TestCrossFileRelationships(t *testing.T) {
	engine, err := detect.Load(fstest.MapFS{
		"frameworks.json": {Data: []byte(document(technology("framework", validRule, `"language"`)))},
		"languages.json":  {Data: []byte(document(technology("language", "", "")))},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := engine.Detect(detect.Input{Headers: http.Header{"Server": {"Example"}}})
	if engine.Len() != 2 || len(got) != 2 || got[1].State != detect.Inferred {
		t.Fatalf("unexpected cross-file findings: %+v", got)
	}
}

func TestDuplicateAcrossFiles(t *testing.T) {
	data := []byte(document(technology("example", validRule, "")))
	_, err := detect.Load(fstest.MapFS{
		"one.json": {Data: data},
		"two.json": {Data: data},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate technology ID") {
		t.Fatalf("error=%v, want duplicate technology", err)
	}
}

func TestEmptyAndMissingCatalogs(t *testing.T) {
	if _, err := detect.Load(fstest.MapFS{}); err == nil {
		t.Fatal("missing catalog should be an error")
	}
	engine, err := detect.Load(fstest.MapFS{"empty.json": {Data: []byte(document(""))}})
	if err != nil {
		t.Fatal(err)
	}
	if engine.Len() != 0 || len(engine.Detect(detect.Input{})) != 0 {
		t.Fatal("explicitly empty catalog should have no findings")
	}
}
