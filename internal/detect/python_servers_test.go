package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func requirePythonHTTPServer(t *testing.T, got []detect.Finding, id string) {
	t.Helper()
	names := map[string]string{"gunicorn": "Gunicorn", "uvicorn": "Uvicorn"}
	if names[id] == "" || len(got) != 1 || got[0].ID != id || got[0].Name != names[id] || got[0].Category != detect.WebServer || got[0].State != detect.Detected || len(got[0].Evidence) != 1 {
		t.Fatalf("want only detected %s without language/framework implications, got %+v", id, got)
	}
	e := got[0].Evidence[0]
	if e.RuleID != "server-header" || e.Description != "Server header reports "+names[id]+"; this may be an intermediary" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Header, Name: "Server"}}) {
		t.Errorf("unexpected server evidence: %+v", e)
	}
}

func TestPythonHTTPServerStatusAndReuse(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct{ id, banner string }{{"gunicorn", "gUnIcOrN"}, {"uvicorn", "uViCoRn"}} {
		for _, status := range []int{0, 200, 403, 500} {
			t.Run(fmt.Sprintf("%s/status=%d", tc.id, status), func(t *testing.T) {
				input := detect.Input{HTTPStatus: status, Headers: http.Header{"server": {"unrelated", tc.banner}, "SERVER": {tc.banner}}}
				got := engine.Detect(input)
				requirePythonHTTPServer(t, got, tc.id)
				if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
					t.Error("repeated scan changed findings")
				}
				got[0].Evidence[0].Description, got[0].Evidence[0].Signals[0].Name = "caller mutation", "changed"
				requirePythonHTTPServer(t, engine.Detect(input), tc.id)
				if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
					t.Errorf("findings retained across scans: %+v", empty)
				}
			})
		}
	}
}

func TestPythonHTTPServerIndependentFrameworks(t *testing.T) {
	engine := bundledEngine(t)
	swagger := string(htmlFixture(t, "fastapi-swagger.html"))
	for _, tc := range []struct{ id, banner string }{{"gunicorn", "gunicorn"}, {"uvicorn", "uvicorn"}} {
		for mask := 0; mask < 8; mask++ {
			t.Run(fmt.Sprintf("%s/markers=%03b", tc.id, mask), func(t *testing.T) {
				// Every input contains a full documentation viewer, but only
				// one branch has the required favicon. A server must not fill it in.
				body := strings.ReplaceAll(swagger, fastAPIFavicon, "")
				if mask&1 != 0 {
					body = swagger
				}
				input := detect.Input{Headers: http.Header{"Server": {tc.banner}, "X-Powered-By": {"FastAPI"}}, CookieNames: []string{"session"}}
				if mask&2 != 0 {
					input.CookieNames = append(input.CookieNames, "csrftoken")
				}
				if mask&4 != 0 {
					body += djangoInput
				}
				input.HTML = []byte(body)
				wantIDs := []string{tc.id}
				if mask&1 != 0 {
					wantIDs = append(wantIDs, "fastapi")
				}
				if mask&6 == 6 {
					wantIDs = append(wantIDs, "django", "python")
				}
				sort.Strings(wantIDs)
				got, ids := engine.Detect(input), []string{}
				for i, f := range got {
					ids = append(ids, f.ID)
					switch f.ID {
					case tc.id:
						requirePythonHTTPServer(t, got[i:i+1], tc.id)
					case "fastapi":
						requireFastAPI(t, got[i:i+1], "swagger-ui-html")
					case "django":
						requireDjangoFinding(t, got[i:i+1])
					case "python":
						requireLanguageInference(t, got[i:i+1], "python", "django")
					}
				}
				if !reflect.DeepEqual(ids, wantIDs) {
					t.Fatalf("findings=%+v want=%v; no borrowed framework or language evidence", got, wantIDs)
				}
			})
		}
	}
}
