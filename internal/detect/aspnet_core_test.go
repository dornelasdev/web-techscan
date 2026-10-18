package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const aspnetCoreCookie = ".AspNetCore.Antiforgery.AbCdEf012_A"
const aspnetCoreInput = `<input name="__RequestVerificationToken" type="hidden" value="private-antiforgery-token" />`

func requireASPNetCore(t *testing.T, got []detect.Finding) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "aspnet-core" || got[0].Name != "ASP.NET Core" || got[0].Category != detect.Framework || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
		t.Fatalf("want only inferred ASP.NET Core, got %+v", got)
	}
	e := got[0].Evidence[0]
	if e.RuleID != "antiforgery-cookie-and-input" || e.Description == "" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Cookie}, {Source: detect.HTML}}) {
		t.Errorf("unexpected paired evidence: %+v", e)
	}
	for _, raw := range []string{aspnetCoreCookie, "private-antiforgery-token", "private-cookie"} {
		if strings.Contains(e.Description, raw) {
			t.Errorf("raw value leaked into evidence: %q", raw)
		}
	}
}

func TestASPNetCoreCookieNameBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, name := range []string{aspnetCoreCookie, ".AspNetCore.Antiforgery.47DEQpj8HBQ", ".AspNetCore.Antiforgery.aB_cD-eF01Q"} {
		t.Run("positive/"+name, func(t *testing.T) {
			requireASPNetCore(t, engine.Detect(detect.Input{CookieNames: []string{name, name, "unrelated"}, HTML: []byte(aspnetCoreInput)}))
		})
	}
	for _, name := range []string{
		"", ".AspNetCore.Antiforgery.", ".AspNetCore.Antiforgery.AbCdEf012_", ".AspNetCore.Antiforgery.AbCdEf012_AA",
		".aspnetcore.Antiforgery.AbCdEf012_A", ".AspNetCore.antiforgery.AbCdEf012_A", "AspNetCore.Antiforgery.AbCdEf012_A",
		"x" + aspnetCoreCookie, aspnetCoreCookie + "-extra", aspnetCoreCookie + "=private-cookie", aspnetCoreCookie + "\n",
		" " + aspnetCoreCookie, aspnetCoreCookie + "\t", aspnetCoreCookie + "\x00",
		".AspNetCore.Antiforgery.AbCdEf012+Q", ".AspNetCore.Antiforgery.AbCdEf012/Q", ".AspNetCore.Antiforgery.AbCdEf012 Q",
		".AspNetCore.Antiforgery.ＡbCdEf012_A", ".AspNetCore.Session", ".AspNetCore.Identity.Application",
		"__RequestVerificationToken", "__RequestVerificationToken_AbCdEf012_A", "ASP.NET_SessionId", "custom-antiforgery",
	} {
		t.Run("negative/"+name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{CookieNames: []string{name}, HTML: []byte(aspnetCoreInput)}); len(got) != 0 {
				t.Fatalf("unexpected findings: %+v", got)
			}
		})
	}
}

func TestASPNetCoreInputBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, quote := range []string{`"`, `'`} {
		name, kind := "name="+quote+"__RequestVerificationToken"+quote, "type="+quote+"hidden"+quote
		for _, pair := range []string{name + " " + kind, kind + " " + name} {
			for _, body := range []string{
				"<input " + pair + ">", "<INPUT data-first='fixture'\n" + pair + " value='private-antiforgery-token' disabled />",
				"<input " + strings.Replace(pair, " ", " data-middle=fixture ", 1) + ">",
			} {
				t.Run("positive/"+body, func(t *testing.T) {
					requireASPNetCore(t, engine.Detect(detect.Input{CookieNames: []string{aspnetCoreCookie}, HTML: []byte(body)}))
				})
			}
		}
	}
	fixture := htmlFixture(t, "aspnet-core-antiforgery.html")
	for _, body := range []string{string(fixture), aspnetCoreInput + aspnetCoreInput, `<INPUT TYPE = "HIDDEN" NAME = '__RequestVerificationToken'>`, "<!--" + aspnetCoreInput + "-->"} {
		// Values/forms are not required or validated. Copied/commented input
		// tags remain a documented limitation of raw-HTML matching.
		requireASPNetCore(t, engine.Detect(detect.Input{CookieNames: []string{aspnetCoreCookie}, HTML: []byte(body)}))
	}
	for i, body := range []string{
		"", "__RequestVerificationToken", `<input name="__RequestVerificationToken">`, `<input type="hidden">`,
		`<input type="text" name="__RequestVerificationToken">`, `<input type="hiddenish" name="__RequestVerificationToken">`,
		`<input type="hidden" name="__requestverificationtoken">`, `<input type="hidden" name="__RequestVerificationToken-extra">`,
		`<input type="hidden" data-name="__RequestVerificationToken">`, `<input data-type="hidden" name="__RequestVerificationToken">`,
		`<input type="hidden"><input name="__RequestVerificationToken">`, `<div type="hidden" name="__RequestVerificationToken">`,
		`<input-widget type="hidden" name="__RequestVerificationToken">`, `<input:type type="hidden" name="__RequestVerificationToken">`,
		`<input data-example='type="hidden" name="__RequestVerificationToken"'>`,
		`<input type="hidden" data-example=' name="__RequestVerificationToken" '>`,
		`<input name="__RequestVerificationToken" data-example=' type="hidden" '>`,
		`<input type="hidden" name="__RequestVerificationToken"`, `<input type="hidden" name="__RequestVerificationToken" value="unfinished`,
		`<input type="hidden"name="__RequestVerificationToken">`, `<input/type="hidden" name="__RequestVerificationToken">`,
		`<input type=hidden name="__RequestVerificationToken">`, `<input type="hidden" name=__RequestVerificationToken>`,
		`&lt;input type="hidden" name="__RequestVerificationToken"&gt;`, `<input type="hidden" name="__RequestVerification&#84;oken">`,
	} {
		t.Run("negative/"+strconv.Itoa(i), func(t *testing.T) {
			if got := engine.Detect(detect.Input{CookieNames: []string{aspnetCoreCookie}, HTML: []byte(body)}); len(got) != 0 {
				t.Fatalf("unexpected findings: %+v", got)
			}
		})
	}
}

func TestASPNetCorePairStatusAndSourceIsolation(t *testing.T) {
	engine := bundledEngine(t)
	for mask := 0; mask < 4; mask++ {
		for _, status := range []int{0, 200, 403, 500} {
			t.Run(fmt.Sprintf("markers=%02b/status=%d", mask, status), func(t *testing.T) {
				input := detect.Input{HTTPStatus: status}
				if mask&1 != 0 {
					input.CookieNames = []string{aspnetCoreCookie}
				}
				if mask&2 != 0 {
					input.HTML = []byte(aspnetCoreInput)
				}
				got := engine.Detect(input)
				if mask == 3 {
					requireASPNetCore(t, got)
				} else if len(got) != 0 {
					t.Fatalf("partial pair produced findings: %+v", got)
				}
				if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
					t.Error("repeated scan changed findings")
				}
				if mask == 3 {
					got[0].Evidence[0].Description, got[0].Evidence[0].Signals[0].Name = "caller mutation", "changed"
					requireASPNetCore(t, engine.Detect(input))
				}
				if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
					t.Errorf("findings retained across scans: %+v", empty)
				}
			})
		}
	}
	for _, input := range []detect.Input{
		{Headers: http.Header{"Set-Cookie": {aspnetCoreCookie + "=private-cookie"}, "Cookie": {aspnetCoreCookie + "=private-cookie"}}, HTML: []byte(aspnetCoreInput)},
		{Headers: http.Header{"X-Example": {aspnetCoreCookie}}, HTML: []byte(aspnetCoreInput)},
		{CookieNames: []string{aspnetCoreCookie}, Headers: http.Header{"X-Example": {aspnetCoreInput}}},
		{HTML: []byte(aspnetCoreCookie + aspnetCoreInput)},
		{Headers: http.Header{"X-Powered-By": {"ASP.NET"}, "X-AspNet-Version": {"4.0.30319"}, "X-AspNetMvc-Version": {"5.2"}}, CookieNames: []string{"ASP.NET_SessionId", ".AspNetCore.Session"}},
		{CookieNames: []string{aspnetCoreCookie}, Assets: []detect.Asset{{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: []byte(aspnetCoreInput)}, {URL: "https://example.test/app.css", Source: detect.AssetCSS, Body: []byte(aspnetCoreInput)}}},
	} {
		if got := engine.Detect(input); len(got) != 0 {
			t.Errorf("wrong-source/generic markers produced findings: %+v", got)
		}
	}
}

func TestASPNetCoreIndependentServersAndLanguages(t *testing.T) {
	engine := bundledEngine(t)
	for _, server := range []struct{ id, name, banner string }{{}, {"iis", "Microsoft IIS", "Microsoft-IIS/10.0"}, {"kestrel", "Kestrel", "Kestrel"}} {
		for mask := 0; mask < 4; mask++ {
			t.Run(fmt.Sprintf("server=%s/markers=%02b", server.id, mask), func(t *testing.T) {
				input := detect.Input{CookieNames: []string{"csrftoken"}, HTML: []byte(djangoInput + railsParam + railsToken)}
				wantIDs := []string{"django", "python", "rails", "ruby"}
				if server.id != "" {
					input.Headers = http.Header{"Server": {server.banner}}
					wantIDs = append(wantIDs, server.id)
				}
				if mask&1 != 0 {
					input.CookieNames = append(input.CookieNames, aspnetCoreCookie)
				}
				if mask&2 != 0 {
					input.HTML = append(input.HTML, aspnetCoreInput...)
				}
				if mask == 3 {
					wantIDs = append(wantIDs, "aspnet-core")
				}
				sort.Strings(wantIDs)
				got, ids := engine.Detect(input), []string{}
				for _, finding := range got {
					ids = append(ids, finding.ID)
				}
				if !reflect.DeepEqual(ids, wantIDs) {
					t.Fatalf("IDs=%v want=%v", ids, wantIDs)
				}
				for i, finding := range got {
					one := got[i : i+1]
					switch finding.ID {
					case "aspnet-core":
						requireASPNetCore(t, one)
					case "django":
						requireDjangoFinding(t, one)
					case "rails":
						requireRailsFinding(t, one)
					case "python", "ruby":
						requireLanguageInference(t, one, finding.ID, map[string]string{"python": "django", "ruby": "rails"}[finding.ID])
					default:
						if finding.ID != server.id || finding.Name != server.name || finding.Category != detect.WebServer || finding.State != detect.Detected || len(finding.Evidence) != 1 {
							t.Fatalf("unexpected independent server finding: %+v", finding)
						}
						e := finding.Evidence[0]
						if e.RuleID != "server-header" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Header, Name: "Server"}}) {
							t.Errorf("unexpected independent server evidence: %+v", e)
						}
					}
				}
			})
		}
	}
}
