package cli_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/output"
)

func TestCLIRedirectDowngradePolicy(t *testing.T) {
	var mu sync.Mutex
	var visited []string
	plainMux, secureMux := http.NewServeMux(), http.NewServeMux()
	plain := httptest.NewServer(plainMux)
	defer plain.Close()
	secure := httptest.NewUnstartedServer(secureMux)
	secure.Config.ErrorLog = log.New(io.Discard, "", 0) // Expected untrusted-TLS case.
	secure.StartTLS()
	defer secure.Close()
	final := "/final?token=private-final"
	handler := func(w http.ResponseWriter, r *http.Request) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		mu.Lock()
		visited = append(visited, scheme+":"+r.URL.Path)
		mu.Unlock()
		if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Cookie") != "" {
			t.Errorf("request policy changed: %s %v", r.Method, r.Header)
		}
		switch r.URL.Path {
		case "/upgrade":
			w.Header().Set("Location", secure.URL+"/down?token=private-middle")
		case "/down":
			w.Header().Set("Location", plain.URL+final)
		case "/same":
			w.Header().Set("Location", final)
		case "/credentials":
			w.Header().Set("Location", strings.Replace(plain.URL, "http://", "http://private-user:private-password@", 1)+final)
		case "/final":
			if r.TLS == nil && r.Referer() != "" {
				t.Errorf("downgrade forwarded Referer: %q", r.Referer())
			}
			w.Header().Set("Server", "nginx")
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "page")
			return
		default:
			t.Errorf("unexpected path: %q", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Powered-By", "Express") // Redirect evidence must stay separate.
		http.SetCookie(w, &http.Cookie{Name: "hop", Value: "private-cookie"})
		w.WriteHeader(http.StatusFound)
	}
	plainMux.HandleFunc("/", handler)
	secureMux.HandleFunc("/", handler)
	for _, tc := range []struct {
		name      string
		start     string
		flags     []string
		reason    string
		wantPaths []string
		finalURL  string
		untrusted bool
	}{
		{"blocked", secure.URL + "/down", nil, "HTTPS-to-HTTP redirect blocked", []string{"https:/down"}, "", false},
		{"explicit-false", secure.URL + "/down", []string{"--allow-http-downgrade=false"}, "HTTPS-to-HTTP redirect blocked", []string{"https:/down"}, "", false},
		{"allowed", secure.URL + "/down", []string{"--allow-http-downgrade"}, "", []string{"https:/down", "http:/final"}, plain.URL + final, false},
		{"upgrade-then-blocked", plain.URL + "/upgrade", nil, "HTTPS-to-HTTP redirect blocked", []string{"http:/upgrade", "https:/down"}, "", false},
		{"upgrade-then-allowed", plain.URL + "/upgrade", []string{"--allow-http-downgrade=true"}, "", []string{"http:/upgrade", "https:/down", "http:/final"}, plain.URL + final, false},
		{"direct-http", plain.URL + final, nil, "", []string{"http:/final"}, plain.URL + final, false},
		{"relative-https", secure.URL + "/same", nil, "", []string{"https:/same", "https:/final"}, secure.URL + final, false},
		{"limit-with-opt-in", secure.URL + "/down", []string{"--allow-http-downgrade", "--max-redirects=0"}, "redirect limit exceeded", []string{"https:/down"}, "", false},
		{"credentials-with-opt-in", secure.URL + "/credentials", []string{"--allow-http-downgrade"}, "embedded credentials are not supported", []string{"https:/credentials"}, "", false},
		{"tls-still-verified", secure.URL + "/down", []string{"--allow-http-downgrade"}, "TLS certificate verification failed", nil, "", true},
	} {
		for _, asJSON := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", tc.name, asJSON), func(t *testing.T) {
				mu.Lock()
				visited = nil
				mu.Unlock()
				// Test-local certificate trust, never InsecureSkipVerify. Like the
				// offline catalog tests, these must not run in parallel.
				original := http.DefaultTransport
				transport := original.(*http.Transport).Clone()
				roots := x509.NewCertPool()
				if !tc.untrusted {
					roots.AddCert(secure.Certificate())
				}
				transport.TLSClientConfig = &tls.Config{RootCAs: roots}
				http.DefaultTransport = transport
				t.Cleanup(func() {
					http.DefaultTransport = original
					transport.CloseIdleConnections()
				})
				args := append([]string{"--no-color"}, tc.flags...)
				if asJSON {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				code := cli.Run(append(args, tc.start), &stdout, &stderr, "dev")
				mu.Lock()
				gotPaths := append([]string(nil), visited...)
				mu.Unlock()
				if !reflect.DeepEqual(gotPaths, tc.wantPaths) {
					t.Errorf("requests=%q want=%q", gotPaths, tc.wantPaths)
				}
				if tc.reason != "" {
					if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.reason) {
						t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
					}
					if tc.reason == "HTTPS-to-HTTP redirect blocked" && !strings.Contains(stderr.String(), "--allow-http-downgrade") {
						t.Error("missing opt-in guidance")
					}
					for _, raw := range []string{plain.URL, secure.URL, "private-", "Run 'webscan --help'"} {
						if strings.Contains(stderr.String(), raw) {
							t.Errorf("unsafe or misclassified diagnostic: %q", stderr.String())
						}
					}
					return
				}
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, stderr.String())
				}
				if asJSON {
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					if report.FinalURL != tc.finalURL || len(report.Redirects) != len(tc.wantPaths)-1 || report.BodyBytes != 4 || len(report.Findings) != 1 || report.Findings[0].ID != "nginx" {
						t.Errorf("unexpected report: %+v", report)
					}
				} else if !strings.Contains(stdout.String(), "URL: "+tc.finalURL+"\n") || !strings.Contains(stdout.String(), "✓ nginx [web server]") || strings.Contains(stdout.String(), "Express") {
					t.Errorf("unexpected terminal report: %q", stdout.String())
				}
			})
		}
	}
}
