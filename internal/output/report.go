// Package output builds and renders scan reports without fetching or detecting.
package output

import (
	"webscan/internal/detect"
	"webscan/internal/fetch"
)

// Report is the versioned JSON contract, independent of internal detector types.
type Report struct {
	SchemaVersion int        `json:"schema_version"`
	URL           string     `json:"url"`
	FinalURL      string     `json:"final_url"`
	HTTPStatus    int        `json:"http_status"`
	ResponseScope string     `json:"response_scope"`
	BodyBytes     int        `json:"body_bytes"`
	CatalogSize   int        `json:"catalog_size"`
	Redirects     []Redirect `json:"redirects"`
	Findings      []Finding  `json:"findings"`
}

type Redirect struct {
	FromURL    string `json:"from_url"`
	ToURL      string `json:"to_url"`
	StatusCode int    `json:"status_code"`
}

type Finding struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Category string     `json:"category"`
	State    string     `json:"state"`
	Evidence []Evidence `json:"evidence"`
}

type Evidence struct {
	RuleID       string   `json:"rule_id,omitempty"`
	Description  string   `json:"description"`
	Signals      []Signal `json:"signals"`
	InferredFrom string   `json:"inferred_from,omitempty"`
}

type Signal struct {
	Source string `json:"source"`
	Name   string `json:"name,omitempty"`
}

// NewReport copies only reportable metadata and evidence. Response bodies,
// header values, and cookie values are never included. Arrays stay non-null.
func NewReport(snapshot fetch.Snapshot, findings []detect.Finding, catalogSize int) Report {
	report := Report{
		SchemaVersion: 1,
		URL:           snapshot.OriginalURL,
		FinalURL:      snapshot.FinalURL,
		HTTPStatus:    snapshot.StatusCode,
		ResponseScope: "final_response",
		BodyBytes:     len(snapshot.Body),
		CatalogSize:   catalogSize,
		Redirects:     make([]Redirect, 0, len(snapshot.Redirects)),
		Findings:      make([]Finding, 0, len(findings)),
	}
	if snapshot.StatusCode >= 400 {
		report.ResponseScope = "http_error_response"
	}
	for _, redirect := range snapshot.Redirects {
		report.Redirects = append(report.Redirects, Redirect{
			FromURL: redirect.FromURL, ToURL: redirect.ToURL, StatusCode: redirect.StatusCode,
		})
	}
	for _, finding := range findings {
		item := Finding{
			ID: finding.ID, Name: finding.Name, Category: string(finding.Category),
			State: string(finding.State), Evidence: make([]Evidence, 0, len(finding.Evidence)),
		}
		for _, evidence := range finding.Evidence {
			detail := Evidence{
				RuleID: evidence.RuleID, Description: evidence.Description,
				InferredFrom: evidence.InferredFrom, Signals: make([]Signal, 0, len(evidence.Signals)),
			}
			for _, signal := range evidence.Signals {
				detail.Signals = append(detail.Signals, Signal{Source: string(signal.Source), Name: signal.Name})
			}
			item.Evidence = append(item.Evidence, detail)
		}
		report.Findings = append(report.Findings, item)
	}
	return report
}
