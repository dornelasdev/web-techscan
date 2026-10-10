package output

import "webscan/internal/assets"

// AssetReport is collection metadata only. Bodies and response headers are
// deliberately absent. Complete means the selected bounded scope, not a site.
type AssetReport struct {
	Mode                string      `json:"mode"`
	Status              string      `json:"status"`
	Reason              string      `json:"reason,omitempty"`
	Truncated           bool        `json:"truncated"`
	SkippedDeclarations int         `json:"skipped_declarations"`
	Duplicates          int         `json:"duplicates"`
	Attempted           int         `json:"attempted"`
	Collected           int         `json:"collected"`
	DecodedBytes        int64       `json:"decoded_bytes"`
	EncodedBytes        int64       `json:"encoded_bytes"`
	Items               []AssetItem `json:"items"`
}

type AssetItem struct {
	URL          string `json:"url"`
	Kind         string `json:"kind"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	DecodedBytes int64  `json:"decoded_bytes"`
	EncodedBytes int64  `json:"encoded_bytes"`
}

func NewAssetReport(collection assets.Collection) *AssetReport {
	report := &AssetReport{
		Mode: "collection_only", Status: collection.Status, Reason: collection.Reason,
		Truncated: collection.Truncated, SkippedDeclarations: collection.SkippedDeclarations,
		Duplicates: collection.Duplicates, Attempted: collection.Attempted, Collected: collection.Collected,
		DecodedBytes: collection.Usage.Decoded, EncodedBytes: collection.Usage.Encoded,
		Items: make([]AssetItem, 0, len(collection.Items)),
	}
	for _, item := range collection.Items {
		report.Items = append(report.Items, AssetItem{
			URL: item.URL, Kind: string(item.Kind), Status: item.Status, Reason: item.Reason,
			HTTPStatus: item.HTTPStatus, DecodedBytes: item.Usage.Decoded, EncodedBytes: item.Usage.Encoded,
		})
	}
	return report
}
