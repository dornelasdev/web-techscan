package output

import "webscan/internal/assets"

// AssetReport is collection metadata only. Bodies and response headers are
// deliberately absent. Complete means the selected bounded scope, not a site.
type AssetReport struct {
	InlineCSS                InlineCSSReport  `json:"inline_css"`
	Budget                   AssetBudget      `json:"budget"`
	AllowedOrigins           []string         `json:"allowed_origins"`
	Mode                     string           `json:"mode"`
	Status                   string           `json:"status"`
	Reason                   string           `json:"reason,omitempty"`
	Truncated                bool             `json:"truncated"`
	SkippedDeclarations      int              `json:"skipped_declarations"`
	Duplicates               int              `json:"duplicates"`
	ExternalOrigins          []ExternalOrigin `json:"external_origins"`
	ExternalOriginsTruncated bool             `json:"external_origins_truncated"`
	Attempted                int              `json:"attempted"`
	Collected                int              `json:"collected"`
	DecodedBytes             int64            `json:"decoded_bytes"`
	EncodedBytes             int64            `json:"encoded_bytes"`
	Items                    []AssetItem      `json:"items"`
}

// ExternalOrigin contains origin-only metadata, never full asset URLs.
type ExternalOrigin struct {
	Origin      string `json:"origin"`
	Scripts     int    `json:"scripts"`
	Stylesheets int    `json:"stylesheets"`
}

// AssetBudget records configured bounds, not remaining bytes or memory limits.
type AssetBudget struct {
	Profile              string `json:"profile"`
	MaxAssetDecodedBytes int64  `json:"max_asset_decoded_bytes"`
	MaxAssetEncodedBytes int64  `json:"max_asset_encoded_bytes"`
	MaxTotalDecodedBytes int64  `json:"max_total_decoded_bytes"`
	MaxTotalEncodedBytes int64  `json:"max_total_encoded_bytes"`
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
		Budget: AssetBudget{
			Profile:              collection.Budget.Profile,
			MaxAssetDecodedBytes: collection.Budget.MaxAssetDecodedBytes,
			MaxAssetEncodedBytes: collection.Budget.MaxAssetEncodedBytes,
			MaxTotalDecodedBytes: collection.Budget.MaxTotalDecodedBytes,
			MaxTotalEncodedBytes: collection.Budget.MaxTotalEncodedBytes,
		},
		Mode: "fingerprint_inspection", Status: collection.Status, Reason: collection.Reason,
		Truncated: collection.Truncated, SkippedDeclarations: collection.SkippedDeclarations,
		Duplicates: collection.Duplicates, Attempted: collection.Attempted, Collected: collection.Collected,
		DecodedBytes: collection.Usage.Decoded, EncodedBytes: collection.Usage.Encoded,
		Items:                    make([]AssetItem, 0, len(collection.Items)),
		AllowedOrigins:           append([]string{}, collection.AllowedOrigins...),
		ExternalOrigins:          make([]ExternalOrigin, 0, len(collection.ExternalOrigins)),
		ExternalOriginsTruncated: collection.ExternalOriginsTruncated,
	}
	for _, origin := range collection.ExternalOrigins {
		report.ExternalOrigins = append(report.ExternalOrigins, ExternalOrigin{
			Origin: origin.Origin, Scripts: origin.Scripts, Stylesheets: origin.Stylesheets,
		})
	}
	for _, item := range collection.Items {
		report.Items = append(report.Items, AssetItem{
			URL: item.URL, Kind: string(item.Kind), Status: item.Status, Reason: item.Reason,
			HTTPStatus: item.HTTPStatus, DecodedBytes: item.Usage.Decoded, EncodedBytes: item.Usage.Encoded,
		})
	}
	report.InlineCSS = newInlineCSSReport(collection.InlineCSS)
	return report
}
