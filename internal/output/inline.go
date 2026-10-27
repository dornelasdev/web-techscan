package output

import "webscan/internal/assets"

type InlineCSSReport struct {
	Status        string            `json:"status"`
	Reason        string            `json:"reason,omitempty"`
	MaxBlocks     int               `json:"max_blocks"`
	MaxBlockBytes int64             `json:"max_block_bytes"`
	MaxTotalBytes int64             `json:"max_total_bytes"`
	Seen          int               `json:"seen"`
	Collected     int               `json:"collected"`
	Skipped       int               `json:"skipped"`
	Bytes         int64             `json:"bytes"`
	Truncated     bool              `json:"truncated"`
	Items         []InlineStyleItem `json:"items"`
}

type InlineStyleItem struct {
	Index  int    `json:"index"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Bytes  int64  `json:"bytes"`
}

func newInlineCSSReport(collection assets.InlineCSSCollection) InlineCSSReport {
	report := InlineCSSReport{
		Status: collection.Status, Reason: collection.Reason,
		MaxBlocks: assets.MaxInlineStyleBlocks, MaxBlockBytes: assets.MaxInlineStyleBytes, MaxTotalBytes: assets.MaxInlineCSSBytes,
		Seen: collection.Seen, Collected: collection.Collected, Skipped: collection.Skipped,
		Bytes: collection.Bytes, Truncated: collection.Truncated, Items: make([]InlineStyleItem, 0, len(collection.Items)),
	}
	for _, item := range collection.Items {
		report.Items = append(report.Items, InlineStyleItem{Index: item.Index, Status: item.Status, Reason: item.Reason, Bytes: item.Bytes})
	}
	return report
}
