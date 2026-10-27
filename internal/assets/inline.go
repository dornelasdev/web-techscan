package assets

import (
	"strings"

	"golang.org/x/net/html"
)

const (
	MaxInlineStyleBlocks       = 20
	MaxInlineStyleBytes  int64 = 512 << 10
	MaxInlineCSSBytes    int64 = 1 << 20
)

// InlineStyle is one whole eligible CSS style element from the final document.
// Index is one-based among eligible elements, including empty/skipped blocks.
type InlineStyle struct {
	Index int
	Body  []byte
}

type InlineStyleItem struct {
	Index  int
	Status string
	Reason string
	Bytes  int64 // Whole parsed block size, including when it is skipped.
}

// InlineCSSCollection has independent local bounds; Bytes counts retained CSS,
// never network reads. Items/Blocks retain at most the first 20 eligible slots.
type InlineCSSCollection struct {
	Status    string
	Reason    string
	Seen      int
	Collected int
	Skipped   int
	Bytes     int64
	Truncated bool
	Items     []InlineStyleItem
	Blocks    []InlineStyle // Never serialized.
}

func newInlineCSS(status, reason string) InlineCSSCollection {
	return InlineCSSCollection{Status: status, Reason: reason, Items: make([]InlineStyleItem, 0), Blocks: make([]InlineStyle, 0)}
}

// collectInlineStyle runs only inside the existing non-inert HTML tree walk.
func collectInlineStyle(n *html.Node, result *InlineCSSCollection) {
	if n.Type != html.ElementNode || n.Data != "style" {
		return
	}
	typ, _ := attribute(n, "type")
	if typ = strings.ToLower(trimSpace(typ)); typ != "" && typ != "text/css" {
		return
	}
	result.Seen++
	if result.Seen > MaxInlineStyleBlocks {
		result.Truncated = true
		result.Skipped++
		result.incomplete("block_limit")
		return
	}
	var size int64
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			size += int64(len(child.Data))
		}
	}
	item := InlineStyleItem{Index: result.Seen, Status: "collected", Bytes: size}
	switch {
	case size > MaxInlineStyleBytes:
		item.Reason = "block_byte_limit"
	case size > MaxInlineCSSBytes-result.Bytes:
		item.Reason = "total_byte_limit"
	}
	if item.Reason != "" {
		item.Status = "skipped"
		result.Skipped++
		result.incomplete(item.Reason)
	} else {
		// Measure before allocating/copying, so no rejected prefix is retained.
		body := make([]byte, 0, int(size))
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if child.Type == html.TextNode {
				body = append(body, child.Data...)
			}
		}
		result.Blocks = append(result.Blocks, InlineStyle{Index: item.Index, Body: body})
		result.Collected++
		result.Bytes += size
	}
	result.Items = append(result.Items, item)
}

func (c *InlineCSSCollection) incomplete(reason string) {
	c.Status = "incomplete"
	if c.Reason == "" {
		c.Reason = reason
	}
}
