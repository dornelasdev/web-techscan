package fetch

import (
	"net/url"
	"strconv"
	"strings"
)

// sameOrigin compares validated HTTP(S) URLs by scheme, hostname and effective
// port. Different DNS aliases remain different origins, even on the same IP.
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) int {
	if port := u.Port(); port != "" {
		n, _ := strconv.Atoi(port) // ParseURL already validated the port.
		return n
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}
