package sanitize

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// NewSanitizer is the Sanitize configurator
func NewSanitizer() *Sanitize {
	return &Sanitize{puny: idna.New(idna.MapForLookup(), idna.Transitional(true))}
}

// Sanitize structure
type Sanitize struct {
	puny *idna.Profile
}

// ToHost takes the raw url to host; report result status and an ip flag
//
//	handles canonical hosts as well as ipv4/6 and idna conversion to punycode
func (s *Sanitize) ToHost(url *string) (result struct {
	Okay, IP bool
}) {

	// configuration assurance
	if s.puny == nil {
		s.puny = idna.New(idna.MapForLookup(), idna.Transitional(true))
	}

	// basic url assurances
	*url = strings.TrimPrefix(*url, "http://")  // strip scheme
	*url = strings.TrimPrefix(*url, "https://") // strip scheme
	idx := strings.Index(*url, "/")
	if idx > 0 { // strip page
		*url = (*url)[:idx]
	}
	idx = strings.Index(*url, "@")
	if idx > 0 {
		// strip user:pass
		*url = (*url)[idx+1:]
	}

	// port removal
	if strings.Contains(*url, ":") { // ported host|ipv4 or ipv6
		switch {
		case strings.Contains(*url, "."):
			// ported host or ipv4 example.com or 100.100.100.100
			idx = strings.Index(*url, ":")
			*url = (*url)[:idx]
		case strings.HasSuffix(*url, "]") && strings.HasPrefix(*url, "["):
			// unported ipv6 [abcd::dcba]
			*url = (*url)[1 : len(*url)-2]
		case strings.Contains(*url, "]:"):
			// ipv6 with port [abcd::dcba]:1234
			idx = strings.Index(*url, "]:")
			*url = (*url)[1:idx]
		}
	}

	// detect ipv4/6 and validate
	ip := net.ParseIP(*url)
	result.IP = ip != nil // ip flag
	if result.IP {
		result.Okay = !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate()
		return
	}

	// host form rectification and type assurance
	*url = strings.ToLower(*url)            // standardize case
	*url = strings.TrimSuffix(*url, ".")    // remove cannonical
	*url = strings.TrimPrefix(*url, "www.") // strip www label
	*url, _ = s.puny.ToASCII(*url)          // punycode any idna characters

	// basic host validation final check
	result.Okay = strings.Contains(*url, ".") && len(*url) < 253
	return
}
