package sanitize

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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

// Sanitize result
type SanitizeResult struct {
	Okay, IP bool
}

// ToHost takes the raw url to host; reports status with ip conditional flag
//
//	handles canonical hosts as well as ipv4/6 and idna conversion to punycode
func (s *Sanitize) ToHost(url *string) (result SanitizeResult) {

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

// NewTLDSanitizer is the TLDSanitize configurator that loads the tld map using
// the standard iana.org and publicsuffix.org lists
func NewTLDSanitizer() *TLDSanitizer {
	var s TLDSanitizer
	return s.Configure()
}

// TLDSanitize structure
type TLDSanitizer struct {
	puny *idna.Profile
	tld  map[string]bool
}

// Len is number of registered tld items in use in the TLDSanitizer
func (s *TLDSanitizer) Len() int { return len(s.tld) }

// Configure load the tld reference map; then iana.org and publicsuffix.org are fetched
// automatically any local files should be passed as paths or additional remote lists cab
// be passed in as additional paramaters
//
//	var s TLDSanitizer
//	s.Configure("/var/url/custom")
func (s *TLDSanitizer) Configure(a ...string) *TLDSanitizer {

	if s.puny == nil {
		s.puny = idna.New(idna.MapForLookup(), idna.Transitional(true))
	}

	if s.tld == nil {
		// tld are derived from iana.org and publicsuffix.org lists that are used to
		// detect and validate the host tld and for apex localization; 72h updates
		s.tld = make(map[string]bool)

		var resource = "dat"
		if runtime.GOOS == "linux" {
			resource = "/var/url"
		}
		if _, err := os.Stat(resource); errors.Is(err, fs.ErrNotExist) {
			os.Mkdir(resource, 0744)
		}

		// add iana.org and publicsuffix.org tld lists to any others that may have been
		// provided when calling this initialization process
		a = append(a,
			"https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
			"https://publicsuffix.org/list/effective_tld_names.dat")

		// icann,psl combo resource loader
		for _, item := range a {
			if strings.Contains(item, "://") {
				// fetch resource when not exist or over 72h aged
				var target = filepath.Join(resource, filepath.Base(item))
				var info, err = os.Stat(target)
				if err != nil || info.ModTime().Before(time.Now().Add(-time.Hour*72)) {
					r, err := http.Get(item)
					if err == nil && r != nil && r.StatusCode == http.StatusOK {
						w, _ := os.Create(target)
						io.Copy(w, r.Body)
						w.Close()
					}
				}
				item = target
			}

			f, err := os.Open(item)
			if err == nil {
				var row string
				var scanner = bufio.NewScanner(f)
				for scanner.Scan() {
					row = strings.TrimSpace(scanner.Text())
					if strings.HasPrefix(row, "//") || strings.HasPrefix(row, "#") {
						continue
					}
					row = strings.TrimPrefix(row, "*.") // ignore psl *. rules for simplicity
					row = strings.ToLower(row)          // rectify case for icann
					row = strings.TrimSpace(row)
					if len(row) > 0 && !s.tld[row] {
						s.tld[row] = true
					}
				}
				f.Close()
			}

		}
	}

	return s
}

// ToHost takes the raw url to host; reports status with ip conditional flag
// and sets the tld and apex form index location for domains using the icann.org
// and publicsuffix.org private tld extentions
//
//	url := "blog.example.com"
//	r := s.ToHost(&url)
//	if r.Okay && !r.IP {
//	 url[r.Apex:] = example.com
//	 url[r.TLD:] = com
//	}
//
//	handles canonical hosts as well as ipv4/6 and idna conversion to punycode
func (s *TLDSanitizer) ToHost(url *string) (result struct {
	Okay, IP  bool // status flags
	Apex, TLD int  // index locations
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

	// detect tld and set the apex index
	if s.tld != nil {
		idx = 0
		for {
			if s.tld[(*url)[idx:]] {
				result.TLD = idx
				if idx == result.Apex {
					return // item is tld
				}
				break // tld found
			}
			result.Apex = idx
			idx += strings.Index((*url)[idx:], ".") + 1
			if idx == 0 || idx == result.Apex {
				break // exhausted
			}
		}
	}

	// basic host validation final check
	result.Okay = strings.Contains(*url, ".") && len(*url) < 253
	return

}
