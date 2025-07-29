package sanitize_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/zxdev/sanitize"
)

func TestSanitize(t *testing.T) {

	/*
		=== RUN   TestSanitize
		example.com {true false} 19.125µs
		xn--exmple-cua.com {true false} 18.167µs
		example.com {true false} 458ns
		100.10.10.10 {true true} 459ns
		10.10.10.10 {false true} 250ns
		abcd::dbca {true true} 500ns
		--- PASS: TestSanitize (0.00s)
	*/

	var s sanitize.Sanitize
	for _, v := range []string{
		"https://www.example.com:1234/path",          // normal
		"https://www.exämple.com:1234/path",          // idan
		"http://user:pass@www.example.com:1234/path", // user:pass
		"100.10.10.10:1234",                          // ipv4 valid
		"10.10.10.10:1234",                           // ipv4 private
		"https://[abcd::dbca]:1234",                  // ipv6 ported
	} {
		t := time.Now()
		r := s.ToHost(&v)
		fmt.Println(v, r, time.Since(t))

	}
}

func TestTLDSanitize(t *testing.T) {

	/*
		=== RUN   TestTLDSanitize
		example.com {true false 0 8} example.com com 23.042µs
		xn--exmple-cua.com {true false 0 15} xn--exmple-cua.com com 9.708µs
		blog.example.com {true false 5 13} example.com com 11.375µs
		one.0x4433 {false false 4 0} 0x4433 one.0x4433 500ns
		co.uk {false false 0 0} co.uk co.uk 375ns
		test.co.uk {true false 0 5} test.co.uk co.uk 458ns
		100.10.10.10 {true true 0 0} 14.75µs
		10.10.10.10 {false true 0 0} 334ns
		abcd::dbca {true true 0 0} 625ns
		--- PASS: TestTLDSanitize (0.00s)
	*/

	var s sanitize.TLDSanitizer
	t.Log(s.Configure(nil).Len())
	for _, v := range []string{
		"https://www.example.com:1234/path",           // normal
		"https://www.exämple.com:1234/path",           // idan
		"http://user:pass@blog.example.com:1234/path", // user:pass
		"one.0x4433",                // invalid tld
		"co.uk",                     // public suffix
		"test.co.uk",                // public suffix
		"100.10.10.10:1234",         // ipv4 valid
		"10.10.10.10:1234",          // ipv4 private
		"https://[abcd::dbca]:1234", // ipv6 ported
	} {
		t := time.Now()
		r := s.ToHost(&v)
		if r.IP {
			fmt.Println(v, r, time.Since(t))
		} else {
			fmt.Println(v, r, v[r.Apex:], v[r.TLD:], time.Since(t))

		}
	}
}
