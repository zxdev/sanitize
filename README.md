```Sanitizer``` is a simple url to host rectifier and basic format validator for domain and ip addresses.

```golang
// ToHost takes the raw url to host; reports status with ip conditional flag
//
//	handles canonical hosts as well as ipv4/6 and idna conversion to punycode
func (s *Sanitize) ToHost(url *string) (result struct {
	Okay, IP bool
})
```

```TLDSanitizer``` is a simple url to host rectifier and basic format validator for domain and ip address that also reports the index locations within a domain for the tld and apex forms using the icann and public suffix private tld domains where the apex form is the effective tld+1 segment. Invalid or unregognized tld will invalidate the domain.

```golang
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
```

testing example
```golang
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
```
