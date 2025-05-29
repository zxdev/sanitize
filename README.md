Simple url to host sanitizer and validator.

```golang
// ToHost takes the raw url to host; report result status and an ip flag
//
//	handles canonical hosts as well as ipv4/6 and idna conversion to punycode
func (s *Sanitize) ToHost(url *string) (result struct {
	Okay, IP bool
})
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
