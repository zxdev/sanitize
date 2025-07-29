package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/zxdev/sanitize"
)

// GOOS=linux GOARCH=amd64 go build -o sanitize cmd/main.go

func main() {

	var writer = os.Stdout
	var reader = os.Stdin
	var invalid = os.Stderr

	if len(os.Args) > 1 {
		switch strings.TrimLeft(os.Args[1], "-") {
		case "help":
			fmt.Println("\nsanitize - validate list of urls")
			fmt.Println("IP=on retains Ipv4/6 addresses")
			fmt.Println("TLD=on retains bad tld")
			return
		default:
			f, err := os.Open(os.Args[1])
			if err == nil {
				defer f.Close()
				reader = f
			}
		}
	}

	var ip bool
	switch os.Getenv("IP") {
	case "on", "true", "1":
		ip = true
		f, err := os.Open(os.Args[1])
		if err == nil {
			defer f.Close()
			reader = f
		}

	}

	var tld bool
	switch os.Getenv("TLD") {
	case "on", "true", "1":
		tld = true
	}
	tld = !tld

	var host string
	var s = sanitize.NewTLDSanitizer()
	var scanner = bufio.NewScanner(reader)
	for scanner.Scan() {
		host = scanner.Text()
		r := s.ToHost(&host)
		switch {
		case !r.Okay:

		case r.IP && !ip:
			fmt.Fprintln(invalid, host)
		case r.IP && ip:
			fmt.Fprintln(writer, host)

		case r.TLD == 0 && tld:
			fmt.Fprintln(invalid, host)
		case r.TLD > 0:
			fmt.Fprintln(writer, host)
		}
	}

}
