package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/miekg/dns"
)

func main() {
	server := flag.String("server", "127.0.0.1:1053", "dns server ip:port")
	qname := flag.String("name", "deneme.com.", "fqdn")
	qtype := flag.String("type", "A", "qtype")
	flag.Parse()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(*qname), strToType(*qtype))
	m.RecursionDesired = false

	c := &dns.Client{Net: "udp"}
	r, _, err := c.Exchange(m, *server)
	if err != nil {
		log.Fatal(err)
	}
	if r.Truncated {
		c = &dns.Client{Net: "tcp"}
		r, _, err = c.Exchange(m, *server)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println(";; ->>HEADER<<-", dns.RcodeToString[r.Rcode], "AA=", r.Authoritative, "RA=", r.RecursionAvailable)
	for _, a := range r.Answer {
		fmt.Println(a.String())
	}
	for _, ns := range r.Ns {
		fmt.Println("AUTH:", ns.String())
	}
	for _, ex := range r.Extra {
		fmt.Println("EXTRA:", ex.String())
	}
}

func strToType(s string) uint16 {
	switch s {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "CNAME":
		return dns.TypeCNAME
	case "MX":
		return dns.TypeMX
	case "NS":
		return dns.TypeNS
	case "TXT":
		return dns.TypeTXT
	case "SRV":
		return dns.TypeSRV
	default:
		return dns.TypeA
	}
}
