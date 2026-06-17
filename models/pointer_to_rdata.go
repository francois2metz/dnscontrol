package models

import (
	"fmt"

	dnsv2 "codeberg.org/miekg/dns"
	dnsrdatav2 "codeberg.org/miekg/dns/rdata"
)

func AssureItsAPointer(rd dnsv2.RDATA) dnsv2.RDATA {
	switch v := rd.(type) {
	case dnsrdatav2.A:
		return &v
	case dnsrdatav2.AAAA:
		return &v
	case dnsrdatav2.CNAME:
		return &v
	case dnsrdatav2.MX:
		return &v
	case dnsrdatav2.NS:
		return &v
	case dnsrdatav2.RP:
		return &v
	case dnsrdatav2.SVCB:
		return &v
	case dnsrdatav2.TXT:
		return &v
	}
	fmt.Printf("\nDEBUG: PointerToRDATA: Please add %T\n\n", rd)
	return rd
}
