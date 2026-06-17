package models

import (
	"fmt"
	"runtime/debug"
	"strings"

	dnsv2 "codeberg.org/miekg/dns"
)

func (rc *RecordConfig) SetRDATA(rd dnsv2.RDATA) {
	rc.rdata = rd
	rc.ValidateRDATA()
}

func (rc *RecordConfig) GetRDATA() (rd dnsv2.RDATA) {
	return rc.rdata
}

func (rc *RecordConfig) ClearRDATA() {
	rc.rdata = nil
}

func (rc *RecordConfig) ValidateRDATA() {

	if rc.GetRDATA() == nil {
		return
	}

	tn := fmt.Sprintf("%T", rc.GetRDATA())

	if strings.HasPrefix(tn, "*rdata.") {
		return
	}
	if strings.HasPrefix(tn, "*privatetypesrdata.") {
		return
	}

	l := fmt.Sprintf("\nDEBUG: ValidateRDATA: %s\n", tn)
	fmt.Println(l)
	fmt.Println(string(debug.Stack()))
	// panic(l)
}
