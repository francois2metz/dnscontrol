package models

import (
	"fmt"
	"strings"

	dnsv2 "codeberg.org/miekg/dns"
	dnsrdatav2 "codeberg.org/miekg/dns/rdata"
	svcbv2 "codeberg.org/miekg/dns/svcb"

	"github.com/DNSControl/dnscontrol/v4/pkg/mustbe"
	_ "github.com/DNSControl/dnscontrol/v4/pkg/privatetypes"
	privatetypesrdata "github.com/DNSControl/dnscontrol/v4/pkg/privatetypes/rdata"
	dnsv1 "github.com/miekg/dns"
)

func MakeA(target any) (dnsv2.RDATA, error) {
	return dnsrdatav2.A{Addr: mustbe.IPv4(target)}, nil
}
func MakeALIAS(origin, target string) (dnsv2.RDATA, error) {
	return privatetypesrdata.ALIAS{Target: mustbe.TargetHost(origin, target)}, nil
}
func MakeAAAA(target any) (dnsv2.RDATA, error) {
	return dnsrdatav2.AAAA{Addr: mustbe.IPv6(target)}, nil
}

func MakeCAA(origin string, flags any, tag any, value any) (dnsv2.RDATA, error) {
	return dnsrdatav2.CAA{Flag: mustbe.Uint8(flags), Tag: mustbe.RawString(tag), Value: mustbe.RawString(value)}, nil
}
func MakeCNAME(origin, target string) (dnsv2.RDATA, error) {
	return dnsrdatav2.CNAME{Target: mustbe.TargetHost(origin, target)}, nil
}
func MakeCFWORKERROUTE(when, then string) (dnsv2.RDATA, error) {
	return privatetypesrdata.CFWORKERROUTE{When: mustbe.RawString(when), Then: mustbe.RawString(then)}, nil
}

func MakeDHCID(origin, target string) (dnsv2.RDATA, error) {
	return dnsrdatav2.DHCID{Digest: mustbe.RawString(target)}, nil
}
func MakeDNAME(origin, target string) (dnsv2.RDATA, error) {
	return dnsrdatav2.DNAME{Target: mustbe.TargetHost(origin, target)}, nil
}
func MakeDNSKEY(origin string, flags any, protocol any, algorithm any, publicKey any) (dnsv2.RDATA, error) {
	return dnsrdatav2.DNSKEY{Flags: mustbe.Uint16(flags), Protocol: mustbe.Uint8(protocol), Algorithm: mustbe.Uint8(algorithm), PublicKey: mustbe.RawString(publicKey)}, nil
}

func MakeDS(origin string, keyTag any, algorithm any, digestType any, digest any) (dnsv2.RDATA, error) {
	return dnsrdatav2.DS{KeyTag: mustbe.Uint16(keyTag), Algorithm: mustbe.Uint8(algorithm), DigestType: mustbe.Uint8(digestType), Digest: mustbe.RawString(digest)}, nil
}

func MakeHTTPS(origin string, priority any, target string, params any) (dnsv2.RDATA, error) {
	return MakeSVCB(origin, priority, target, params)
}

func MakeLOC(origin string,
	version any, size any,
	horizPre any, vertPre any,
	latitude any, longitude any,
	altitude any,
) (dnsv2.RDATA, error) {
	return dnsrdatav2.LOC{
		Version: mustbe.Uint8(version), Size: mustbe.Uint8(size),
		HorizPre: mustbe.Uint8(horizPre), VertPre: mustbe.Uint8(vertPre),
		Latitude: mustbe.Uint32(latitude), Longitude: mustbe.Uint32(longitude),
		Altitude: mustbe.Uint32(altitude)}, nil
}

func MakeMIKROTIKFWD(origin, target string) (dnsv2.RDATA, error) {
	return privatetypesrdata.MIKROTIKFWD{ForwardTo: mustbe.TargetHost(origin, target)}, nil
}
func MakeMIKROTIKNXDOMAIN() (dnsv2.RDATA, error) {
	return privatetypesrdata.MIKROTIKNXDOMAIN{}, nil
}
func MakeMX(origin string, preference any, mx string) (dnsv2.RDATA, error) {
	return dnsrdatav2.MX{Preference: mustbe.Uint16(preference), Mx: mustbe.TargetHost(origin, mx)}, nil
}

func MakeNS(origin, ns string) (dnsv2.RDATA, error) {
	return dnsrdatav2.NS{Ns: mustbe.TargetHost(origin, ns)}, nil
}
func MakeNAPTR(origin string, order any, preference any, flags any, service any, regexp any, replacement string) (dnsv2.RDATA, error) {
	return dnsrdatav2.NAPTR{Order: mustbe.Uint16(order), Preference: mustbe.Uint16(preference), Flags: mustbe.RawString(flags), Service: mustbe.RawString(service), Regexp: mustbe.RawString(regexp), Replacement: mustbe.TargetHost(origin, replacement)}, nil
}

func MakeOPENPGPKEY(origin string, publicKey string) (dnsv2.RDATA, error) {
	return dnsrdatav2.OPENPGPKEY{PublicKey: mustbe.RawString(publicKey)}, nil
}

func MakePORKBUNURLFWD() (dnsv2.RDATA, error) {
	return privatetypesrdata.PORKBUNURLFWD{}, nil
}

func MakePTR(origin, ptr string) (dnsv2.RDATA, error) {
	return dnsrdatav2.PTR{Ptr: mustbe.TargetHost(origin, ptr)}, nil
}

func MakeRP(origin, mbox string, txt string) (dnsv2.RDATA, error) {
	return dnsrdatav2.RP{Mbox: mustbe.TargetHost(origin, mbox), Txt: mustbe.RawString(txt)}, nil
}

func MakeR53ALIAS(origin string, aliasType string, target string, zoneID string, evalTargetHealth any) (dnsv2.RDATA, error) {
	return privatetypesrdata.R53ALIAS{
		AliasType:        mustbe.RawString(aliasType),
		Target:           mustbe.TargetHost(origin, target),
		ZoneID:           mustbe.RawString(zoneID),
		EvalTargetHealth: mustbe.RawString(evalTargetHealth),
		// FIXME(tlim): EvalTargetHealth is a boolean in our internal model but the R53ALIAS type expects a string. This is a hack to convert it to the expected format. We should probably change the R53ALIAS type to use a boolean for this field.
	}, nil
}

func MakeSMIMEA(origin string, usage any, selector any, matchingType any, certificate string) (dnsv2.RDATA, error) {
	return dnsrdatav2.SMIMEA{Usage: mustbe.Uint8(usage), Selector: mustbe.Uint8(selector), MatchingType: mustbe.Uint8(matchingType), Certificate: mustbe.RawString(certificate)}, nil
}

func MakeSOA(origin, ns string, mbox string, serial any, refresh any, retry any, expire any, minttl any) (dnsv2.RDATA, error) {
	return dnsrdatav2.SOA{Ns: mustbe.TargetHost(origin, ns), Mbox: mustbe.TargetHost(origin, mbox), Serial: mustbe.Uint32(serial), Refresh: mustbe.Uint32(refresh), Retry: mustbe.Uint32(retry), Expire: mustbe.Uint32(expire), Minttl: mustbe.Uint32(minttl)}, nil
}

func MakeSRV(origin string, priority any, weight any, port any, target string) (dnsv2.RDATA, error) {
	return dnsrdatav2.SRV{Priority: mustbe.Uint16(priority), Weight: mustbe.Uint16(weight), Port: mustbe.Uint16(port), Target: mustbe.TargetHost(origin, target)}, nil
}

func MakeSSHFP(origin string, algorithm any, fingerprintType any, fingerprint string) (dnsv2.RDATA, error) {
	return dnsrdatav2.SSHFP{Algorithm: mustbe.Uint8(algorithm), Type: mustbe.Uint8(fingerprintType), FingerPrint: mustbe.RawString(fingerprint)}, nil
}

func MakeSVCB(origin string, priority any, target string, params any) (dnsv2.RDATA, error) {
	if priority == 0 {
		return dnsrdatav2.SVCB{Priority: mustbe.Uint16(priority), Target: mustbe.TargetHost(origin, target)}, nil
	}

	switch v := params.(type) {
	case []dnsv1.SVCBKeyValue:
		pv2, err := convertSVCBv1v2(v) // This hasn't tested extensively.
		if err != nil {
			panic("BUG: Failed to convert SVCB parameters from v1 to v2: " + err.Error())
		}
		return dnsrdatav2.SVCB{Priority: mustbe.Uint16(priority), Target: mustbe.TargetHost(origin, target), Value: pv2}, nil
	case []svcbv2.Pair:
		return dnsrdatav2.SVCB{Priority: mustbe.Uint16(priority), Target: mustbe.TargetHost(origin, target), Value: v}, nil
	case string:
		v = strings.ReplaceAll(" "+v+" ", ` ech=IGNORE `, ` ech=1000`)
		v = strings.ReplaceAll(v, `  `, ` `) // Collapse 2 spaces into 1
		v = strings.TrimSpace(v)
		// ech=1000 is a special value that indicates "use the ech value from
		// the existing zone." This is not an RFC standard, just something we do
		// in DNSControl. There is a very small chance that someone will
		// actually have an ech value of "0000" but if that happens I will eat
		// my hat.

		return dnsv2.NewData(dnsv2.TypeHTTPS, fmt.Sprintf("%d %s %s", mustbe.Uint16(priority), mustbe.TargetHost(origin, target), params))
		// NB(tlim): It's an abomination to construct this string just to parse it but dnsv2 doesn't expose the parser in a way to do a partial line.
	}

	panic(fmt.Sprintf("BUG: Invalid params type for SVCB/HTTPS record: %T", params))
}

func MakeTLSA(origin string, usage any, selector any, matchingType any, certificate string) (dnsv2.RDATA, error) {
	return dnsrdatav2.TLSA{Usage: mustbe.Uint8(usage), Selector: mustbe.Uint8(selector), MatchingType: mustbe.Uint8(matchingType), Certificate: mustbe.RawString(certificate)}, nil
}

func MakeTXT(origin string, txt string) (dnsv2.RDATA, error) {
	return dnsrdatav2.TXT{Txt: mustbe.Txts(txt)}, nil
}

func MakeURL(origin string, location string) (dnsv2.RDATA, error) {
	return privatetypesrdata.URL{Location: mustbe.RawString(location)}, nil
}

func MakeURL301(origin string, location string) (dnsv2.RDATA, error) {
	return privatetypesrdata.URL{Location: mustbe.RawString(location)}, nil
}
