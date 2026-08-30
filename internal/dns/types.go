// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrUnknownType indicates an unrecognized or malformed DNS record type name or number.
	ErrUnknownType = errors.New("dns: unknown query type")
)

// Type represents a 16-bit DNS query type as defined by RFC 1035 and subsequent protocol standards.
type Type uint16

const (
	// TypeA requests the IPv4 host address record (RFC 1035 3.4.1).
	TypeA Type = 1
	// TypeNS requests authoritative name server records for the zone delegation (RFC 1035 3.3.11).
	TypeNS Type = 2
	// TypeCNAME requests the canonical name alias record (RFC 1035 3.2.2).
	TypeCNAME Type = 5
	// TypeSOA requests the Start of Authority record for zone administration (RFC 1035 3.3.13).
	TypeSOA Type = 6
	// TypePTR requests a pointer record for in-addr.arpa / ip6.arpa reverse lookups (RFC 1035 3.3.12).
	TypePTR Type = 12
	// TypeMX requests mail exchange routing records (RFC 1035 3.3.9, RFC 7505).
	TypeMX Type = 15
	// TypeTXT requests arbitrary text strings, commonly used for SPF, DKIM, and DMARC (RFC 1035 3.3.14, RFC 7208).
	TypeTXT Type = 16
	// TypeAAAA requests the IPv6 host address record (RFC 3596 2.1).
	TypeAAAA Type = 28
	// TypeSRV requests generalized service location endpoints with port and priority weighting (RFC 2782).
	TypeSRV Type = 33
	// TypeOPT is a pseudo-record for EDNS0 buffer extension negotiation and DNSSEC signaling (RFC 6891 6.1).
	TypeOPT Type = 41
	// TypeDS requests Delegation Signer records establishing the DNSSEC chain of trust (RFC 4034).
	TypeDS Type = 43
	// TypeRRSIG requests cryptographic Resource Record Signatures in DNSSEC (RFC 4034).
	TypeRRSIG Type = 46
	// TypeNSEC requests Next Secure records for authenticated denial of existence (RFC 4034).
	TypeNSEC Type = 47
	// TypeDNSKEY requests zone public keys used for DNSSEC signature verification (RFC 4034).
	TypeDNSKEY Type = 48
	// TypeNSEC3 requests Next Secure 3 records for hashed authenticated denial of existence (RFC 5155).
	TypeNSEC3 Type = 50
	// TypeZONEMD requests cryptographic Zone Message Digest records (RFC 8976).
	TypeZONEMD Type = 63
	// TypeTSIG requests Transaction Signature pseudo-record authentication (RFC 2845 / RFC 8945).
	TypeTSIG Type = 250
	// TypeCAA requests Certification Authority Authorization policy records (RFC 8659).
	TypeCAA Type = 257
	// TypeANY is a meta-query requesting all available records (RFC 1035, restricted by RFC 8482).
	TypeANY Type = 255
)

// String returns the canonical uppercase text mnemonic for the Type.
func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	case TypeDS:
		return "DS"
	case TypeRRSIG:
		return "RRSIG"
	case TypeNSEC:
		return "NSEC"
	case TypeDNSKEY:
		return "DNSKEY"
	case TypeNSEC3:
		return "NSEC3"
	case TypeZONEMD:
		return "ZONEMD"
	case TypeTSIG:
		return "TSIG"
	case TypeCAA:
		return "CAA"
	case TypeANY:
		return "ANY"
	default:
		return "TYPE" + strconv.FormatUint(uint64(t), 10)
	}
}

// ParseType parses a canonical type mnemonic (e.g. "A", "AAAA", "MX") or generic "TYPE<N>" string into its Type.
func ParseType(s string) (Type, error) {
	upper := strings.ToUpper(s)
	switch upper {
	case "A":
		return TypeA, nil
	case "AAAA":
		return TypeAAAA, nil
	case "CNAME":
		return TypeCNAME, nil
	case "TXT":
		return TypeTXT, nil
	case "MX":
		return TypeMX, nil
	case "NS":
		return TypeNS, nil
	case "SOA":
		return TypeSOA, nil
	case "PTR":
		return TypePTR, nil
	case "SRV":
		return TypeSRV, nil
	case "CAA":
		return TypeCAA, nil
	case "DNSKEY":
		return TypeDNSKEY, nil
	case "DS":
		return TypeDS, nil
	case "RRSIG":
		return TypeRRSIG, nil
	case "NSEC":
		return TypeNSEC, nil
	case "NSEC3":
		return TypeNSEC3, nil
	case "ZONEMD":
		return TypeZONEMD, nil
	case "TSIG":
		return TypeTSIG, nil
	case "OPT":
		return TypeOPT, nil
	case "ANY":
		return TypeANY, nil
	default:
		if typeNum, ok := strings.CutPrefix(upper, "TYPE"); ok {
			v, err := strconv.ParseUint(typeNum, 10, 16)
			if err == nil {
				return Type(v), nil
			}
		}
		v, err := strconv.ParseUint(s, 10, 16)
		if err == nil {
			return Type(v), nil
		}
		return 0, fmt.Errorf("%w: %q", ErrUnknownType, s)
	}
}

// Class represents a 16-bit DNS query class as defined by RFC 1035 3.2.4.
type Class uint16

const (
	// ClassIN represents the Internet DNS class (1, RFC 1035).
	ClassIN Class = 1
	// ClassCH represents the CHAOS DNS class (3, RFC 1035).
	ClassCH Class = 3
	// ClassNONE represents the QCLASS NONE condition for Dynamic Updates (254, RFC 2136).
	ClassNONE Class = 254
	// ClassANY represents the QCLASS * / ANY wildcard class (255, RFC 1035 / RFC 2136).
	ClassANY Class = 255
)

// String returns the text representation of the Class.
func (c Class) String() string {
	switch c {
	case ClassIN:
		return "IN"
	case ClassCH:
		return "CH"
	case ClassNONE:
		return "NONE"
	case ClassANY:
		return "ANY"
	default:
		return "CLASS" + strconv.FormatUint(uint64(c), 10)
	}
}

// RCode represents a 4-bit DNS response code as defined in RFC 1035 4.1.1 and RFC 2136 2.2.
type RCode byte

const (
	// RCodeSuccess indicates that the request completed without error (0, NOERROR, RFC 1035).
	RCodeSuccess RCode = 0
	// RCodeFormatError indicates the server was unable to interpret the query format (1, FORMERR, RFC 1035).
	RCodeFormatError RCode = 1
	// RCodeServerFailure indicates the server encountered an internal failure processing the request (2, SERVFAIL, RFC 1035).
	RCodeServerFailure RCode = 2
	// RCodeNameError indicates the queried domain name does not exist in the authoritative zone (3, NXDOMAIN, RFC 1035).
	RCodeNameError RCode = 3
	// RCodeNotImplemented indicates the requested opcode or query type is not supported (4, NOTIMP, RFC 1035).
	RCodeNotImplemented RCode = 4
	// RCodeRefused indicates the server refuses to perform the operation for policy reasons (5, REFUSED, RFC 1035).
	RCodeRefused RCode = 5
	// RCodeYXDomain indicates a name exists when it should not (6, YXDOMAIN, RFC 2136).
	RCodeYXDomain RCode = 6
	// RCodeYXRRSet indicates an RRSet exists when it should not (7, YXRRSET, RFC 2136).
	RCodeYXRRSet RCode = 7
	// RCodeNXRRSet indicates an RRSet that should exist does not (8, NXRRSET, RFC 2136).
	RCodeNXRRSet RCode = 8
	// RCodeNotAuth indicates the server is not authoritative for the zone or update is not authorized (9, NOTAUTH, RFC 2136).
	RCodeNotAuth RCode = 9
	// RCodeNotZone indicates a prerequisite or update name is outside the zone (10, NOTZONE, RFC 2136).
	RCodeNotZone RCode = 10
)

const (
	// TSIGErrBadSig indicates signature validation failed (16, RFC 2845 / RFC 8945).
	TSIGErrBadSig uint16 = 16
	// TSIGErrBadKey indicates the key was not recognized (17, RFC 2845 / RFC 8945).
	TSIGErrBadKey uint16 = 17
	// TSIGErrBadTime indicates the signature time stamp is outside the allowed fudge window (18, RFC 2845 / RFC 8945).
	TSIGErrBadTime uint16 = 18
	// TSIGErrBadMode indicates bad TKEY mode (19, RFC 2930).
	TSIGErrBadMode uint16 = 19
	// TSIGErrBadName indicates duplicate key name (20, RFC 2845).
	TSIGErrBadName uint16 = 20
	// TSIGErrBadAlg indicates unsupported algorithm (21, RFC 2845 / RFC 8945).
	TSIGErrBadAlg uint16 = 21
	// TSIGErrBadTrunc indicates bad truncation (22, RFC 4635 / RFC 8945).
	TSIGErrBadTrunc uint16 = 22
)

// String returns the standard mnemonic text representation of the RCode.
func (r RCode) String() string {
	switch r {
	case RCodeSuccess:
		return "NOERROR"
	case RCodeFormatError:
		return "FORMERR"
	case RCodeServerFailure:
		return "SERVFAIL"
	case RCodeNameError:
		return "NXDOMAIN"
	case RCodeNotImplemented:
		return "NOTIMP"
	case RCodeRefused:
		return "REFUSED"
	case RCodeYXDomain:
		return "YXDOMAIN"
	case RCodeYXRRSet:
		return "YXRRSET"
	case RCodeNXRRSet:
		return "NXRRSET"
	case RCodeNotAuth:
		return "NOTAUTH"
	case RCodeNotZone:
		return "NOTZONE"
	default:
		return "RCODE" + strconv.FormatUint(uint64(r), 10)
	}
}

// Opcode represents a 4-bit DNS query operation code as defined in RFC 1035 4.1.1.
type Opcode byte

const (
	// OpcodeQuery represents a standard forward DNS query (0, RFC 1035).
	OpcodeQuery Opcode = 0
	// OpcodeIQuery represents an inverse DNS query (1, RFC 1035, obsoleted by RFC 3425).
	OpcodeIQuery Opcode = 1
	// OpcodeStatus represents a server status inquiry request (2, RFC 1035).
	OpcodeStatus Opcode = 2
	// OpcodeNotify represents an authoritative zone change notification (4, RFC 1996).
	OpcodeNotify Opcode = 4
	// OpcodeUpdate represents a dynamic DNS zone update request (5, RFC 2136).
	OpcodeUpdate Opcode = 5
)

// String returns the standard mnemonic text representation of the Opcode.
func (o Opcode) String() string {
	switch o {
	case OpcodeQuery:
		return "QUERY"
	case OpcodeIQuery:
		return "IQUERY"
	case OpcodeStatus:
		return "STATUS"
	case OpcodeNotify:
		return "NOTIFY"
	case OpcodeUpdate:
		return "UPDATE"
	default:
		return "OTHER"
	}
}

// Header represents the 12-byte fixed DNS message header defined in RFC 1035 4.1.1.
// Header bitfield layout in wire format (16-bit Flags word):
//
//	 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	|QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//	QR:     Query (0) / Response (1)          [bit 15]
//	OPCODE: Operation Code (4 bits)           [bits 11-14]
//	AA:     Authoritative Answer              [bit 10]
//	TC:     Truncation Flag                   [bit 9]
//	RD:     Recursion Desired                 [bit 8]
//	RA:     Recursion Available               [bit 7]
//	Z:      Zero / Reserved (3 bits)          [bits 4-6]
//	RCODE:  Response Code (4 bits)            [bits 0-3]
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Opcode extracts the 4-bit OPCODE field from the Header flags word (bits 11-14).
func (h Header) Opcode() Opcode {
	return Opcode((h.Flags >> 11) & 0x0F)
}

// RCode extracts the 4-bit RCODE field from the Header flags word (bits 0-3).
func (h Header) RCode() RCode {
	return RCode(h.Flags & 0x0F)
}

// IsResponse reports whether the QR bit (bit 15) is set, indicating a response packet (RFC 1035 4.1.1).
func (h Header) IsResponse() bool {
	return (h.Flags & 0x8000) != 0
}

// Question represents a single entry in the DNS question section (RFC 1035 4.1.2).
type Question struct {
	Name  string
	Type  Type
	Class Class
}

// RRSet represents a Resource Record Set sharing the same Name, Type, and Class (RFC 2181).
type RRSet struct {
	RData [][]byte
	TTL   uint32
	Type  Type
	Class Class
}

// HasRecords reports whether the RRSet contains at least one resource record payload.
func (r RRSet) HasRecords() bool {
	return len(r.RData) > 0
}

// RRSets represents an ordered collection of Resource Record Sets for a domain node.
type RRSets []RRSet

// Get retrieves the resource record set for the specified DNS type.
func (s RRSets) Get(qType Type) (RRSet, bool) {
	for _, set := range s {
		if set.Type == qType {
			return set, true
		}
	}
	return RRSet{}, false
}

// Clone performs a deep copy of the RRSets and its inner binary RData slices,
// guaranteeing complete memory isolation for copy-on-write state swaps.
func (s RRSets) Clone() RRSets {
	if s == nil {
		return nil
	}
	cloned := make(RRSets, len(s))
	for i := range s {
		cloned[i] = RRSet{
			Type:  s[i].Type,
			Class: s[i].Class,
			TTL:   s[i].TTL,
		}
		if s[i].RData != nil {
			cloned[i].RData = make([][]byte, len(s[i].RData))
			for j, wireBytes := range s[i].RData {
				cloned[i].RData[j] = bytes.Clone(wireBytes)
			}
		}
	}
	return cloned
}

// Result encapsulates the complete authoritative resolution outcome from the DNS data plane.
type Result struct {
	AuthorityName  string
	Answer         RRSet
	AnswerRRSIG    RRSet
	Authority      RRSet
	AuthorityRRSIG RRSet
	Additional     RRSet
	RCode          RCode
}

// HasAnswer reports whether the resolution produced an answer payload in the Answer section.
func (r Result) HasAnswer() bool {
	return r.Answer.HasRecords()
}

// HasAnswerRRSIG reports whether an RRSIG signature is present for the Answer section.
func (r Result) HasAnswerRRSIG() bool {
	return r.AnswerRRSIG.HasRecords()
}

// HasAuthority reports whether the resolution produced an authority payload in the Authority section.
func (r Result) HasAuthority() bool {
	return r.Authority.HasRecords()
}

// HasAuthorityRRSIG reports whether an RRSIG signature is present for the Authority section.
func (r Result) HasAuthorityRRSIG() bool {
	return r.AuthorityRRSIG.HasRecords()
}

// HasAdditional reports whether the resolution produced an additional payload in the Additional section.
func (r Result) HasAdditional() bool {
	return r.Additional.HasRecords()
}
