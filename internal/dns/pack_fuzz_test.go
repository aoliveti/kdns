// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "testing"

// FuzzMessage_PackResponse bombards the serializer with randomized data to ensure memory safety.
func FuzzMessage_PackResponse(f *testing.F) {
	f.Add("example.com", "192.168.1.1", uint16(TypeA))
	f.Add("ipv6.network", "2001:db8::1", uint16(TypeAAAA))
	f.Add("alias.example.com", "target.example.com", uint16(TypeCNAME))
	f.Add("txt.domain", "v=spf1 -all", uint16(TypeTXT))
	f.Add("ns.example.com", "ns1.example.com", uint16(TypeNS))
	f.Add("ptr.example.com", "printer.local", uint16(TypePTR))
	f.Add("soa.example.com", "ns1.example.com admin.example.com 2026081201 7200 3600 1209600 3600", uint16(TypeSOA))
	f.Add("mx.example.com", "10 mail.example.com", uint16(TypeMX))
	f.Add("srv.example.com", "10 60 5060 sipserver.example.com", uint16(TypeSRV))
	f.Add("dnskey.example.com", "256 3 8 AwEAAag=", uint16(TypeDNSKEY))
	f.Add("ds.example.com", "60999 8 2 2BB1832F", uint16(TypeDS))
	f.Add("rrsig.example.com", "A 8 2 300 20260901000000 20260801000000 60999 example.com. AwEAAag=", uint16(TypeRRSIG))
	f.Add("nsec.example.com", "next.example.com. A AAAA RRSIG NSEC", uint16(TypeNSEC))
	f.Add("nsec3.example.com", "1 0 10 AABBCCDD 09BE1F9856A15F431C8B9A2E12345678 A AAAA RRSIG NSEC3", uint16(TypeNSEC3))
	f.Add("zonemd.example.com", "2026081201 1 1 09BE1F9856A15F431C8B9A2E12345678", uint16(TypeZONEMD))
	f.Add("caa.example.com", `0 issue "letsencrypt.org"`, uint16(TypeCAA))
	f.Add("", "", uint16(0))

	f.Fuzz(func(_ *testing.T, qName string, rdata string, rawType uint16) {
		msg := Message{
			Header: Header{ID: 1234},
			Questions: []Question{
				{
					Name:  qName,
					Type:  Type(rawType),
					Class: ClassIN,
				},
			},
			EDNS0Size: 4096,
		}

		wireBytes, err := PackRData(Type(rawType), rdata)
		if err != nil {
			wireBytes = []byte(rdata)
		}

		record := RRSet{
			Type:  Type(rawType),
			Class: ClassIN,
			TTL:   300,
			RData: [][]byte{wireBytes},
		}

		res := Result{
			RCode:  RCodeSuccess,
			Answer: record,
		}

		buf := make([]byte, 512)

		_, _ = msg.PackResponse(buf, res, 512)
	})
}
