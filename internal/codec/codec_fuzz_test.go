// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codec

import (
	"bytes"
	"hash/crc32"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

func FuzzDecoder_ReadRecord(f *testing.F) {
	var buf bytes.Buffer
	hashW := crc32.NewIEEE()
	enc := NewEncoder(&buf, hashW)
	a1, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	_ = enc.WriteRecord("example.com", dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{a1}},
	})
	_ = enc.Flush()
	f.Add(buf.Bytes())

	f.Fuzz(func(_ *testing.T, data []byte) {
		br := bytes.NewReader(data)
		hashR := crc32.NewIEEE()
		dec := NewDecoder(br, hashR)
		_, _, _ = dec.ReadRecord()
	})
}

func FuzzEncoder_WriteRecord(f *testing.F) {
	f.Add("example.com", uint16(1), uint32(300), "1.1.1.1")
	f.Add("example.com", uint16(28), uint32(300), "2001:db8::1")
	f.Add("example.com", uint16(5), uint32(300), "target.example.com")
	f.Add("example.com", uint16(16), uint32(3600), "v=spf1 -all")
	f.Add("example.com", uint16(2), uint32(3600), "ns1.example.com")
	f.Add("example.com", uint16(12), uint32(3600), "printer.local")
	f.Add("example.com", uint16(6), uint32(3600), "ns1.example.com admin.example.com 2026081201 7200 3600 1209600 3600")
	f.Add("example.com", uint16(15), uint32(300), "10 mail.example.com")
	f.Add("example.com", uint16(33), uint32(300), "10 60 5060 sip.example.com")
	f.Add("example.com", uint16(48), uint32(3600), "256 3 8 AwEAAag=")
	f.Add("example.com", uint16(43), uint32(3600), "60999 8 2 2BB1832F")
	f.Add("example.com", uint16(46), uint32(3600), "A 8 2 300 20260901000000 20260801000000 60999 example.com. AwEAAag=")
	f.Add("example.com", uint16(47), uint32(3600), "next.example.com. A AAAA RRSIG NSEC")
	f.Add("example.com", uint16(50), uint32(3600), "1 0 10 AABBCCDD 09BE1F9856A15F431C8B9A2E12345678 A AAAA RRSIG NSEC3")
	f.Add("example.com", uint16(63), uint32(3600), "2026081201 1 1 09BE1F9856A15F431C8B9A2E12345678")
	f.Add("example.com", uint16(257), uint32(3600), `0 issue "letsencrypt.org"`)

	f.Fuzz(func(_ *testing.T, domain string, qType uint16, ttl uint32, rdataVal string) {
		var buf bytes.Buffer
		hashW := crc32.NewIEEE()
		enc := NewEncoder(&buf, hashW)

		wireBytes, err := dns.PackRData(dns.Type(qType), rdataVal)
		if err != nil {
			wireBytes = []byte(rdataVal)
		}

		records := dns.RRSets{
			{Type: dns.Type(qType), Class: dns.ClassIN, TTL: ttl, RData: [][]byte{wireBytes}},
		}

		_ = enc.WriteRecord(domain, records)
	})
}
