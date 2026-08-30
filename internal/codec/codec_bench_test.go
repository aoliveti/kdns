// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codec

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

// BenchmarkCodec_EncodeOnly measures pure serialization throughput and allocations
// simulating the Write-Ahead Log (WAL) record logging path.
func BenchmarkCodec_EncodeOnly(b *testing.B) {
	domain := "example.com"
	a1, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	a2, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	txt1, _ := dns.PackRData(dns.TypeTXT, "v=spf1 ~all")
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{a1, a2}},
		{Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{txt1}},
	}

	hashW := crc32.NewIEEE()
	enc := NewEncoder(io.Discard, hashW)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		hashW.Reset()
		enc.Reset(io.Discard, hashW)
		_ = enc.WriteRecord(domain, records)
	}
}

// BenchmarkCodec_DecodeOnly measures pure deserialization throughput and allocations
// simulating cold-start snapshot replay and WAL recovery.
func BenchmarkCodec_DecodeOnly(b *testing.B) {
	domain := "example.com"
	a1, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	a2, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	txt1, _ := dns.PackRData(dns.TypeTXT, "v=spf1 ~all")
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{a1, a2}},
		{Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{txt1}},
	}

	var prefilled bytes.Buffer
	enc := NewEncoder(&prefilled, crc32.NewIEEE())
	_ = enc.WriteRecord(domain, records)
	rawFrame := prefilled.Bytes()

	reader := bytes.NewReader(rawFrame)
	hashR := crc32.NewIEEE()
	dec := NewDecoder(reader, hashR)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		reader.Reset(rawFrame)
		hashR.Reset()
		dec.Reset(reader, hashR)
		_, _, _ = dec.ReadRecord()
	}
}

// BenchmarkCodec_DNSSEC_Heavy measures serialization and deserialization efficiency
// on high-volume cryptographic payloads (DNSKEY, RRSIG, NSEC3).
func BenchmarkCodec_DNSSEC_Heavy(b *testing.B) {
	domain := "secure.example.com"
	dnskey, _ := dns.PackRData(dns.TypeDNSKEY, "256 3 8 AwEAAag=")
	rrsig, _ := dns.PackRData(dns.TypeRRSIG, "A 8 2 300 20260901000000 20260801000000 60999 example.com. AwEAAag=")
	nsec3, _ := dns.PackRData(dns.TypeNSEC3, "1 0 10 AABBCCDD 09BE1F9856A15F431C8B9A2E12345678 A AAAA RRSIG NSEC3")

	records := dns.RRSets{
		{Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dnskey}},
		{Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{rrsig}},
		{Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{nsec3}},
	}

	var buf bytes.Buffer
	hashW := crc32.NewIEEE()
	enc := NewEncoder(&buf, hashW)

	hashR := crc32.NewIEEE()
	dec := NewDecoder(&buf, hashR)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		buf.Reset()
		hashW.Reset()
		enc.Reset(&buf, hashW)

		_ = enc.WriteRecord(domain, records)

		hashR.Reset()
		dec.Reset(&buf, hashR)
		_, _, _ = dec.ReadRecord()
	}
}

// BenchmarkCodec_BulkStream_Throughput evaluates streaming performance across 1000 continuous records,
// reporting data throughput in MB/s.
func BenchmarkCodec_BulkStream_Throughput(b *testing.B) {
	const batchSize = 1000
	domains := make([]string, batchSize)
	domainRecords := make([]dns.RRSets, batchSize)

	wireA, _ := dns.PackRData(dns.TypeA, "192.0.2.1")
	wireAAAA, _ := dns.PackRData(dns.TypeAAAA, "2001:db8::1")

	var sampleBuffer bytes.Buffer
	tmpEnc := NewEncoder(&sampleBuffer, crc32.NewIEEE())

	for i := range batchSize {
		domains[i] = fmt.Sprintf("bulk-node-%d.example.com", i)
		domainRecords[i] = dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{wireA}},
			{Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{wireAAAA}},
		}
		_ = tmpEnc.WriteRecord(domains[i], domainRecords[i])
	}

	totalBatchBytes := int64(sampleBuffer.Len())
	rawBatchBytes := sampleBuffer.Bytes()

	b.SetBytes(totalBatchBytes)
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		reader := bytes.NewReader(rawBatchBytes)
		hashR := crc32.NewIEEE()
		dec := NewDecoder(reader, hashR)

		for range batchSize {
			_, _, err := dec.ReadRecord()
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkCodec_RoundTrip measures one-shot encoding and decoding per record.
func BenchmarkCodec_RoundTrip(b *testing.B) {
	domain := "example.com"
	a1, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	a2, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	txt1, _ := dns.PackRData(dns.TypeTXT, "v=spf1 ~all")
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{a1, a2}},
		{Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{txt1}},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		var buf bytes.Buffer
		hashW := crc32.NewIEEE()
		enc := NewEncoder(&buf, hashW)
		_ = enc.WriteRecord(domain, records)
		_ = enc.Flush()

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		_, _, _ = dec.ReadRecord()
	}
}

// BenchmarkCodec_RoundTrip_Streaming measures performance in a persistent stream (WAL / Snapshot replay)
// by reusing encoder/decoder instances and buffer memory.
func BenchmarkCodec_RoundTrip_Streaming(b *testing.B) {
	domain := "example.com"
	a1, _ := dns.PackRData(dns.TypeA, "192.168.1.1")
	a2, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
	txt1, _ := dns.PackRData(dns.TypeTXT, "v=spf1 ~all")
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{a1, a2}},
		{Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{txt1}},
	}

	var buf bytes.Buffer
	hashW := crc32.NewIEEE()
	enc := NewEncoder(&buf, hashW)

	hashR := crc32.NewIEEE()
	dec := NewDecoder(&buf, hashR)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		buf.Reset()
		hashW.Reset()
		enc.Reset(&buf, hashW)

		_ = enc.WriteRecord(domain, records)
		_ = enc.Flush()

		hashR.Reset()
		dec.Reset(&buf, hashR)
		_, _, _ = dec.ReadRecord()
	}
}
