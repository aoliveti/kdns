// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codec

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestEncodeDecode_RecordRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		domain  string
		records dns.RRSets
	}{
		{
			name:   "RecordType_A",
			domain: "a.example.com",
			records: dns.RRSets{
				{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.168.1.1"), dns.MustPackRData(dns.TypeA, "10.0.0.1")}},
			},
		},
		{
			name:   "RecordType_AAAA",
			domain: "aaaa.example.com",
			records: dns.RRSets{
				{Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeAAAA, "2001:db8::1")}},
			},
		},
		{
			name:   "RecordType_TXT",
			domain: "txt.example.com",
			records: dns.RRSets{
				{Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "v=spf1 ~all")}},
			},
		},
		{
			name:   "RecordType_CNAME",
			domain: "alias.example.com",
			records: dns.RRSets{
				{Type: dns.TypeCNAME, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeCNAME, "target.example.com.")}},
			},
		},
		{
			name:   "RecordType_NS",
			domain: "ns.example.com",
			records: dns.RRSets{
				{Type: dns.TypeNS, Class: dns.ClassIN, TTL: 86400, RData: [][]byte{dns.MustPackRData(dns.TypeNS, "ns1.example.com."), dns.MustPackRData(dns.TypeNS, "ns2.example.com.")}},
			},
		},
		{
			name:   "RecordType_PTR",
			domain: "1.1.168.192.in-addr.arpa",
			records: dns.RRSets{
				{Type: dns.TypePTR, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypePTR, "host.example.com.")}},
			},
		},
		{
			name:   "RecordType_SOA",
			domain: "example.com",
			records: dns.RRSets{
				{Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 86400, RData: [][]byte{dns.MustPackRData(dns.TypeSOA, "ns1.example.com. admin.example.com. 2026081200 7200 3600 1209600 3600")}},
			},
		},
		{
			name:   "RecordType_MX",
			domain: "mail.example.com",
			records: dns.RRSets{
				{Type: dns.TypeMX, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeMX, "10 mail.example.com"), dns.MustPackRData(dns.TypeMX, "20 mail2.example.com")}},
			},
		},
		{
			name:   "RecordType_SRV",
			domain: "service._tcp.example.com",
			records: dns.RRSets{
				{Type: dns.TypeSRV, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeSRV, "0 5 5060 sip.example.com")}},
			},
		},
		{
			name:   "RecordType_CAA",
			domain: "caa.example.com",
			records: dns.RRSets{
				{Type: dns.TypeCAA, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeCAA, `0 issue "letsencrypt.org"`)}},
			},
		},
		{
			name:   "RecordType_DNSKEY",
			domain: "dnskey.example.com",
			records: dns.RRSets{
				{Type: dns.TypeDNSKEY, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeDNSKEY, "256 3 8 AwEAAag=")}},
			},
		},
		{
			name:   "RecordType_DS",
			domain: "ds.example.com",
			records: dns.RRSets{
				{Type: dns.TypeDS, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeDS, "60999 8 2 2BB1832F")}},
			},
		},
		{
			name:   "RecordType_RRSIG",
			domain: "rrsig.example.com",
			records: dns.RRSets{
				{Type: dns.TypeRRSIG, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeRRSIG, "A 8 2 300 20260901000000 20260801000000 60999 example.com. AwEAAag=")}},
			},
		},
		{
			name:   "RecordType_NSEC",
			domain: "nsec.example.com",
			records: dns.RRSets{
				{Type: dns.TypeNSEC, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeNSEC, "next.example.com. A AAAA RRSIG NSEC")}},
			},
		},
		{
			name:   "RecordType_NSEC3",
			domain: "nsec3.example.com",
			records: dns.RRSets{
				{Type: dns.TypeNSEC3, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeNSEC3, "1 0 10 AABBCCDD 09BE1F9856A15F431C8B9A2E12345678 A AAAA RRSIG NSEC3")}},
			},
		},
		{
			name:   "RecordType_ZONEMD",
			domain: "zonemd.example.com",
			records: dns.RRSets{
				{Type: dns.TypeZONEMD, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeZONEMD, "2026081201 1 1 09BE1F9856A15F431C8B9A2E12345678")}},
			},
		},
		{
			name:   "MultiRecordSet",
			domain: "multi.example.com",
			records: dns.RRSets{
				{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.168.1.1")}},
				{Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeAAAA, "2001:db8::1")}},
				{Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "v=spf1 ~all")}},
				{Type: dns.TypeMX, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeMX, "10 mail.example.com")}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			hashW := crc32.NewIEEE()
			enc := NewEncoder(&buf, hashW)

			require.NoError(t, enc.WriteRecord(tt.domain, tt.records))
			require.NoError(t, enc.Flush())

			hashR := crc32.NewIEEE()
			dec := NewDecoder(&buf, hashR)

			readDomain, readRecords, err := dec.ReadRecord()
			require.NoError(t, err)

			assert.Equal(t, tt.domain, readDomain)
			assert.Equal(t, tt.records, readRecords)
			assert.Equal(t, hashW.Sum32(), hashR.Sum32())
		})
	}
}

func TestEncodeDecode_EdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("RootDomain", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		hashW := crc32.NewIEEE()
		enc := NewEncoder(&buf, hashW)

		records := dns.RRSets{
			{Type: dns.TypeNS, Class: dns.ClassIN, TTL: 86400, RData: [][]byte{dns.MustPackRData(dns.TypeNS, "a.root-servers.net.")}},
		}

		require.NoError(t, enc.WriteRecord("", records))
		require.NoError(t, enc.Flush())

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		readDomain, readRecords, err := dec.ReadRecord()
		require.NoError(t, err)
		assert.Empty(t, readDomain)
		assert.Equal(t, records, readRecords)
	})

	t.Run("ZeroRecords", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		hashW := crc32.NewIEEE()
		enc := NewEncoder(&buf, hashW)

		require.NoError(t, enc.WriteRecord("empty.example.com", dns.RRSets{}))
		require.NoError(t, enc.Flush())

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		readDomain, readRecords, err := dec.ReadRecord()
		require.NoError(t, err)
		assert.Equal(t, "empty.example.com", readDomain)
		assert.Empty(t, readRecords)
	})

	t.Run("EmptyRDataSlice", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		hashW := crc32.NewIEEE()
		enc := NewEncoder(&buf, hashW)

		records := dns.RRSets{
			{Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 60, RData: [][]byte{}},
		}

		require.NoError(t, enc.WriteRecord("nodata.example.com", records))
		require.NoError(t, enc.Flush())

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		readDomain, readRecords, err := dec.ReadRecord()
		require.NoError(t, err)
		assert.Equal(t, "nodata.example.com", readDomain)
		assert.Equal(t, records, readRecords)
	})
}

func TestEncodeDecode_CapacityBounds(t *testing.T) {
	t.Parallel()

	t.Run("DomainLengthOverflow", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		hashW := crc32.NewIEEE()
		enc := NewEncoder(&buf, hashW)
		oversizedDomain := strings.Repeat("a", MaxDomainLen+1)

		err := enc.WriteRecord(oversizedDomain, dns.RRSets{})
		require.ErrorIs(t, err, ErrCapacityExceeded)
	})

	t.Run("RecordsPerDomainOverflow", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		hashW := crc32.NewIEEE()
		enc := NewEncoder(&buf, hashW)
		oversizedRecords := make(dns.RRSets, MaxRecordsPerDomain+1)
		for i := range oversizedRecords {
			oversizedRecords[i] = dns.RRSet{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{{1, 1, 1, 1}}}
		}

		err := enc.WriteRecord("example.com", oversizedRecords)
		require.ErrorIs(t, err, ErrCapacityExceeded)
	})

	t.Run("RDataCountOverflow", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		hashW := crc32.NewIEEE()
		enc := NewEncoder(&buf, hashW)
		oversizedRData := make([][]byte, MaxRDataCount+1)
		for i := range oversizedRData {
			oversizedRData[i] = []byte{1, 1, 1, 1}
		}
		records := dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: oversizedRData}}

		err := enc.WriteRecord("example.com", records)
		require.ErrorIs(t, err, ErrCapacityExceeded)
	})

	t.Run("RDataLengthOverflow", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		hashW := crc32.NewIEEE()
		enc := NewEncoder(&buf, hashW)
		oversizedData := make([]byte, MaxRDataLen+1)
		records := dns.RRSets{{Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 300, RData: [][]byte{oversizedData}}}

		err := enc.WriteRecord("example.com", records)
		require.ErrorIs(t, err, ErrCapacityExceeded)
	})
}

func TestDecoder_CorruptedStream(t *testing.T) {
	t.Parallel()

	t.Run("DomainExceedsRFC1035Limit", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		var lenBytes [2]byte
		binary.BigEndian.PutUint16(lenBytes[:], uint16(MaxDomainLen+1))
		buf.Write(lenBytes[:])

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		_, _, err := dec.ReadRecord()
		require.ErrorIs(t, err, ErrCorruptedData)
	})

	t.Run("RecordsCountExceedsLimit", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		domain := "example.com"
		var lenBytes [2]byte
		// #nosec G115
		binary.BigEndian.PutUint16(lenBytes[:], uint16(len(domain)))
		buf.Write(lenBytes[:])
		buf.WriteString(domain)

		binary.BigEndian.PutUint16(lenBytes[:], uint16(MaxRecordsPerDomain+1))
		buf.Write(lenBytes[:])

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		_, _, err := dec.ReadRecord()
		require.ErrorIs(t, err, ErrCorruptedData)
	})

	t.Run("RDataCountExceedsLimit", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		domain := "example.com"
		var buf2 [2]byte
		var buf4 [4]byte

		// #nosec G115
		binary.BigEndian.PutUint16(buf2[:], uint16(len(domain)))
		buf.Write(buf2[:])
		buf.WriteString(domain)

		binary.BigEndian.PutUint16(buf2[:], 1)
		buf.Write(buf2[:])

		binary.BigEndian.PutUint16(buf2[:], uint16(dns.TypeA))
		buf.Write(buf2[:])

		binary.BigEndian.PutUint32(buf4[:], 300)
		buf.Write(buf4[:])

		binary.BigEndian.PutUint16(buf2[:], uint16(MaxRDataCount+1))
		buf.Write(buf2[:])

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		_, _, err := dec.ReadRecord()
		require.ErrorIs(t, err, ErrCorruptedData)
	})

	t.Run("TruncatedRDataPayload", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		domain := "example.com"
		var buf2 [2]byte
		var buf4 [4]byte

		// #nosec G115
		binary.BigEndian.PutUint16(buf2[:], uint16(len(domain)))
		buf.Write(buf2[:])
		buf.WriteString(domain)

		binary.BigEndian.PutUint16(buf2[:], 1)
		buf.Write(buf2[:])

		binary.BigEndian.PutUint16(buf2[:], uint16(dns.TypeA))
		buf.Write(buf2[:])
		binary.BigEndian.PutUint32(buf4[:], 300)
		buf.Write(buf4[:])
		binary.BigEndian.PutUint16(buf2[:], 1)
		buf.Write(buf2[:])

		binary.BigEndian.PutUint16(buf2[:], 100)
		buf.Write(buf2[:])
		buf.Write([]byte{1, 2, 3, 4})

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		_, _, err := dec.ReadRecord()
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("TruncatedRRSetMetadata", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		domain := "example.com"
		var buf2 [2]byte

		// #nosec G115
		binary.BigEndian.PutUint16(buf2[:], uint16(len(domain)))
		buf.Write(buf2[:])
		buf.WriteString(domain)

		binary.BigEndian.PutUint16(buf2[:], 1)
		buf.Write(buf2[:])
		buf.Write([]byte{0, 1, 2})

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		_, _, err := dec.ReadRecord()
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("UnexpectedEOF_TruncatedLengthHeader", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		buf.WriteByte(1)

		hashR := crc32.NewIEEE()
		dec := NewDecoder(&buf, hashR)
		_, _, err := dec.ReadRecord()
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}

func TestDecoder_ChecksumIntegrity(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	hashW := crc32.NewIEEE()
	enc := NewEncoder(&buf, hashW)

	domain := "tamper.example.com"
	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}},
	}

	require.NoError(t, enc.WriteRecord(domain, records))
	require.NoError(t, enc.Flush())
	originalChecksum := hashW.Sum32()

	rawBytes := buf.Bytes()
	rawBytes[len(rawBytes)-1] ^= 0xFF

	tamperedReader := bytes.NewReader(rawBytes)
	hashR := crc32.NewIEEE()
	dec := NewDecoder(tamperedReader, hashR)

	readDomain, readRecords, err := dec.ReadRecord()
	require.NoError(t, err)
	assert.Equal(t, domain, readDomain)
	assert.NotEqual(t, records[0].RData[0], readRecords[0].RData[0])

	assert.NotEqual(t, originalChecksum, hashR.Sum32())
}

func TestEncoderDecoder_ResetAndReuse(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	hashW := crc32.NewIEEE()
	enc := NewEncoder(&buf, hashW)

	hashR := crc32.NewIEEE()
	dec := NewDecoder(&buf, hashR)

	records := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.2.3.4")}},
	}

	for i := range 5 {
		buf.Reset()
		hashW.Reset()
		enc.Reset(&buf, hashW)

		domain := strings.Repeat("sub.", i+1) + "example.com"
		require.NoError(t, enc.WriteRecord(domain, records))
		require.NoError(t, enc.Flush())

		hashR.Reset()
		dec.Reset(&buf, hashR)

		readDomain, readRecords, err := dec.ReadRecord()
		require.NoError(t, err)
		assert.Equal(t, domain, readDomain)
		assert.Equal(t, records, readRecords)
		assert.Equal(t, hashW.Sum32(), hashR.Sum32())
	}
}

func TestDecoder_OOM_Protection(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Code panicked (OOM or Overflow) instead of returning an error: %v", r)
		}
	}()
	rdata := make([][]byte, 4096)
	for i := range 4096 {
		rdata[i] = make([]byte, 65535)
	}
	records := make(dns.RRSets, 4096)
	for i := range 4096 {
		records[i] = dns.RRSet{Type: dns.TypeTXT, RData: rdata}
	}

	var buf bytes.Buffer
	enc := NewEncoder(&buf, nil)
	err := enc.WriteRecord("example.com", records)
	if err == nil {
		t.Fatal("Expected error for payload exceeding size limits, got nil")
	}
}
