// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackAndUnpackRData_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		qType Type
	}{
		{name: "A", qType: TypeA, input: "192.0.2.1"},
		{name: "AAAA", qType: TypeAAAA, input: "2001:db8::1"},
		{name: "CNAME", qType: TypeCNAME, input: "target.example.com."},
		{name: "NS", qType: TypeNS, input: "ns1.example.com."},
		{name: "PTR", qType: TypePTR, input: "ptr.example.com."},
		{name: "TXT", qType: TypeTXT, input: "v=spf1 -all"},
		{name: "MX", qType: TypeMX, input: "10 mail.example.com."},
		{name: "SRV", qType: TypeSRV, input: "10 60 5060 sip.example.com."},
		{name: "SOA", qType: TypeSOA, input: "ns1.example.com. admin.example.com. 2026081201 7200 3600 1209600 3600"},
		{name: "CAA", qType: TypeCAA, input: `0 issue "letsencrypt.org"`},
		{name: "DS", qType: TypeDS, input: "60999 8 2 2BB1832F"},
		{name: "DNSKEY", qType: TypeDNSKEY, input: "256 3 8 AwEAAag="},
		{name: "RRSIG", qType: TypeRRSIG, input: "A 8 2 300 20260901000000 20260801000000 60999 example.com. AwEAAag="},
		{name: "NSEC", qType: TypeNSEC, input: "next.example.com. A AAAA RRSIG NSEC"},
		{name: "NSEC3", qType: TypeNSEC3, input: "1 0 10 AABBCCDD 09BE1F9856A15F431C8B9A2E12345678 A AAAA RRSIG NSEC3"},
		{name: "ZONEMD", qType: TypeZONEMD, input: "2026081201 1 1 09BE1F9856A15F431C8B9A2E12345678"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wire, err := PackRData(tt.qType, tt.input)
			require.NoError(t, err)

			formatted, err := UnpackRData(tt.qType, wire)
			require.NoError(t, err)

			assert.NotEmpty(t, formatted)
		})
	}
}

func TestWriteRData_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expectedErr error
		name        string
		rdata       string
		qType       Type
	}{
		{
			name:        "InvalidIPv4",
			qType:       TypeA,
			rdata:       "999.999.999.999",
			expectedErr: ErrInvalidIPAddress,
		},
		{
			name:        "InvalidIPv6",
			qType:       TypeAAAA,
			rdata:       "2001:xyz::1",
			expectedErr: ErrInvalidIPAddress,
		},
		{
			name:        "InvalidSOAFieldsCount",
			qType:       TypeSOA,
			rdata:       "ns1.com admin.com 1 2 3",
			expectedErr: ErrInvalidRData,
		},
		{
			name:        "InvalidDNSKEYFieldsCount",
			qType:       TypeDNSKEY,
			rdata:       "256 3",
			expectedErr: ErrInvalidRData,
		},
		{
			name:        "InvalidDSFieldsCount",
			qType:       TypeDS,
			rdata:       "60999 8",
			expectedErr: ErrInvalidRData,
		},
		{
			name:        "InvalidRRSIGFieldsCount",
			qType:       TypeRRSIG,
			rdata:       "A 8 2",
			expectedErr: ErrInvalidRData,
		},
		{
			name:        "InvalidNSECFieldsCount",
			qType:       TypeNSEC,
			rdata:       "onlyonefield",
			expectedErr: ErrInvalidRData,
		},
		{
			name:        "InvalidNSEC3FieldsCount",
			qType:       TypeNSEC3,
			rdata:       "1 0 10",
			expectedErr: ErrInvalidRData,
		},
		{
			name:        "InvalidZONEMDFieldsCount",
			qType:       TypeZONEMD,
			rdata:       "2026081201 1",
			expectedErr: ErrInvalidRData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := PackRData(tt.qType, tt.rdata)
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestUnpackRData_Malformed(t *testing.T) {
	t.Parallel()

	t.Run("ShortA", func(t *testing.T) {
		t.Parallel()

		_, err := UnpackRData(TypeA, []byte{1, 2, 3})
		assert.ErrorIs(t, err, ErrInvalidRData)
	})

	t.Run("ShortAAAA", func(t *testing.T) {
		t.Parallel()

		_, err := UnpackRData(TypeAAAA, make([]byte, 10))
		assert.ErrorIs(t, err, ErrInvalidRData)
	})

	t.Run("ShortMX", func(t *testing.T) {
		t.Parallel()

		_, err := UnpackRData(TypeMX, []byte{0x00})
		assert.ErrorIs(t, err, ErrInvalidRData)
	})

	t.Run("ShortSRV", func(t *testing.T) {
		t.Parallel()

		_, err := UnpackRData(TypeSRV, make([]byte, 5))
		assert.ErrorIs(t, err, ErrInvalidRData)
	})

	t.Run("ShortCAA", func(t *testing.T) {
		t.Parallel()

		_, err := UnpackRData(TypeCAA, []byte{0x00})
		assert.ErrorIs(t, err, ErrInvalidRData)
	})

	t.Run("ShortDS", func(t *testing.T) {
		t.Parallel()

		_, err := UnpackRData(TypeDS, []byte{0x00, 0x01})
		assert.ErrorIs(t, err, ErrInvalidRData)
	})

	t.Run("ShortDNSKEY", func(t *testing.T) {
		t.Parallel()

		_, err := UnpackRData(TypeDNSKEY, []byte{0x00, 0x01})
		assert.ErrorIs(t, err, ErrInvalidRData)
	})

	t.Run("ShortRRSIG", func(t *testing.T) {
		t.Parallel()

		_, err := UnpackRData(TypeRRSIG, make([]byte, 10))
		assert.ErrorIs(t, err, ErrInvalidRData)
	})

	t.Run("ShortZONEMD", func(t *testing.T) {
		t.Parallel()

		_, err := UnpackRData(TypeZONEMD, []byte{0x00, 0x01})
		assert.ErrorIs(t, err, ErrInvalidRData)
	})
}

func TestEncodeTypeBitMaps_MultipleWindowBlocks(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 128)
	n, err := encodeTypeBitMaps(buf, 0, []string{"A", "CAA"})
	if err != nil {
		t.Fatal(err)
	}
	encoded := buf[:n]
	// Block 0 should exist for A (TypeA=1)
	if !bytes.Contains(encoded, []byte{0, 1, 0x40}) {
		t.Fatalf("Missing window block 0 in bitmap: %x", encoded)
	}
}

func TestWriteRDataCAA_SpacesInValue(t *testing.T) {
	t.Parallel()

	w := &packetWriter{buf: make([]byte, 128)}
	err := writeRDataCAA(w, `0 issue "letsencrypt.org; validationmethods=dns-01"`)
	if err != nil {
		t.Fatal(err)
	}
	rdata := w.buf[:w.offset]
	if !strings.Contains(string(rdata), "validationmethods=dns-01") {
		t.Fatalf("CAA value was truncated: %s", rdata)
	}
}
