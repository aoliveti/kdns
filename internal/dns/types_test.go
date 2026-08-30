// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"iter"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestType_StringAndParse(t *testing.T) {
	t.Parallel()

	types := []struct {
		str   string
		qType Type
	}{
		{qType: TypeA, str: "A"},
		{qType: TypeAAAA, str: "AAAA"},
		{qType: TypeCNAME, str: "CNAME"},
		{qType: TypeTXT, str: "TXT"},
		{qType: TypeMX, str: "MX"},
		{qType: TypeNS, str: "NS"},
		{qType: TypeSOA, str: "SOA"},
		{qType: TypePTR, str: "PTR"},
		{qType: TypeSRV, str: "SRV"},
		{qType: TypeCAA, str: "CAA"},
		{qType: TypeDNSKEY, str: "DNSKEY"},
		{qType: TypeDS, str: "DS"},
		{qType: TypeRRSIG, str: "RRSIG"},
		{qType: TypeNSEC, str: "NSEC"},
		{qType: TypeNSEC3, str: "NSEC3"},
		{qType: TypeZONEMD, str: "ZONEMD"},
		{qType: TypeTSIG, str: "TSIG"},
		{qType: TypeANY, str: "ANY"},
		{qType: TypeOPT, str: "OPT"},
	}

	for _, tt := range types {
		t.Run(tt.str, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.str, tt.qType.String())
			parsed, err := ParseType(tt.str)
			require.NoError(t, err)
			assert.Equal(t, tt.qType, parsed)
		})
	}

	t.Run("CustomTypes", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "TYPE999", Type(999).String())
		parsed, err := ParseType("TYPE999")
		require.NoError(t, err)
		assert.Equal(t, Type(999), parsed)

		numericParsed, err := ParseType("999")
		require.NoError(t, err)
		assert.Equal(t, Type(999), numericParsed)
	})

	t.Run("InvalidType", func(t *testing.T) {
		t.Parallel()

		_, err := ParseType("INVALID_TYPE_NAME")
		require.ErrorIs(t, err, ErrUnknownType)
	})
}

func TestClass_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		want  string
		class Class
	}{
		{"IN", ClassIN},
		{"CH", ClassCH},
		{"NONE", ClassNONE},
		{"ANY", ClassANY},
		{"CLASS999", Class(999)},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.class.String())
		})
	}
}

func TestRCode_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		want  string
		rCode RCode
	}{
		{"NOERROR", RCodeSuccess},
		{"FORMERR", RCodeFormatError},
		{"SERVFAIL", RCodeServerFailure},
		{"NXDOMAIN", RCodeNameError},
		{"NOTIMP", RCodeNotImplemented},
		{"REFUSED", RCodeRefused},
		{"YXDOMAIN", RCodeYXDomain},
		{"YXRRSET", RCodeYXRRSet},
		{"NXRRSET", RCodeNXRRSet},
		{"NOTAUTH", RCodeNotAuth},
		{"NOTZONE", RCodeNotZone},
		{"RCODE99", RCode(99)},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.rCode.String())
		})
	}
}

func TestOpcode_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		want   string
		opcode Opcode
	}{
		{"QUERY", OpcodeQuery},
		{"IQUERY", OpcodeIQuery},
		{"STATUS", OpcodeStatus},
		{"NOTIFY", OpcodeNotify},
		{"UPDATE", OpcodeUpdate},
		{"OTHER", Opcode(99)},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.opcode.String())
		})
	}
}

func TestHeader_Flags(t *testing.T) {
	t.Parallel()

	t.Run("OpcodeExtraction", func(t *testing.T) {
		t.Parallel()

		h := Header{Flags: 0x0000} // Opcode 0 (QUERY)
		assert.Equal(t, OpcodeQuery, h.Opcode())

		hNotify := Header{Flags: 0x2000} // Opcode 4 (NOTIFY)
		assert.Equal(t, OpcodeNotify, hNotify.Opcode())
	})

	t.Run("IsResponse", func(t *testing.T) {
		t.Parallel()

		queryHeader := Header{Flags: 0x0100} // QR=0 (RD=1)
		assert.False(t, queryHeader.IsResponse())

		respHeader := Header{Flags: 0x8180} // QR=1, RD=1, RA=1
		assert.True(t, respHeader.IsResponse())
	})
}

func TestRRSet_Helpers(t *testing.T) {
	t.Parallel()

	t.Run("HasRecords", func(t *testing.T) {
		t.Parallel()

		empty := RRSet{Type: TypeA, Class: ClassIN, TTL: 300, RData: nil}
		assert.False(t, empty.HasRecords())

		emptySlice := RRSet{Type: TypeA, Class: ClassIN, TTL: 300, RData: [][]byte{}}
		assert.False(t, emptySlice.HasRecords())

		populated := RRSet{Type: TypeA, Class: ClassIN, TTL: 300, RData: [][]byte{{192, 0, 2, 1}}}
		assert.True(t, populated.HasRecords())
	})
}

func TestRRSets_GetAndClone(t *testing.T) {
	t.Parallel()

	t.Run("NilAndEmptySlice", func(t *testing.T) {
		t.Parallel()

		assert.Nil(t, RRSets(nil).Clone())
		assert.Equal(t, RRSets{}, RRSets{}.Clone())

		_, okNil := RRSets(nil).Get(TypeA)
		assert.False(t, okNil)

		_, okEmpty := RRSets{}.Get(TypeA)
		assert.False(t, okEmpty)
	})

	t.Run("GetMatchingAndMissing", func(t *testing.T) {
		t.Parallel()

		rr := RRSets{
			{Type: TypeA, Class: ClassIN, TTL: 300, RData: [][]byte{{192, 0, 2, 1}}},
			{Type: TypeTXT, Class: ClassIN, TTL: 300, RData: [][]byte{[]byte("test")}},
		}

		setA, ok := rr.Get(TypeA)
		assert.True(t, ok)
		assert.Equal(t, TypeA, setA.Type)

		setAAAA, ok := rr.Get(TypeAAAA)
		assert.False(t, ok)
		assert.Zero(t, setAAAA)
	})

	t.Run("MemoryIsolationOnClone", func(t *testing.T) {
		t.Parallel()

		original := RRSets{
			{
				Type:  TypeA,
				Class: ClassIN,
				TTL:   300,
				RData: [][]byte{{192, 168, 1, 1}},
			},
		}

		cloned := original.Clone()
		require.Equal(t, original, cloned)

		// Mutate original byte slice
		original[0].RData[0][0] = 0xFF
		original[0].RData = append(original[0].RData, []byte{10, 0, 0, 1})

		// Clone must remain unchanged
		assert.Equal(t, byte(192), cloned[0].RData[0][0])
		assert.Len(t, cloned[0].RData, 1)
	})
}

func TestResult_Helpers(t *testing.T) {
	t.Parallel()

	res := Result{
		RCode:      RCodeSuccess,
		Answer:     RRSet{Type: TypeA, RData: [][]byte{{1, 2, 3, 4}}},
		Authority:  RRSet{Type: TypeSOA, RData: [][]byte{[]byte("soa")}},
		Additional: RRSet{Type: TypeTXT, RData: [][]byte{[]byte("extra")}},
	}

	assert.True(t, res.HasAnswer())
	assert.True(t, res.HasAuthority())
	assert.True(t, res.HasAdditional())

	emptyRes := Result{RCode: RCodeNameError}
	assert.False(t, emptyRes.HasAnswer())
	assert.False(t, emptyRes.HasAuthority())
	assert.False(t, emptyRes.HasAdditional())
}

func TestTSIGErrorConstants_Values(t *testing.T) {
	t.Parallel()

	assert.Equal(t, uint16(16), TSIGErrBadSig)
	assert.Equal(t, uint16(17), TSIGErrBadKey)
	assert.Equal(t, uint16(18), TSIGErrBadTime)
	assert.Equal(t, uint16(19), TSIGErrBadMode)
	assert.Equal(t, uint16(20), TSIGErrBadName)
	assert.Equal(t, uint16(21), TSIGErrBadAlg)
	assert.Equal(t, uint16(22), TSIGErrBadTrunc)
}

type mockViewer struct{}

func (m mockViewer) Get(string) (RRSets, bool)             { return nil, true }
func (m mockViewer) Seek(string) iter.Seq2[string, RRSets] { return func(func(string, RRSets) bool) {} }
func (m mockViewer) Walk() iter.Seq2[string, RRSets]       { return func(func(string, RRSets) bool) {} }
func (m mockViewer) Search(string) iter.Seq2[string, RRSets] {
	return func(func(string, RRSets) bool) {}
}

type mockUpserter struct{}

func (m mockUpserter) Upsert(string, RRSets) error { return nil }

type mockDeleter struct{}

func (m mockDeleter) DeleteDomain(string) error { return nil }

type mockUpsertDeleter struct {
	mockUpserter
	mockDeleter
}

func TestInterfaces_Compliance(t *testing.T) {
	t.Parallel()

	var _ Getter = mockViewer{}
	var _ Seeker = mockViewer{}
	var _ Walker = mockViewer{}
	var _ Searcher = mockViewer{}
	var _ Viewer = mockViewer{}

	var _ Upserter = mockUpserter{}
	var _ Deleter = mockDeleter{}
	var _ UpsertDeleter = mockUpsertDeleter{}

	assert.NotNil(t, mockViewer{})
	assert.NotNil(t, mockUpsertDeleter{})
}
