// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteDomain_Boundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expectedErr error
		name        string
		domain      string
		bufSize     int
		offset      int
		expectedLen int
	}{
		{
			name:        "ValidNormalDomain",
			domain:      "example.com",
			bufSize:     512,
			offset:      0,
			expectedErr: nil,
			expectedLen: 13,
		},
		{
			name:        "RootDomain",
			domain:      ".",
			bufSize:     512,
			offset:      0,
			expectedErr: nil,
			expectedLen: 1,
		},
		{
			name:        "EmptyDomainTreatedAsRoot",
			domain:      "",
			bufSize:     512,
			offset:      0,
			expectedErr: nil,
			expectedLen: 1,
		},
		{
			name:        "NameTooLongRFC1035",
			domain:      string(make([]byte, 256)),
			bufSize:     512,
			offset:      0,
			expectedErr: ErrNameTooLong,
		},
		{
			name:        "LabelTooLongRFC1035",
			domain:      string(make([]byte, 64)) + ".com",
			bufSize:     512,
			offset:      0,
			expectedErr: ErrLabelTooLong,
		},
		{
			name:        "BufferTooSmallForRoot",
			domain:      ".",
			bufSize:     0,
			offset:      0,
			expectedErr: ErrBufferTooSmall,
		},
		{
			name:        "BufferTooSmallForLabel",
			domain:      "example.com",
			bufSize:     5,
			offset:      0,
			expectedErr: ErrBufferTooSmall,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buf := make([]byte, tt.bufSize)
			pw := packetWriter{buf: buf, offset: tt.offset}
			err := pw.writeUncompressedDomain(tt.domain)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedLen+tt.offset, pw.offset)
		})
	}
}

func TestPackResponse_Scenarios(t *testing.T) {
	t.Parallel()
	baseMsg := Message{
		Header:    Header{ID: 1234},
		Questions: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}},
	}
	rA1 := MustPackRData(TypeA, "192.168.1.1")
	rA2 := MustPackRData(TypeA, "192.168.1.2")
	multiRecord := RRSet{
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		RData: [][]byte{rA1, rA2},
	}

	tests := []struct {
		expectedErr error
		validate    func(t *testing.T, buf []byte, written int)
		name        string
		record      RRSet
		msg         Message
		maxSize     int
	}{
		{
			name:    "RFC1035_StandardSingleAnswer",
			msg:     baseMsg,
			record:  RRSet{Type: TypeA, Class: ClassIN, TTL: 300, RData: [][]byte{rA1}},
			maxSize: 512,
			validate: func(t *testing.T, buf []byte, written int) {
				assert.Greater(t, written, 0)
				assert.Equal(t, []byte{0x04, 0xD2}, buf[0:2])
				assert.Equal(t, uint8(pointerMask), buf[29])
				assert.Equal(t, uint8(0x0C), buf[30])
				assert.Equal(t, uint16(1), binary.BigEndian.Uint16(buf[6:8]))
			},
		},
		{
			name: "RFC6891_EDNS0_OPT_Attached",
			msg: Message{
				Header:    Header{ID: 1234},
				Questions: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}},
				EDNS0Size: 4096,
			},
			record:  RRSet{Type: TypeA, Class: ClassIN, TTL: 300, RData: [][]byte{rA1}},
			maxSize: 512,
			validate: func(t *testing.T, buf []byte, written int) {
				assert.Greater(t, written, 0)
				assert.Equal(t, uint16(1), binary.BigEndian.Uint16(buf[6:8]))
				assert.Equal(t, uint16(1), binary.BigEndian.Uint16(buf[10:12]))
			},
		},
		{
			name: "RFC6891_EDNS0_DO_Bit_Signaling",
			msg: Message{
				Header:    Header{ID: 1234},
				Questions: []Question{{Name: "example.com", Type: TypeA, Class: ClassIN}},
				EDNS0Size: 4096,
				DO:        true,
			},
			record:  RRSet{Type: TypeA, Class: ClassIN, TTL: 300, RData: [][]byte{rA1}},
			maxSize: 512,
			validate: func(t *testing.T, buf []byte, written int) {
				assert.Greater(t, written, 0)
				// OPT record starts after Answer (45): 1 byte root (45), 2 bytes Type (46-47), 2 bytes Class (48-49), 4 bytes TTL (50-53)
				// TTL carries ExtRCode (upper byte) + DO bit (0x8000 in lower 2 bytes)
				ednsFlags := binary.BigEndian.Uint16(buf[52:54])
				assert.NotZero(t, ednsFlags&0x8000, "DO bit (0x8000) must be set in OPT TTL")
			},
		},
		{
			name:    "RFC1035_FitsExactBoundaryWithoutTruncation",
			msg:     baseMsg,
			record:  multiRecord,
			maxSize: 61,
			validate: func(t *testing.T, buf []byte, written int) {
				assert.Equal(t, 61, written)
				assert.Equal(t, uint16(2), binary.BigEndian.Uint16(buf[6:8]))
				flags := binary.BigEndian.Uint16(buf[2:4])
				assert.Zero(t, flags&0x0200)
			},
		},
		{
			name:    "RFC1035_TruncationSetsTCBitOnOverflow",
			msg:     baseMsg,
			record:  multiRecord,
			maxSize: 60,
			validate: func(t *testing.T, buf []byte, written int) {
				assert.Equal(t, 45, written)
				assert.Equal(t, uint16(1), binary.BigEndian.Uint16(buf[6:8]))
				flags := binary.BigEndian.Uint16(buf[2:4])
				assert.NotZero(t, flags&0x0200)
			},
		},
		{
			name:    "RFC1035_TruncationAllRecordsOnSmallBuffer",
			msg:     baseMsg,
			record:  multiRecord,
			maxSize: 44,
			validate: func(t *testing.T, buf []byte, written int) {
				assert.Equal(t, 29, written)
				assert.Equal(t, uint16(0), binary.BigEndian.Uint16(buf[6:8]))
				flags := binary.BigEndian.Uint16(buf[2:4])
				assert.NotZero(t, flags&0x0200)
			},
		},
		{
			name:        "RFC1035_MaxSizeSmallerThanHeaderReturnsError",
			msg:         baseMsg,
			record:      multiRecord,
			maxSize:     11,
			expectedErr: ErrBufferTooSmall,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			buf := make([]byte, 512)
			res := Result{
				RCode:  RCodeSuccess,
				Answer: tt.record,
			}
			n, err := tt.msg.PackResponse(buf, res, tt.maxSize)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, buf, n)
			}
		})
	}
}

func TestPackResponse_SectionsAndCompression(t *testing.T) {
	t.Parallel()

	t.Run("RFC1035_AdditionalSectionEncoding", func(t *testing.T) {
		t.Parallel()

		msg := Message{
			Header:    Header{ID: 0x1234},
			Questions: []Question{{Name: "example.com", Type: TypeNS, Class: ClassIN}},
			EDNS0Size: 4096,
		}
		res := Result{
			RCode: RCodeSuccess,
			Answer: RRSet{
				Type:  TypeNS,
				Class: ClassIN,
				TTL:   300,
				RData: [][]byte{MustPackRData(TypeNS, "ns1.example.com.")},
			},
			Additional: RRSet{
				Type:  TypeA,
				Class: ClassIN,
				TTL:   300,
				RData: [][]byte{MustPackRData(TypeA, "192.0.2.1")},
			},
		}

		buf := make([]byte, 512)
		n, err := msg.PackResponse(buf, res, 512)
		require.NoError(t, err)
		assert.Greater(t, n, 0)
		assert.Equal(t, uint16(1), binary.BigEndian.Uint16(buf[6:8]))   // ANCount = 1
		assert.Equal(t, uint16(2), binary.BigEndian.Uint16(buf[10:12])) // ARCount = 2 (1 Additional A + 1 OPT)
	})

	t.Run("RFC2308_AuthoritySectionSOANegativeCache", func(t *testing.T) {
		t.Parallel()

		msg := Message{
			Header: Header{ID: 9999},
			Questions: []Question{
				{Name: "missing.example.com", Type: TypeA, Class: ClassIN},
			},
		}

		res := Result{
			RCode:         RCodeNameError,
			AuthorityName: "example.com",
			Authority: RRSet{
				Type:  TypeSOA,
				Class: ClassIN,
				TTL:   300,
				RData: [][]byte{MustPackRData(TypeSOA, "ns1.example.com admin.example.com 1 7200 3600 1209600 300")},
			},
		}

		buf := make([]byte, 512)
		n, err := msg.PackResponse(buf, res, 512)
		require.NoError(t, err)
		assert.Greater(t, n, 0)

		// Check RCODE is NXDOMAIN (3)
		flags := binary.BigEndian.Uint16(buf[2:4])
		assert.Equal(t, uint16(3), flags&0xF)

		// Check ANCOUNT is 0, NSCOUNT is 1
		anCount := binary.BigEndian.Uint16(buf[6:8])
		nsCount := binary.BigEndian.Uint16(buf[8:10])
		assert.Equal(t, uint16(0), anCount)
		assert.Equal(t, uint16(1), nsCount)
	})

	t.Run("RFC1035_PointerCompression", func(t *testing.T) {
		t.Parallel()

		msg := Message{
			Header:    Header{ID: 0x1234},
			Questions: []Question{{Name: "example.com", Type: TypeNS, Class: ClassIN}},
		}
		res := Result{
			RCode: RCodeSuccess,
			Answer: RRSet{
				Type:  TypeNS,
				Class: ClassIN,
				TTL:   300,
				RData: [][]byte{MustPackRData(TypeNS, "ns1.example.com.")},
			},
		}

		buf := make([]byte, 512)
		n, err := msg.PackResponse(buf, res, 512)
		require.NoError(t, err)

		// Answer owner name starts at offset 29: pointer 0xC00C (2 bytes)
		assert.Equal(t, uint8(0xC0), buf[29])
		assert.Equal(t, uint8(0x0C), buf[30])

		// NS RData starts at offset 41: \x03ns1\x07example\x03com\x00
		assert.Equal(t, uint8(3), buf[41])
		assert.Equal(t, "ns1", string(buf[42:45]))
		assert.Equal(t, uint8(7), buf[45])
		assert.Equal(t, "example", string(buf[46:53]))

		// Unpack to ensure full correctness
		var unpacked Message
		err = unpacked.Unpack(buf[:n])
		require.NoError(t, err)
		assert.Equal(t, "example.com", unpacked.Questions[0].Name)
	})
}

func TestDomainCompressor_CapacityBounds(t *testing.T) {
	t.Parallel()

	var comp domainCompressor
	// Insert 16 entries (maxCompressionOffsets = 16)
	for i := range 16 {
		comp.insert(fmt.Sprintf("node%d.example.com", i), 10+i*2)
	}
	assert.Equal(t, uint8(16), comp.count)

	// 17th insert must be safely dropped without panic
	comp.insert("overflow.example.com", 999)
	assert.Equal(t, uint8(16), comp.count)

	_, found := comp.lookup("overflow.example.com")
	assert.False(t, found)
}

func TestPackResponse_HeaderFlagsPreservation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		queryFlags uint16
		wantOPCODE uint16
		wantRCode  uint16
		rCode      RCode
		wantRD     bool
	}{
		{
			name:       "StandardQueryWithRD",
			queryFlags: 0x0100, // QR=0 (query), OPCODE=0 (QUERY), RD=1
			rCode:      RCodeSuccess,
			wantOPCODE: 0,
			wantRD:     true,
			wantRCode:  0,
		},
		{
			name:       "StandardQueryWithoutRD",
			queryFlags: 0x0000,
			rCode:      RCodeSuccess,
			wantOPCODE: 0,
			wantRD:     false,
			wantRCode:  0,
		},
		{
			name:       "IQUERYPreservesRD",
			queryFlags: 0x0900, // OPCODE=1 (IQUERY), RD=1
			rCode:      RCodeNotImplemented,
			wantOPCODE: 1,
			wantRD:     true,
			wantRCode:  4,
		},
		{
			name:       "UPDATEWithoutRD",
			queryFlags: 0x2800, // OPCODE=5 (UPDATE), RD=0
			rCode:      RCodeNotImplemented,
			wantOPCODE: 5,
			wantRD:     false,
			wantRCode:  4,
		},
		{
			name:       "NXDOMAINPreservesRD",
			queryFlags: 0x0100,
			rCode:      RCodeNameError,
			wantOPCODE: 0,
			wantRD:     true,
			wantRCode:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			msg := &Message{
				Header: Header{
					ID:    0xABCD,
					Flags: tt.queryFlags,
				},
				Questions: []Question{
					{Name: "example.com", Type: TypeA, Class: ClassIN},
				},
			}

			buf := make([]byte, 512)
			res := Result{RCode: tt.rCode}
			n, err := msg.PackResponse(buf, res, 512)
			require.NoError(t, err)
			require.Greater(t, n, 0)

			flags := binary.BigEndian.Uint16(buf[2:4])

			gotQR := (flags >> 15) & 0x1
			gotOPCODE := (flags >> 11) & 0xF
			gotAA := (flags >> 10) & 0x1
			gotRD := (flags >> 8) & 0x1
			gotRCode := flags & 0xF

			assert.Equal(t, uint16(1), gotQR, "QR must always be 1 in a response")
			assert.Equal(t, uint16(1), gotAA, "AA must always be 1 for an authoritative response")
			assert.Equal(t, tt.wantOPCODE, gotOPCODE, "OPCODE must be copied from the query")
			wantRD := uint16(0)
			if tt.wantRD {
				wantRD = 1
			}
			assert.Equal(t, wantRD, gotRD, "RD bit must match query expectation")
			assert.Equal(t, tt.wantRCode, gotRCode, "RCODE must match the provided argument")
		})
	}
}

func TestMaxPayloadSize_Scenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		transportSize int
		edns0Size     int
		want          int
	}{
		{name: "UDP_WithoutEDNS0_DefaultsTo512", transportSize: MaxUDPSize, edns0Size: 0, want: MaxUDPSize},
		{name: "UDP_WithStandardEDNS0_4096_CappedTo1232", transportSize: MaxUDPSize, edns0Size: 4096, want: MaxEDNS0Size},
		{name: "UDP_WithEDNS0_1024_Honors1024", transportSize: MaxUDPSize, edns0Size: 1024, want: 1024},
		{name: "UDP_WithEDNS0_512_Remains512", transportSize: MaxUDPSize, edns0Size: 512, want: MaxUDPSize},
		{name: "TCP_IgnoresEDNS0Size", transportSize: MaxTCPSize, edns0Size: 4096, want: MaxTCPSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, MaxPayloadSize(tt.transportSize, tt.edns0Size))
		})
	}
}

func TestTruncateToSlip_Behavior(t *testing.T) {
	t.Parallel()

	t.Run("BCP140_TruncatesToQuestionAndSetsTC", func(t *testing.T) {
		t.Parallel()

		msg := Message{
			Header: Header{ID: 0x1234},
			Questions: []Question{
				{Name: "example.com", Type: TypeA, Class: ClassIN},
			},
		}

		res := Result{
			RCode: RCodeSuccess,
			Answer: RRSet{
				Type:  TypeA,
				Class: ClassIN,
				TTL:   300,
				RData: [][]byte{MustPackRData(TypeA, "93.184.216.34")},
			},
		}

		buf := make([]byte, 512)
		written, err := msg.PackResponse(buf, res, 512)
		require.NoError(t, err)
		require.Greater(t, written, 12)

		slipLen := TruncateToSlip(buf, written)
		assert.Less(t, slipLen, written)

		// TC bit should be set
		flags := binary.BigEndian.Uint16(buf[2:4])
		assert.NotZero(t, flags&0x0200)

		// ANCOUNT, NSCOUNT, ARCOUNT must be 0
		assert.Equal(t, uint16(0), binary.BigEndian.Uint16(buf[6:8]))
		assert.Equal(t, uint16(0), binary.BigEndian.Uint16(buf[8:10]))
		assert.Equal(t, uint16(0), binary.BigEndian.Uint16(buf[10:12]))

		// QDCOUNT must be 1
		assert.Equal(t, uint16(1), binary.BigEndian.Uint16(buf[4:6]))
	})

	t.Run("ShortBufferSafety", func(t *testing.T) {
		t.Parallel()

		shortBuf := make([]byte, 8)
		assert.Equal(t, 8, TruncateToSlip(shortBuf, 8))
	})
}
