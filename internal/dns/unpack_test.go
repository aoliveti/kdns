// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validQuery returns a raw byte slice representing a standard DNS query for google.com (Type A, Class IN).
func validQuery() []byte {
	return []byte{
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
		0x03, 0x63, 0x6f, 0x6d,
		0x00,
		0x00, 0x01,
		0x00, 0x01,
	}
}

func TestMessage_Unpack(t *testing.T) {
	t.Parallel()

	tests := []struct {
		validate func(t *testing.T, m *Message)
		payload  func() []byte
		name     string
	}{
		{
			name:    "RFC1035_StandardQuery",
			payload: validQuery,
			validate: func(t *testing.T, m *Message) {
				assert.Equal(t, uint16(0x1234), m.Header.ID)
				assert.Equal(t, uint16(1), m.Header.QDCount)
				require.Len(t, m.Questions, 1)
				assert.Equal(t, "google.com", m.Questions[0].Name)
				assert.Equal(t, TypeA, m.Questions[0].Type)
				assert.Equal(t, ClassIN, m.Questions[0].Class)
			},
		},
		{
			name: "RFC1035_CasePreservationInQuestion",
			payload: func() []byte {
				return []byte{
					0x12, 0x34,
					0x01, 0x00,
					0x00, 0x01,
					0x00, 0x00,
					0x00, 0x00,
					0x00, 0x00,
					0x06, 'G', 'o', 'O', 'g', 'L', 'e',
					0x03, 'c', 'O', 'm',
					0x00,
					0x00, 0x01,
					0x00, 0x01,
				}
			},
			validate: func(t *testing.T, m *Message) {
				require.Len(t, m.Questions, 1)
				assert.Equal(t, "GoOgLe.cOm", m.Questions[0].Name)
			},
		},
		{
			name: "RFC1035_MultipleQuestions",
			payload: func() []byte {
				return []byte{
					0xab, 0xcd,
					0x01, 0x00,
					0x00, 0x02,
					0x00, 0x00,
					0x00, 0x00,
					0x00, 0x00,
					0x01, 0x61, 0x03, 0x63, 0x6f, 0x6d, 0x00,
					0x00, 0x01,
					0x00, 0x01,
					0x01, 0x62, 0x03, 0x63, 0x6f, 0x6d, 0x00,
					0x00, 0x10,
					0x00, 0x01,
				}
			},
			validate: func(t *testing.T, m *Message) {
				require.Len(t, m.Questions, 2)
				assert.Equal(t, "a.com", m.Questions[0].Name)
				assert.Equal(t, TypeA, m.Questions[0].Type)
				assert.Equal(t, "b.com", m.Questions[1].Name)
				assert.Equal(t, TypeTXT, m.Questions[1].Type)
			},
		},
		{
			name: "RFC1035_SkipAnswerAndAuthorityBeforeEDNS0",
			payload: func() []byte {
				// Packet with QDCount=1, ANCount=1, NSCount=1, ARCount=1 (OPT)
				payload := make([]byte, 12)
				binary.BigEndian.PutUint16(payload[0:2], 0x4321)
				binary.BigEndian.PutUint16(payload[2:4], 0x0100)
				binary.BigEndian.PutUint16(payload[4:6], 1)   // QDCount
				binary.BigEndian.PutUint16(payload[6:8], 1)   // ANCount
				binary.BigEndian.PutUint16(payload[8:10], 1)  // NSCount
				binary.BigEndian.PutUint16(payload[10:12], 1) // ARCount

				// Question: example.com A IN
				payload = append(payload, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
				payload = append(payload, []byte{0x00, 0x01, 0x00, 0x01}...)

				// Answer record (A record with 4 bytes IPv4)
				payload = append(payload, []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 192, 0, 2, 1}...)

				// Authority record (NS record with 5 bytes domain)
				payload = append(payload, []byte{0xC0, 0x0C, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x05, 3, 'n', 's', '1', 0}...)

				// Additional section: EDNS0 OPT record
				payload = append(payload, []byte{0x00, 0x00, 41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
				return payload
			},
			validate: func(t *testing.T, m *Message) {
				require.Len(t, m.Questions, 1)
				assert.Equal(t, "example.com", m.Questions[0].Name)
				assert.Equal(t, 4096, m.EDNS0Size)
				assert.False(t, m.DO)
				assert.Equal(t, uint8(0), m.ExtRCode)
			},
		},
		{
			name: "RFC6891_EDNS0_OPT_Extraction",
			payload: func() []byte {
				payload := make([]byte, 12)
				binary.BigEndian.PutUint16(payload[0:2], 0x1234)
				binary.BigEndian.PutUint16(payload[2:4], 0x0100)
				binary.BigEndian.PutUint16(payload[4:6], 1)
				binary.BigEndian.PutUint16(payload[6:8], 1)
				binary.BigEndian.PutUint16(payload[10:12], 1)
				payload = append(payload, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
				payload = append(payload, []byte{0x00, 0x01, 0x00, 0x01}...)
				payload = append(payload, []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 1, 2, 3, 4}...)
				payload = append(payload, []byte{0x00, 0x00, 41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
				return payload
			},
			validate: func(t *testing.T, m *Message) {
				require.Len(t, m.Questions, 1)
				assert.Equal(t, "example.com", m.Questions[0].Name)
				assert.Equal(t, 4096, m.EDNS0Size)
				assert.False(t, m.DO)
				assert.Equal(t, uint8(0), m.ExtRCode)
				assert.Equal(t, uint16(0), m.FullRCode())
			},
		},
		{
			name: "RFC6891_EDNS0_DO_Bit_And_ExtRCode",
			payload: func() []byte {
				payload := make([]byte, 12)
				binary.BigEndian.PutUint16(payload[0:2], 0x5678)
				binary.BigEndian.PutUint16(payload[2:4], 0x0103) // header RCode = 3 (NXDOMAIN)
				binary.BigEndian.PutUint16(payload[4:6], 1)
				binary.BigEndian.PutUint16(payload[10:12], 1)
				payload = append(payload, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
				payload = append(payload, []byte{0x00, 0x01, 0x00, 0x01}...)
				// OPT record: Name=0, Type=41, Class=4096 (0x1000), TTL=0x01 00 80 00 (ExtRCode=1, Version=0, DO bit=0x8000), RDLen=0
				payload = append(payload, []byte{0x00, 0x00, 41, 0x10, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00}...)
				return payload
			},
			validate: func(t *testing.T, m *Message) {
				require.Len(t, m.Questions, 1)
				assert.Equal(t, 4096, m.EDNS0Size)
				assert.True(t, m.DO)
				assert.Equal(t, uint8(1), m.ExtRCode)
				assert.Equal(t, uint16(0x13), m.FullRCode()) // (1<<4)|3 = 0x13 (19)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var m Message
			err := m.Unpack(tt.payload())
			require.NoError(t, err)
			tt.validate(t, &m)
		})
	}

	t.Run("StateResetOnZeroQDCount", func(t *testing.T) {
		t.Parallel()

		var m Message
		err := m.Unpack(validQuery())
		require.NoError(t, err)
		require.Len(t, m.Questions, 1)

		emptyPayload := make([]byte, 12)
		err = m.Unpack(emptyPayload)
		require.NoError(t, err)
		assert.Empty(t, m.Questions)
	})
}

func TestMessage_Unpack_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expectedErr error
		payload     func() []byte
		name        string
	}{
		{
			name: "RFC1035_PacketSmallerThanHeader",
			payload: func() []byte {
				return []byte{0x00, 0x01}
			},
			expectedErr: ErrPacketTooSmall,
		},
		{
			name: "RFC1035_OutOfBoundsPreventionInAnswer",
			payload: func() []byte {
				payload := make([]byte, 12)
				binary.BigEndian.PutUint16(payload[4:6], 1)
				binary.BigEndian.PutUint16(payload[6:8], 1)
				payload = append(payload, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}...)
				payload = append(payload, []byte{0x00, 0x01, 0x00, 0x01}...)
				payload = append(payload, []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04}...)
				return payload
			},
			expectedErr: ErrOutOfBounds,
		},
		{
			name: "RFC1035_ForwardPointerRejected",
			payload: func() []byte {
				return []byte{
					0x00, 0x00, 0xc0, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0xc0, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x04, 0x65, 0x76, 0x69, 0x6c, 0x00,
				}
			},
			expectedErr: ErrInvalidPointer,
		},
		{
			name: "RFC1035_SelfReferentialPointerRejected",
			payload: func() []byte {
				return []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
				}
			},
			expectedErr: ErrInvalidPointer,
		},
		{
			name: "RFC1035_OutOfBoundsStringRead",
			payload: func() []byte {
				return []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x14, 0x61, 0x62, 0x63,
				}
			},
			expectedErr: ErrOutOfBounds,
		},
		{
			name: "RFC1035_LabelExceeds63Bytes",
			payload: func() []byte {
				return append(
					[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40},
					make([]byte, 68)...,
				)
			},
			expectedErr: ErrLabelTooLong,
		},
		{
			name: "RFC1035_NameExceeds255Bytes",
			payload: func() []byte {
				p := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				for range 5 {
					p = append(p, 60)
					p = append(p, make([]byte, 60)...)
				}
				p = append(p, 0x00, 0x00, 0x01, 0x00, 0x01)
				return p
			},
			expectedErr: ErrNameTooLong,
		},
		{
			name: "Security_TooManyQuestionsMitigation",
			payload: func() []byte {
				return []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}
			},
			expectedErr: ErrTooManyQuestions,
		},
		{
			name: "RFC1035_MissingRootLabel",
			payload: func() []byte {
				return []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x01, 0x61,
				}
			},
			expectedErr: ErrOutOfBounds,
		},
		{
			name: "RFC1035_TruncatedPointer",
			payload: func() []byte {
				return []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0xc0,
				}
			},
			expectedErr: ErrOutOfBounds,
		},
		{
			name: "RFC1035_QuestionTruncatedBeforeType",
			payload: func() []byte {
				return []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x01, 0x61, 0x00, 0x00,
				}
			},
			expectedErr: ErrOutOfBounds,
		},
		{
			name: "RFC1035_TooManyPointerJumpsLoopDetected",
			payload: func() []byte {
				return []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x16,
					0xc0, 0x0b, 0xc0, 0x0d, 0xc0, 0x0f, 0xc0, 0x11, 0xc0, 0x13, 0xc0, 0x15,
					0xc0, 0x17, 0xc0, 0x19, 0xc0, 0x1b, 0xc0, 0x1d, 0xc0, 0x1f,
					0xc0, 0x21,
				}
			},
			expectedErr: ErrTooManyJumps,
		},
		{
			name: "RFC6891_DuplicateOPTRecordsRejected",
			payload: func() []byte {
				return []byte{
					0x55, 0xaa, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
					0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
					0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}
			},
			expectedErr: ErrMultipleOPT,
		},
		{
			name: "RFC6891_OPTInQuestionSectionRejected",
			payload: func() []byte {
				return []byte{
					0x12, 0x34, 0x01, 0x00,
					0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // QDCount = 1
					0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
					0x00, 41, 0x00, 0x01, // Type = 41 (OPT), Class = 1 (IN)
				}
			},
			expectedErr: ErrMisplacedOPT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var m Message
			err := m.Unpack(tt.payload())
			assert.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestUnpackDomainName(t *testing.T) {
	t.Parallel()

	payload := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0xFF, 0xFF}
	name, nextOffset, err := UnpackDomainName(payload, 0)
	require.NoError(t, err)
	assert.Equal(t, "example.com", name)
	assert.Equal(t, 13, nextOffset)
}
