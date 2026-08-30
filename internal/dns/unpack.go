// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"encoding/binary"
	"errors"
)

const (
	// MaxLabelLen defines the maximum length of a single DNS label in bytes (RFC 1035 §2.3.4).
	MaxLabelLen = 63

	// MaxNameLen defines the maximum length of a full uncompressed domain name in wire format (RFC 1035 §2.3.4).
	MaxNameLen = 255

	// headerSize defines the fixed byte length of a standard DNS message header (RFC 1035 §4.1.1).
	headerSize = 12

	// maxJumps limits the maximum number of compression pointer redirects to prevent infinite loops (RFC 1035 §4.1.4).
	maxJumps = 10

	// maxQuestions sets a strict bound on the question section size to prevent DoS resource exhaustion.
	maxQuestions = 10

	// pointerMask checks the top two bits of a length octet to identify a compression pointer (0xC0).
	pointerMask = 0xC0

	// pointerOffsetMask isolates the lower 14 bits of a 16-bit compression pointer offset (0x3FFF).
	pointerOffsetMask = 0x3FFF
)

var (
	// ErrPacketTooSmall indicates that the payload buffer is smaller than the required 12-byte header.
	ErrPacketTooSmall = errors.New("dns: packet too small to contain a valid header")

	// ErrInvalidPointer indicates a malformed or forward-pointing RFC 1035 compression pointer.
	ErrInvalidPointer = errors.New("dns: invalid compression pointer")

	// ErrTooManyJumps indicates excessive compression pointer redirections exceeding safety bounds.
	ErrTooManyJumps = errors.New("dns: too many compression pointer jumps")

	// ErrOutOfBounds indicates an attempt to read past the allocated payload boundaries.
	ErrOutOfBounds = errors.New("dns: read out of bounds")

	// ErrTooManyQuestions indicates that QDCount exceeds the maximum allowed threshold.
	ErrTooManyQuestions = errors.New("dns: excessive number of questions")

	// ErrLabelTooLong indicates a domain label exceeding the RFC 1035 63-byte limit.
	ErrLabelTooLong = errors.New("dns: label length exceeds RFC limit of 63 bytes")

	// ErrNameTooLong indicates a domain name exceeding the RFC 1035 255-byte limit.
	ErrNameTooLong = errors.New("dns: total domain name length exceeds RFC limit of 255 bytes")

	// ErrMultipleOPT indicates the presence of duplicate OPT pseudo-records in violation of RFC 6891 §6.1.1.
	ErrMultipleOPT = errors.New("dns: multiple OPT pseudo-records in message")

	// ErrMisplacedOPT indicates an OPT record appeared outside the Additional section (RFC 6891).
	ErrMisplacedOPT = errors.New("dns: OPT record MUST NOT appear in question section")
)

// Message represents a parsed DNS query or response packet in compliance with RFC 1035 and RFC 6891.
type Message struct {
	Questions []Question
	EDNS0Size int
	Header    Header
	DO        bool
	ExtRCode  uint8
}

// FullRCode combines the upper 8 bits from EDNS0 ExtRCode and lower 4 bits from Header flags
// to reconstruct the full 12-bit extended response code (RFC 6891 §6.1.3).
func (m *Message) FullRCode() uint16 {
	return (uint16(m.ExtRCode) << 4) | (m.Header.Flags & 0x0F)
}

// Unpack parses a raw DNS wire format payload into the Message struct.
func (m *Message) Unpack(payload []byte) error {
	reader, err := newPacketReader(payload)
	if err != nil {
		return err
	}

	m.Header = reader.decodeHeader()

	if m.Header.QDCount > maxQuestions {
		return ErrTooManyQuestions
	}

	m.Questions = m.Questions[:0]
	if cap(m.Questions) < int(m.Header.QDCount) {
		m.Questions = make([]Question, 0, m.Header.QDCount)
	}

	for i := uint16(0); i < m.Header.QDCount; i++ {
		question, err := reader.decodeQuestion()
		if err != nil {
			return err
		}
		m.Questions = append(m.Questions, question)
	}

	recordsToSkip := int(m.Header.ANCount) + int(m.Header.NSCount)
	for range recordsToSkip {
		if err := reader.skipRecord(); err != nil {
			return err
		}
	}

	var ednsErr error
	m.EDNS0Size, m.DO, m.ExtRCode, ednsErr = reader.decodeEDNS0(m.Header.ARCount)
	if ednsErr != nil {
		return ednsErr
	}

	return nil
}

type packetReader struct {
	payload []byte
	offset  int
}

func newPacketReader(payload []byte) (packetReader, error) {
	if len(payload) < headerSize {
		return packetReader{}, ErrPacketTooSmall
	}
	return packetReader{
		payload: payload,
		offset:  0,
	}, nil
}

func (r *packetReader) decodeHeader() Header {
	h := Header{
		ID:      binary.BigEndian.Uint16(r.payload[0:2]),
		Flags:   binary.BigEndian.Uint16(r.payload[2:4]),
		QDCount: binary.BigEndian.Uint16(r.payload[4:6]),
		ANCount: binary.BigEndian.Uint16(r.payload[6:8]),
		NSCount: binary.BigEndian.Uint16(r.payload[8:10]),
		ARCount: binary.BigEndian.Uint16(r.payload[10:12]),
	}
	r.offset = headerSize
	return h
}

func (r *packetReader) decodeQuestion() (Question, error) {
	name, err := r.decodeDomainName()
	if err != nil {
		return Question{}, err
	}

	if r.offset+4 > len(r.payload) {
		return Question{}, ErrOutOfBounds
	}

	qType := binary.BigEndian.Uint16(r.payload[r.offset : r.offset+2])

	if Type(qType) == TypeOPT {
		return Question{}, ErrMisplacedOPT
	}

	class := binary.BigEndian.Uint16(r.payload[r.offset+2 : r.offset+4])
	r.offset += 4

	return Question{
		Name:  name,
		Type:  Type(qType),
		Class: Class(class),
	}, nil
}

func (r *packetReader) skipRecord() error {
	if _, err := r.decodeDomainName(); err != nil {
		return err
	}
	if r.offset+10 > len(r.payload) {
		return ErrOutOfBounds
	}
	rdLen := int(binary.BigEndian.Uint16(r.payload[r.offset+8 : r.offset+10]))
	r.offset += 10 + rdLen
	if r.offset > len(r.payload) {
		return ErrOutOfBounds
	}
	return nil
}

func (r *packetReader) decodeEDNS0(additionalCount uint16) (int, bool, uint8, error) {
	var (
		foundOPT bool
		ednsSize int
		do       bool
		extRCode uint8
	)

	for range int(additionalCount) {
		if _, err := r.decodeDomainName(); err != nil {
			return 0, false, 0, err
		}

		if r.offset+10 > len(r.payload) {
			return 0, false, 0, ErrOutOfBounds
		}

		qType := binary.BigEndian.Uint16(r.payload[r.offset : r.offset+2])
		qClass := binary.BigEndian.Uint16(r.payload[r.offset+2 : r.offset+4])
		rdLen := int(binary.BigEndian.Uint16(r.payload[r.offset+8 : r.offset+10]))

		if Type(qType) == TypeOPT {
			if foundOPT {
				return 0, false, 0, ErrMultipleOPT
			}
			foundOPT = true
			ednsSize = int(qClass) // In OPT records, CLASS field carries UDP payload size (RFC 6891 §6.1.2)
			extRCode = r.payload[r.offset+4]
			ednsFlags := binary.BigEndian.Uint16(r.payload[r.offset+6 : r.offset+8])
			do = (ednsFlags & 0x8000) != 0 // Bit 15 is DO (DNSSEC OK, RFC 3225 / RFC 6891)
		}

		r.offset += 10 + rdLen
		if r.offset > len(r.payload) {
			return 0, false, 0, ErrOutOfBounds
		}
	}
	return ednsSize, do, extRCode, nil
}

func (r *packetReader) decodeDomainName() (string, error) {
	name, nextOffset, err := UnpackDomainName(r.payload, r.offset)
	if err != nil {
		return "", err
	}
	r.offset = nextOffset
	return name, nil
}

// UnpackDomainName decodes a DNS domain name from the wire payload at the given offset,
// following RFC 1035 §4.1.4 compression pointer redirections without heap allocations.
// It returns the decoded canonical string, the next wire offset, and an error if malformed.
func UnpackDomainName(payload []byte, offset int) (string, int, error) {
	var decompressor domainDecompressor
	return decompressor.decode(payload, offset)
}

// domainDecompressor reconstructs uncompressed domain name strings from DNS wire format
// following RFC 1035 §4.1.4 compression pointer redirections with zero heap allocation.
//
// Wire Pointer Mechanics:
// In RFC 1035 §4.1.4, when the two high-order bits of a length octet are set (0xC0),
// the octet pair denotes a 14-bit offset (pointerOffsetMask = 0x3FFF) from the start of the DNS header.
// To guarantee deterministic execution and guard against forward memory attacks or circular compression loops,
// compression pointers must point strictly backward relative to the current stream offset, and the total jump depth
// is bounded by maxJumps. The resumeOffset records the byte position directly following the first encountered pointer
// to allow the caller to resume linear parsing across subsequent message sections.
type domainDecompressor struct {
	buffer [MaxNameLen]byte
	length int
	jumps  int
}

func (d *domainDecompressor) decode(payload []byte, startOffset int) (string, int, error) {
	currentOffset := startOffset
	resumeOffset := startOffset
	hasJumped := false

	for {
		if d.jumps > maxJumps {
			return "", 0, ErrTooManyJumps
		}

		if currentOffset >= len(payload) {
			return "", 0, ErrOutOfBounds
		}

		octet := int(payload[currentOffset])

		// Null octet terminates domain name
		if octet == 0 {
			if !hasJumped {
				resumeOffset++
			}
			break
		}

		// Compression pointer detected (top 2 bits are 11 -> 0xC0)
		if (octet & pointerMask) == pointerMask {
			if currentOffset+1 >= len(payload) {
				return "", 0, ErrOutOfBounds
			}

			pointerOffset := int(binary.BigEndian.Uint16(payload[currentOffset:currentOffset+2])) & pointerOffsetMask

			// Security: pointers must point backward to already-parsed bytes to prevent loops/forward references
			if pointerOffset >= len(payload) || pointerOffset >= currentOffset {
				return "", 0, ErrInvalidPointer
			}

			if !hasJumped {
				resumeOffset += 2
				hasJumped = true
			}

			currentOffset = pointerOffset
			d.jumps++
			continue
		}

		labelLength := octet
		if labelLength > MaxLabelLen {
			return "", 0, ErrLabelTooLong
		}

		currentOffset++
		if currentOffset+labelLength > len(payload) {
			return "", 0, ErrOutOfBounds
		}

		if d.length+labelLength+1 > MaxNameLen {
			return "", 0, ErrNameTooLong
		}

		copy(d.buffer[d.length:d.length+labelLength], payload[currentOffset:currentOffset+labelLength])

		d.length += labelLength
		d.buffer[d.length] = '.'
		d.length++

		currentOffset += labelLength

		if !hasJumped {
			resumeOffset = currentOffset
		}
	}

	if d.length > 0 {
		d.length-- // strip trailing dot
	}

	return string(d.buffer[:d.length]), resumeOffset, nil
}
