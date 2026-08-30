// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
)

const (
	// MaxUDPSize defines the legacy RFC 1035 UDP payload limit (512 bytes).
	MaxUDPSize = 512

	// MaxEDNS0Size defines the DNS Flag Day 2020 recommended UDP cap to avoid IP fragmentation (1232 bytes).
	MaxEDNS0Size = 1232

	// MaxTCPSize defines the maximum payload size for DNS over TCP (65535 bytes, RFC 7766).
	MaxTCPSize = 65535

	// DefaultEDNS0BufferSize advertises the server's UDP payload capacity in OPT records (4096 bytes).
	DefaultEDNS0BufferSize = 4096

	maxCompressionOffsets = 16
	pointerMask16         = uint16(0xC000)
)

var (
	// ErrBufferTooSmall indicates that the destination buffer has insufficient capacity for wire serialization.
	ErrBufferTooSmall = errors.New("dns: buffer too small for serialization")
)

// PackResponse serializes a DNS response packet into wire format using the provided pre-allocated buffer.
// It encodes header flags, preserves the question section, appends answer/authority/additional records,
// enforces the maxSize boundary (setting the TC bit upon overflow), and attaches an EDNS0 OPT record if requested.
func (m *Message) PackResponse(buf []byte, res Result, maxSize int) (int, error) {
	questionCount := len(m.Questions)
	if questionCount > maxQuestions {
		return 0, ErrTooManyQuestions
	}

	writer, err := newPacketWriter(buf, maxSize)
	if err != nil {
		return 0, err
	}

	// Preserve query ID, opcode, and RD bit; set QR=1 (response), AA=1 (authoritative), and RCODE
	flags := (m.Header.Flags & 0x7900) | 0x8400 | uint16(res.RCode&0x0F)
	if res.RCode == RCodeSuccess && !res.HasAnswer() && res.HasAuthority() && res.Authority.Type == TypeNS {
		flags &= ^uint16(0x0400) // RFC 1034 §4.3.2 & RFC 2181 §6.1: Clear AA bit on delegation referrals
	}
	writer.writeHeader(m.Header.ID, flags, uint16(questionCount))

	for _, question := range m.Questions {
		if err := writer.writeQuestion(question); err != nil {
			return 0, err
		}
	}

	answerCount := uint16(0)
	if res.RCode == RCodeSuccess && questionCount > 0 && res.HasAnswer() {
		var err error
		answerCount, err = writer.writeRRSet(m.Questions[0].Name, res.Answer)
		if err != nil {
			return 0, err
		}
		if m.DO && res.HasAnswerRRSIG() {
			rrsigCount, rrsigErr := writer.writeRRSet(m.Questions[0].Name, res.AnswerRRSIG)
			if rrsigErr != nil {
				return 0, rrsigErr
			}
			answerCount += rrsigCount
		}
	}

	authorityCount, authErr := m.writeAuthoritySection(&writer, res, questionCount)
	if authErr != nil {
		return 0, authErr
	}

	additionalCount := uint16(0)
	if res.RCode == RCodeSuccess && questionCount > 0 && res.HasAdditional() {
		var err error
		additionalCount, err = writer.writeRRSet(m.Questions[0].Name, res.Additional)
		if err != nil {
			return 0, err
		}
	}

	additionalCount += writer.writeEDNS0(m, res)
	writer.updateCounts(answerCount, authorityCount, additionalCount)

	return writer.offset, nil
}

// writeAuthoritySection encodes the Authority RRSet and optional RRSIG into the message buffer.
func (m *Message) writeAuthoritySection(writer *packetWriter, res Result, questionCount int) (uint16, error) {
	if questionCount == 0 || !res.HasAuthority() {
		return 0, nil
	}
	authorityOwner := res.AuthorityName
	if authorityOwner == "" {
		authorityOwner = m.Questions[0].Name
	}
	authorityCount, err := writer.writeRRSet(authorityOwner, res.Authority)
	if err != nil {
		return 0, err
	}
	if m.DO && res.HasAuthorityRRSIG() {
		rrsigCount, rrsigErr := writer.writeRRSet(authorityOwner, res.AuthorityRRSIG)
		if rrsigErr != nil {
			return 0, rrsigErr
		}
		authorityCount += rrsigCount
	}
	return authorityCount, nil
}

type packetWriter struct {
	buf              []byte
	compressionTable domainCompressor
	offset           int
}

func newPacketWriter(buf []byte, maxSize int) (packetWriter, error) {
	if maxSize > len(buf) {
		maxSize = len(buf)
	}
	if maxSize < headerSize {
		return packetWriter{}, ErrBufferTooSmall
	}
	return packetWriter{
		buf: buf[:maxSize],
	}, nil
}

func (w *packetWriter) writeHeader(id, flags, questionCount uint16) {
	binary.BigEndian.PutUint16(w.buf[0:2], id)
	binary.BigEndian.PutUint16(w.buf[2:4], flags)
	binary.BigEndian.PutUint16(w.buf[4:6], questionCount)
	binary.BigEndian.PutUint16(w.buf[6:8], 0)
	binary.BigEndian.PutUint16(w.buf[8:10], 0)
	binary.BigEndian.PutUint16(w.buf[10:12], 0)
	w.offset = headerSize
}

func (w *packetWriter) writeQuestion(q Question) error {
	if err := w.writeDomain(q.Name); err != nil {
		return err
	}
	if len(w.buf)-w.offset < 4 {
		return ErrBufferTooSmall
	}
	binary.BigEndian.PutUint16(w.buf[w.offset:w.offset+2], uint16(q.Type))
	binary.BigEndian.PutUint16(w.buf[w.offset+2:w.offset+4], uint16(q.Class))
	w.offset += 4
	return nil
}

func (w *packetWriter) writeRRSet(ownerName string, set RRSet) (uint16, error) {
	count := uint16(0)
	for _, rdataWire := range set.RData {
		recordStartOffset := w.offset

		if err := w.writeDomain(ownerName); err != nil {
			if errors.Is(err, ErrBufferTooSmall) {
				w.offset = recordStartOffset
				w.setTruncatedFlag()
				break
			}
			return 0, err
		}

		if len(w.buf)-w.offset < 10+len(rdataWire) {
			w.offset = recordStartOffset
			w.setTruncatedFlag()
			break
		}

		binary.BigEndian.PutUint16(w.buf[w.offset:w.offset+2], uint16(set.Type))
		binary.BigEndian.PutUint16(w.buf[w.offset+2:w.offset+4], uint16(set.Class))
		binary.BigEndian.PutUint32(w.buf[w.offset+4:w.offset+8], set.TTL)
		// #nosec G115
		binary.BigEndian.PutUint16(w.buf[w.offset+8:w.offset+10], uint16(len(rdataWire)))
		w.offset += 10

		copy(w.buf[w.offset:], rdataWire)
		w.offset += len(rdataWire)

		count++
		if count == math.MaxUint16 {
			break
		}
	}
	return count, nil
}

func (w *packetWriter) setTruncatedFlag() {
	currentFlags := binary.BigEndian.Uint16(w.buf[2:4])
	binary.BigEndian.PutUint16(w.buf[2:4], currentFlags|0x0200)
}

func (w *packetWriter) updateCounts(answerCount, authorityCount, additionalCount uint16) {
	binary.BigEndian.PutUint16(w.buf[6:8], answerCount)
	binary.BigEndian.PutUint16(w.buf[8:10], authorityCount)
	binary.BigEndian.PutUint16(w.buf[10:12], additionalCount)
}

func (w *packetWriter) writeEDNS0(m *Message, res Result) uint16 {
	if m.EDNS0Size == 0 {
		return 0
	}
	if len(w.buf)-w.offset < 11 {
		return 0
	}
	w.buf[w.offset] = 0 // Root domain owner name (empty label)
	binary.BigEndian.PutUint16(w.buf[w.offset+1:w.offset+3], uint16(TypeOPT))
	binary.BigEndian.PutUint16(w.buf[w.offset+3:w.offset+5], DefaultEDNS0BufferSize)

	var ednsFlags uint16
	if m.DO {
		ednsFlags |= 0x8000 // Set DO bit (DNSSEC OK)
	}
	extRCodeUpper := byte(res.RCode >> 4)
	ttlVal := (uint32(extRCodeUpper) << 24) | uint32(ednsFlags)
	binary.BigEndian.PutUint32(w.buf[w.offset+5:w.offset+9], ttlVal)
	binary.BigEndian.PutUint16(w.buf[w.offset+9:w.offset+11], 0) // RDLENGTH = 0 (no extra options)

	w.offset += 11
	return 1
}

func (w *packetWriter) writeDomain(name string) error {
	return w.writeDomainCompressed(name, true)
}

func (w *packetWriter) writeUncompressedDomain(name string) error {
	return w.writeDomainCompressed(name, false)
}

// writeFinalLabel serializes the trailing domain label followed by a terminal root null octet.
func (w *packetWriter) writeFinalLabel(label string, allowCompression bool) error {
	labelLen := len(label)
	if labelLen > MaxLabelLen {
		return ErrLabelTooLong
	}
	if labelLen == 0 {
		return nil
	}
	if w.offset+1+labelLen+1 > len(w.buf) {
		return ErrBufferTooSmall
	}
	if allowCompression {
		w.compressionTable.insert(label, w.offset)
	}
	w.buf[w.offset] = byte(labelLen)
	copy(w.buf[w.offset+1:], label)
	w.offset += 1 + labelLen
	w.buf[w.offset] = 0 // Terminal root null octet
	w.offset++
	return nil
}

// writeIntermediateLabel serializes a non-terminal domain label into the packet buffer.
func (w *packetWriter) writeIntermediateLabel(fullSuffix, label string, allowCompression bool) error {
	labelLen := len(label)
	if labelLen > MaxLabelLen {
		return ErrLabelTooLong
	}
	if labelLen == 0 {
		return nil
	}
	if w.offset+1+labelLen > len(w.buf) {
		return ErrBufferTooSmall
	}
	if allowCompression {
		w.compressionTable.insert(fullSuffix, w.offset)
	}
	w.buf[w.offset] = byte(labelLen)
	copy(w.buf[w.offset+1:], label)
	w.offset += 1 + labelLen
	return nil
}

// writeDomainCompressed encodes a domain name in RFC 1035 wire format, utilizing pointer compression
// when allowCompression is true to minimize packet size.
func (w *packetWriter) writeDomainCompressed(name string, allowCompression bool) error {
	if len(name) > MaxNameLen {
		return ErrNameTooLong
	}

	if name == "" || name == "." {
		if w.offset >= len(w.buf) {
			return ErrBufferTooSmall
		}
		w.buf[w.offset] = 0
		w.offset++
		return nil
	}

	currentSuffix := name
	for {
		if allowCompression {
			if pointerOffset, found := w.compressionTable.lookup(currentSuffix); found {
				if w.offset+2 > len(w.buf) {
					return ErrBufferTooSmall
				}
				binary.BigEndian.PutUint16(w.buf[w.offset:w.offset+2], pointerMask16|pointerOffset)
				w.offset += 2
				return nil
			}
		}

		dotIndex := strings.IndexByte(currentSuffix, '.')

		// Final label in the domain
		if dotIndex == -1 {
			if err := w.writeFinalLabel(currentSuffix, allowCompression); err != nil {
				return err
			}
			break
		}

		// Intermediate label
		if err := w.writeIntermediateLabel(currentSuffix, currentSuffix[:dotIndex], allowCompression); err != nil {
			return err
		}

		currentSuffix = currentSuffix[dotIndex+1:]
		if currentSuffix == "" {
			if w.offset >= len(w.buf) {
				return ErrBufferTooSmall
			}
			w.buf[w.offset] = 0
			w.offset++
			break
		}
	}

	return nil
}

// domainCompressor maintains a zero-allocation fixed-size table of domain suffix offsets (RFC 1035 §4.1.4).
type domainCompressor struct {
	names   [maxCompressionOffsets]string
	offsets [maxCompressionOffsets]uint16
	count   uint8
}

func (c *domainCompressor) lookup(domain string) (uint16, bool) {
	if domain == "" || domain == "." {
		return 0, false
	}
	for i := uint8(0); i < c.count; i++ {
		if equalFoldASCII(c.names[i], domain) {
			return c.offsets[i], true
		}
	}
	return 0, false
}

func (c *domainCompressor) insert(domain string, offset int) {
	if c.count >= maxCompressionOffsets || offset > 0x3FFF || domain == "" || domain == "." {
		return
	}
	for i := uint8(0); i < c.count; i++ {
		if equalFoldASCII(c.names[i], domain) {
			return
		}
	}
	c.names[c.count] = domain
	// #nosec G115 -- offset is bounded by offset <= 0x3FFF (16383)
	c.offsets[c.count] = uint16(offset)
	c.count++
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// MaxPayloadSize calculates the effective wire payload limit honoring EDNS0 constraints.
func MaxPayloadSize(transportSize, edns0Size int) int {
	maxSize := transportSize
	if transportSize == MaxUDPSize && edns0Size > MaxUDPSize {
		maxSize = min(edns0Size, MaxEDNS0Size)
	}
	return maxSize
}

// TruncateToSlip mutates a serialized DNS response wire buffer in-place to construct
// an RRL "slip" response as specified in BCP 140 Section 4.
//
// It sets the TC (Truncated) bit in the header, zeroes out the Answer, Authority,
// and Additional record counts, and truncates the payload to retain only the Question section.
// This forces legitimate DNS clients/resolvers to fall back to TCP transport while
// mitigating UDP amplification attacks.
func TruncateToSlip(buf []byte, written int) int {
	if len(buf) < headerSize || written < headerSize || written > len(buf) {
		return written
	}

	payload := buf[:written]

	// Set TC (Truncated) bit in header flags word (0x0200)
	flags := binary.BigEndian.Uint16(payload[2:4]) | 0x0200
	binary.BigEndian.PutUint16(payload[2:4], flags)

	// Zero out Answer (ANCount), Authority (NSCount), and Additional (ARCount)
	binary.BigEndian.PutUint16(payload[6:8], 0)
	binary.BigEndian.PutUint16(payload[8:10], 0)
	binary.BigEndian.PutUint16(payload[10:12], 0)

	// Scan Question section starting after 12-byte header to find its end
	offset := headerSize
	for offset < len(payload) {
		lenByte := int(payload[offset])
		if lenByte == 0 {
			offset++
			break
		}
		if lenByte >= pointerMask {
			offset += 2
			break
		}
		offset += 1 + lenByte
	}

	// Add 4 bytes for Type (2) + QClass (2)
	offset += 4
	if offset <= len(payload) {
		return offset
	}
	return headerSize
}
