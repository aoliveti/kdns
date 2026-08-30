// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsig

import (
	"crypto/hmac"
	"encoding/binary"
	"slices"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
)

// Record holds the unpacked fields of an RFC 2845 / RFC 8945 TSIG pseudo-record.
type Record struct {
	Name       string
	Algorithm  string
	MAC        []byte
	OtherData  []byte
	TimeSigned uint64
	OriginalID uint16
	Fudge      uint16
	Error      uint16
}

// Extract strips the trailing TSIG resource record from an incoming wire packet if present.
// RFC 2845 §3.2 specifies that TSIG must be the final record in the Additional section.
// On success, it returns the parsed TSIG record and the modified message payload with ARCount decremented by 1.
func Extract(payload []byte) (*Record, []byte, error) {
	if len(payload) < headerSize {
		return nil, payload, nil
	}

	arCount := binary.BigEndian.Uint16(payload[10:12])
	if arCount == 0 {
		return nil, payload, nil
	}

	qdCount := binary.BigEndian.Uint16(payload[4:6])
	anCount := binary.BigEndian.Uint16(payload[6:8])
	nsCount := binary.BigEndian.Uint16(payload[8:10])

	tsigStartOffset, err := skipMessageSections(payload, qdCount, anCount, nsCount, arCount)
	if err != nil {
		return nil, payload, err
	}

	keyName, nextOffset, err := dns.UnpackDomainName(payload, tsigStartOffset)
	if err != nil {
		return nil, payload, err
	}
	offset := nextOffset

	if offset+10 > len(payload) {
		return nil, payload, nil
	}

	qType := binary.BigEndian.Uint16(payload[offset : offset+2])
	qClass := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
	ttl := binary.BigEndian.Uint32(payload[offset+4 : offset+8])
	rdLen := int(binary.BigEndian.Uint16(payload[offset+8 : offset+10]))
	offset += 10

	// Verify standard TSIG pseudo-record attributes (Type TSIG, Class ANY, TTL 0)
	if dns.Type(qType) != dns.TypeTSIG || dns.Class(qClass) != dns.ClassANY || ttl != 0 {
		return nil, payload, nil
	}

	if offset+rdLen > len(payload) {
		return nil, payload, ErrMalformedTSIG
	}

	rec, err := unpackTSIGRecord(payload, offset, offset+rdLen, keyName)
	if err != nil {
		return nil, payload, err
	}

	payloadWithoutTSIG := payload[:tsigStartOffset]
	binary.BigEndian.PutUint16(payloadWithoutTSIG[10:12], arCount-1)

	return rec, payloadWithoutTSIG, nil
}

// skipMessageSections traverses the Question, Answer, Authority, and preceding Additional
// sections, advancing the byte offset directly to the start of the final TSIG record.
func skipMessageSections(payload []byte, qd, an, ns, ar uint16) (int, error) {
	offset := headerSize

	// Traverse Question section (Name + Type uint16 + Class uint16)
	for range qd {
		_, nextOffset, err := dns.UnpackDomainName(payload, offset)
		if err != nil {
			return 0, err
		}
		offset = nextOffset + 4
		if offset > len(payload) {
			return 0, ErrMalformedTSIG
		}
	}

	// Traverse Answer, Authority, and leading Additional records prior to TSIG
	recordsToSkip := int(an) + int(ns) + int(ar) - 1
	for range recordsToSkip {
		_, nextOffset, err := dns.UnpackDomainName(payload, offset)
		if err != nil {
			return 0, err
		}
		if nextOffset+10 > len(payload) {
			return 0, ErrMalformedTSIG
		}
		rdLen := int(binary.BigEndian.Uint16(payload[nextOffset+8 : nextOffset+10]))
		offset = nextOffset + 10 + rdLen
		if offset > len(payload) {
			return 0, ErrMalformedTSIG
		}
	}

	return offset, nil
}

// unpackTSIGRecord decodes the fixed and variable RDATA payload of an RFC 2845 TSIG record.
func unpackTSIGRecord(payload []byte, offset, rdataEnd int, keyName string) (*Record, error) {
	algoName, nextOffset, err := dns.UnpackDomainName(payload, offset)
	if err != nil {
		return nil, err
	}
	offset = nextOffset

	// Validate presence of fixed header: TimeSigned (48-bit), Fudge (16-bit), MACSize (16-bit)
	if offset+10 > rdataEnd {
		return nil, ErrMalformedTSIG
	}

	timeHigh := uint64(binary.BigEndian.Uint16(payload[offset : offset+2]))
	timeLow := uint64(binary.BigEndian.Uint32(payload[offset+2 : offset+6]))
	timeSigned := (timeHigh << 32) | timeLow
	fudge := binary.BigEndian.Uint16(payload[offset+6 : offset+8])
	macSize := int(binary.BigEndian.Uint16(payload[offset+8 : offset+10]))
	offset += 10

	// Validate presence of MAC payload and trailing fixed fields: OriginalID (16-bit), Error (16-bit), OtherLen (16-bit)
	if offset+macSize+6 > rdataEnd {
		return nil, ErrMalformedTSIG
	}

	mac := slices.Clone(payload[offset : offset+macSize])
	offset += macSize

	origID := binary.BigEndian.Uint16(payload[offset : offset+2])
	tsigErr := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
	otherLen := int(binary.BigEndian.Uint16(payload[offset+4 : offset+6]))
	offset += 6

	if offset+otherLen > rdataEnd {
		return nil, ErrMalformedTSIG
	}
	var otherData []byte
	if otherLen > 0 {
		otherData = slices.Clone(payload[offset : offset+otherLen])
	}

	return &Record{
		Name:       CanonicalName(keyName),
		Algorithm:  CanonicalAlgorithm(algoName),
		TimeSigned: timeSigned,
		Fudge:      fudge,
		MAC:        mac,
		OriginalID: origID,
		Error:      tsigErr,
		OtherData:  otherData,
	}, nil
}

// Verify validates the cryptographic HMAC signature of an incoming DNS wire message.
// In accordance with RFC 2845 §3.4.2, it performs the following verification steps:
// 1. Matches key name and HMAC algorithm against server credentials in canonical form.
// 2. Checks clock skew between current server time and TimeSigned within the allowed Fudge window.
// 3. Restores OriginalID into the message header byte array prior to hashing.
// 4. Computes the HMAC over the stripped wire payload concatenated with the TSIG variables.
// 5. Compares digests using constant-time comparison (crypto/hmac.Equal) to prevent timing attacks.
func Verify(payloadWithoutTSIG []byte, rec *Record, key Key, now time.Time) (uint16, error) {
	if CanonicalName(key.Name) != rec.Name {
		return dns.TSIGErrBadKey, ErrBadKey
	}

	if CanonicalAlgorithm(key.Algorithm) != rec.Algorithm {
		return dns.TSIGErrBadAlg, ErrBadAlgorithm
	}

	nowUnix := now.Unix()
	var skew uint64
	switch {
	case nowUnix >= 0 && uint64(nowUnix) >= rec.TimeSigned:
		skew = uint64(nowUnix) - rec.TimeSigned
	case nowUnix >= 0:
		skew = rec.TimeSigned - uint64(nowUnix)
	default:
		skew = rec.TimeSigned
	}
	fudge := uint64(rec.Fudge)
	if fudge == 0 {
		fudge = defaultFudge
	}
	if skew > fudge {
		return dns.TSIGErrBadTime, ErrBadTime
	}

	h, err := newHasher(rec.Algorithm, key.Secret)
	if err != nil {
		return dns.TSIGErrBadAlg, err
	}

	// RFC 2845 §3.4.2: Hash wire message with OriginalID restored into header
	origMsg := make([]byte, len(payloadWithoutTSIG))
	copy(origMsg, payloadWithoutTSIG)
	if rec.OriginalID != 0 {
		binary.BigEndian.PutUint16(origMsg[0:2], rec.OriginalID)
	}
	h.Write(origMsg)

	// RFC 2845 §3.4.2: Append TSIG variables (Name, Class ANY, TTL 0, Alg, TimeSigned, Fudge, Error, OtherData)
	writeTSIGVariables(h, rec.Name, rec.Algorithm, rec.TimeSigned, rec.Fudge, rec.Error, rec.OtherData)

	expectedMAC := h.Sum(nil)
	if !hmac.Equal(expectedMAC, rec.MAC) {
		return dns.TSIGErrBadSig, ErrBadSignature
	}

	return 0, nil
}
