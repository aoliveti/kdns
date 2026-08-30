// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrInvalidIPAddress indicates an invalid IPv4 or IPv6 presentation string.
	ErrInvalidIPAddress = errors.New("dns: invalid IP address format")

	// ErrInvalidRData indicates malformed or out-of-bounds resource record data.
	ErrInvalidRData = errors.New("dns: invalid record data format")

	base32HexEncoding = base32.HexEncoding.WithPadding(base32.NoPadding)
)

// PackRData parses a text presentation RData string and compiles it into binary wire format.
func PackRData(qType Type, text string) ([]byte, error) {
	var buffer [4096]byte
	writer, err := newPacketWriter(buffer[:], len(buffer))
	if err != nil {
		return nil, err
	}
	rdataLen, err := writeRData(&writer, qType, text)
	if err != nil {
		return nil, err
	}
	wire := make([]byte, rdataLen)
	copy(wire, buffer[:rdataLen])
	return wire, nil
}

// MustPackRData encodes a text presentation RData string into wire format, panicking on error.
func MustPackRData(qType Type, text string) []byte {
	wire, err := PackRData(qType, text)
	if err != nil {
		panic(err)
	}
	return wire
}

// NewRRSet constructs a populated RRSet from human-readable text representations with class IN.
func NewRRSet(qType Type, ttl uint32, textValues ...string) RRSet {
	rdata := make([][]byte, 0, len(textValues))
	for _, val := range textValues {
		rdata = append(rdata, MustPackRData(qType, val))
	}
	return RRSet{
		Type:  qType,
		Class: ClassIN,
		TTL:   ttl,
		RData: rdata,
	}
}

// UnpackRData decodes a binary wire-format RData payload into its canonical presentation text format.
func UnpackRData(qType Type, wire []byte) (string, error) {
	switch qType {
	case TypeA:
		if len(wire) != 4 {
			return "", fmt.Errorf("%w: A record requires 4 bytes, got %d", ErrInvalidRData, len(wire))
		}
		addr, _ := netip.AddrFromSlice(wire)
		return addr.String(), nil

	case TypeAAAA:
		if len(wire) != 16 {
			return "", fmt.Errorf("%w: AAAA record requires 16 bytes, got %d", ErrInvalidRData, len(wire))
		}
		addr, _ := netip.AddrFromSlice(wire)
		return addr.String(), nil

	case TypeCNAME, TypeNS, TypePTR:
		domainName, _, err := readWireDomain(wire, 0)
		if err != nil {
			return "", fmt.Errorf("failed to decode domain name: %w", err)
		}
		return domainName, nil

	case TypeTXT:
		var builder strings.Builder
		offset := 0
		for offset < len(wire) {
			chunkLen := int(wire[offset])
			offset++
			if offset+chunkLen > len(wire) {
				return "", fmt.Errorf("%w: TXT chunk exceeds wire bounds", ErrInvalidRData)
			}
			if builder.Len() > 0 {
				builder.WriteByte(' ')
			}
			builder.Write(wire[offset : offset+chunkLen])
			offset += chunkLen
		}
		return builder.String(), nil

	case TypeMX:
		if len(wire) < 3 {
			return "", fmt.Errorf("%w: MX wire payload too short", ErrInvalidRData)
		}
		preference := binary.BigEndian.Uint16(wire[:2])
		exchange, _, err := readWireDomain(wire, 2)
		if err != nil {
			return "", fmt.Errorf("failed to decode MX exchange: %w", err)
		}
		return fmt.Sprintf("%d %s", preference, exchange), nil

	case TypeSRV:
		if len(wire) < 7 {
			return "", fmt.Errorf("%w: SRV wire payload too short", ErrInvalidRData)
		}
		priority := binary.BigEndian.Uint16(wire[0:2])
		weight := binary.BigEndian.Uint16(wire[2:4])
		port := binary.BigEndian.Uint16(wire[4:6])
		target, _, err := readWireDomain(wire, 6)
		if err != nil {
			return "", fmt.Errorf("failed to decode SRV target: %w", err)
		}
		return fmt.Sprintf("%d %d %d %s", priority, weight, port, target), nil

	case TypeSOA:
		primaryMaster, nextOffset, err := readWireDomain(wire, 0)
		if err != nil {
			return "", fmt.Errorf("failed to decode SOA primary master name: %w", err)
		}
		responsibleMailbox, nextOffset, err := readWireDomain(wire, nextOffset)
		if err != nil {
			return "", fmt.Errorf("failed to decode SOA responsible mailbox: %w", err)
		}
		if nextOffset+20 > len(wire) {
			return "", fmt.Errorf("%w: SOA numerical timers too short", ErrInvalidRData)
		}
		serial := binary.BigEndian.Uint32(wire[nextOffset : nextOffset+4])
		refresh := binary.BigEndian.Uint32(wire[nextOffset+4 : nextOffset+8])
		retry := binary.BigEndian.Uint32(wire[nextOffset+8 : nextOffset+12])
		expire := binary.BigEndian.Uint32(wire[nextOffset+12 : nextOffset+16])
		minimumTTL := binary.BigEndian.Uint32(wire[nextOffset+16 : nextOffset+20])
		return fmt.Sprintf("%s %s %d %d %d %d %d", primaryMaster, responsibleMailbox, serial, refresh, retry, expire, minimumTTL), nil

	case TypeCAA:
		if len(wire) < 3 {
			return "", fmt.Errorf("%w: CAA wire payload too short", ErrInvalidRData)
		}
		flags := wire[0]
		tagLen := int(wire[1])
		if 2+tagLen > len(wire) {
			return "", fmt.Errorf("%w: CAA tag exceeds wire bounds", ErrInvalidRData)
		}
		tag := string(wire[2 : 2+tagLen])
		value := string(wire[2+tagLen:])
		return fmt.Sprintf("%d %s %s", flags, tag, strconv.Quote(value)), nil

	case TypeDS, TypeDNSKEY, TypeRRSIG, TypeZONEMD:
		return unpackDNSSECRData(qType, wire)

	default:
		return hex.EncodeToString(wire), nil
	}
}

// unpackDNSSECRData decodes DNSSEC and cryptographic RDATA payloads (DS, DNSKEY, RRSIG, ZONEMD) into presentation text format.
func unpackDNSSECRData(qType Type, wire []byte) (string, error) {
	switch qType {
	case TypeDS:
		if len(wire) < 4 {
			return "", fmt.Errorf("%w: DS wire payload too short", ErrInvalidRData)
		}
		keyTag := binary.BigEndian.Uint16(wire[:2])
		algorithm := wire[2]
		digestType := wire[3]
		digestHex := strings.ToUpper(hex.EncodeToString(wire[4:]))
		return fmt.Sprintf("%d %d %d %s", keyTag, algorithm, digestType, digestHex), nil

	case TypeDNSKEY:
		if len(wire) < 4 {
			return "", fmt.Errorf("%w: DNSKEY wire payload too short", ErrInvalidRData)
		}
		flags := binary.BigEndian.Uint16(wire[:2])
		protocol := wire[2]
		algorithm := wire[3]
		publicKey := base64.StdEncoding.EncodeToString(wire[4:])
		return fmt.Sprintf("%d %d %d %s", flags, protocol, algorithm, publicKey), nil

	case TypeRRSIG:
		if len(wire) < 18 {
			return "", fmt.Errorf("%w: RRSIG wire payload too short", ErrInvalidRData)
		}
		typeCovered := Type(binary.BigEndian.Uint16(wire[:2]))
		algorithm := wire[2]
		labels := wire[3]
		originalTTL := binary.BigEndian.Uint32(wire[4:8])
		expiration := binary.BigEndian.Uint32(wire[8:12])
		inception := binary.BigEndian.Uint32(wire[12:16])
		keyTag := binary.BigEndian.Uint16(wire[16:18])
		signerName, nextOffset, err := readWireDomain(wire, 18)
		if err != nil {
			return "", fmt.Errorf("failed to decode RRSIG signer: %w", err)
		}
		signature := base64.StdEncoding.EncodeToString(wire[nextOffset:])
		return fmt.Sprintf("%s %d %d %d %d %d %d %s %s", typeCovered.String(), algorithm, labels, originalTTL, expiration, inception, keyTag, signerName, signature), nil

	case TypeZONEMD:
		if len(wire) < 6 {
			return "", fmt.Errorf("%w: ZONEMD wire payload too short", ErrInvalidRData)
		}
		serial := binary.BigEndian.Uint32(wire[:4])
		scheme := wire[4]
		hashAlgorithm := wire[5]
		digestHex := strings.ToUpper(hex.EncodeToString(wire[6:]))
		return fmt.Sprintf("%d %d %d %s", serial, scheme, hashAlgorithm, digestHex), nil

	default:
		return hex.EncodeToString(wire), nil
	}
}

// readWireDomain decodes a compressed domain name from a binary RData payload,
// appending a trailing dot for canonical presentation format.
func readWireDomain(wire []byte, offset int) (string, int, error) {
	var decompressor domainDecompressor
	name, nextOffset, err := decompressor.decode(wire, offset)
	if err != nil {
		return "", offset, err
	}
	if name == "" {
		return ".", nextOffset, nil
	}
	return name + ".", nextOffset, nil
}

func writeRData(w *packetWriter, qType Type, rdata string) (int, error) {
	origOffset := w.offset
	var err error
	switch qType {
	case TypeA:
		err = writeRDataA(w, rdata)
	case TypeAAAA:
		err = writeRDataAAAA(w, rdata)
	case TypeTXT:
		err = writeRDataTXT(w, rdata)
	case TypeCNAME, TypeNS, TypePTR:
		err = w.writeDomain(rdata)
	case TypeSOA:
		err = writeRDataSOA(w, rdata)
	case TypeMX:
		err = writeRDataMX(w, rdata)
	case TypeSRV:
		err = writeRDataSRV(w, rdata)
	case TypeDNSKEY:
		err = writeRDataDNSKEY(w, rdata)
	case TypeDS:
		err = writeRDataDS(w, rdata)
	case TypeRRSIG:
		err = writeRDataRRSIG(w, rdata)
	case TypeNSEC:
		err = writeRDataNSEC(w, rdata)
	case TypeNSEC3:
		err = writeRDataNSEC3(w, rdata)
	case TypeZONEMD:
		err = writeRDataZONEMD(w, rdata)
	case TypeCAA:
		err = writeRDataCAA(w, rdata)
	default:
		err = writeRDataRaw(w, rdata)
	}
	if err != nil {
		return 0, err
	}
	return w.offset - origOffset, nil
}

func writeRDataA(w *packetWriter, rdata string) error {
	addr, err := netip.ParseAddr(rdata)
	if err != nil || !addr.Is4() {
		return ErrInvalidIPAddress
	}
	if w.offset+4 > len(w.buf) {
		return ErrBufferTooSmall
	}
	ip4 := addr.As4()
	copy(w.buf[w.offset:], ip4[:])
	w.offset += 4
	return nil
}

func writeRDataAAAA(w *packetWriter, rdata string) error {
	addr, err := netip.ParseAddr(rdata)
	if err != nil || !addr.Is6() {
		return ErrInvalidIPAddress
	}
	if w.offset+16 > len(w.buf) {
		return ErrBufferTooSmall
	}
	ip6 := addr.As16()
	copy(w.buf[w.offset:], ip6[:])
	w.offset += 16
	return nil
}

func writeRDataTXT(w *packetWriter, rdata string) error {
	if rdata == "" {
		if w.offset+1 > len(w.buf) {
			return ErrBufferTooSmall
		}
		w.buf[w.offset] = 0
		w.offset++
		return nil
	}
	for rdata != "" {
		chunkLen := min(len(rdata), math.MaxUint8)
		if w.offset+1+chunkLen > len(w.buf) {
			return ErrBufferTooSmall
		}
		// #nosec G115 -- chunkLen is bounded by math.MaxUint8 (255)
		w.buf[w.offset] = byte(chunkLen)
		copy(w.buf[w.offset+1:], rdata[:chunkLen])
		w.offset += 1 + chunkLen
		rdata = rdata[chunkLen:]
	}
	return nil
}

// writeRDataSOA encodes a Start of Authority record (RFC 1035 §3.3.13).
//
// Format: <primaryMaster> <responsibleMailbox> <serial> <refresh> <retry> <expire> <minimumTTL>
func writeRDataSOA(w *packetWriter, rdata string) error {
	fields := strings.Fields(rdata)
	if len(fields) != 7 {
		return fmt.Errorf("%w: invalid SOA rdata fields count", ErrInvalidRData)
	}

	primaryMaster := fields[0]
	responsibleMailbox := fields[1]

	serial, err1 := strconv.ParseUint(fields[2], 10, 32)
	refresh, err2 := strconv.ParseUint(fields[3], 10, 32)
	retry, err3 := strconv.ParseUint(fields[4], 10, 32)
	expire, err4 := strconv.ParseUint(fields[5], 10, 32)
	minimumTTL, err5 := strconv.ParseUint(fields[6], 10, 32)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil {
		return fmt.Errorf("%w: invalid SOA numeric timers", ErrInvalidRData)
	}

	if err := w.writeDomain(primaryMaster); err != nil {
		return err
	}
	if err := w.writeDomain(responsibleMailbox); err != nil {
		return err
	}

	if w.offset+20 > len(w.buf) {
		return ErrBufferTooSmall
	}

	binary.BigEndian.PutUint32(w.buf[w.offset:w.offset+4], uint32(serial))
	binary.BigEndian.PutUint32(w.buf[w.offset+4:w.offset+8], uint32(refresh))
	binary.BigEndian.PutUint32(w.buf[w.offset+8:w.offset+12], uint32(retry))
	binary.BigEndian.PutUint32(w.buf[w.offset+12:w.offset+16], uint32(expire))
	binary.BigEndian.PutUint32(w.buf[w.offset+16:w.offset+20], uint32(minimumTTL))
	w.offset += 20

	return nil
}

// writeRDataMX encodes a Mail Exchange record (RFC 1035 §3.3.9).
//
// Format: <preference> <exchange>
func writeRDataMX(w *packetWriter, rdata string) error {
	fields := strings.Fields(rdata)
	if len(fields) < 2 {
		return errors.New("dns: invalid MX rdata")
	}
	preference, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return errors.New("dns: invalid MX preference")
	}
	if w.offset+2 > len(w.buf) {
		return ErrBufferTooSmall
	}
	binary.BigEndian.PutUint16(w.buf[w.offset:w.offset+2], uint16(preference))
	w.offset += 2
	return w.writeDomain(fields[1])
}

// writeRDataSRV encodes a Service Location record (RFC 2782).
//
// Format: <priority> <weight> <port> <target>
func writeRDataSRV(w *packetWriter, rdata string) error {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return errors.New("dns: invalid SRV rdata")
	}
	priority, err1 := strconv.ParseUint(fields[0], 10, 16)
	weight, err2 := strconv.ParseUint(fields[1], 10, 16)
	port, err3 := strconv.ParseUint(fields[2], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil {
		return errors.New("dns: invalid SRV numeric field")
	}
	if w.offset+6 > len(w.buf) {
		return ErrBufferTooSmall
	}
	binary.BigEndian.PutUint16(w.buf[w.offset:w.offset+2], uint16(priority))
	binary.BigEndian.PutUint16(w.buf[w.offset+2:w.offset+4], uint16(weight))
	binary.BigEndian.PutUint16(w.buf[w.offset+4:w.offset+6], uint16(port))
	w.offset += 6
	return w.writeDomain(fields[3])
}

// writeRDataDNSKEY encodes a DNSSEC public key record (RFC 4034 §2).
//
// Format: <flags> <protocol> <algorithm> <publicKeyBase64>
func writeRDataDNSKEY(w *packetWriter, rdata string) error {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return fmt.Errorf("%w: invalid DNSKEY rdata", ErrInvalidRData)
	}
	flags, err1 := strconv.ParseUint(fields[0], 10, 16)
	protocol, err2 := strconv.ParseUint(fields[1], 10, 8)
	algorithm, err3 := strconv.ParseUint(fields[2], 10, 8)
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("%w: invalid DNSKEY numeric field", ErrInvalidRData)
	}
	publicKeyString := strings.Join(fields[3:], "")
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyString)
	if err != nil {
		return fmt.Errorf("%w: invalid DNSKEY base64 public key: %w", ErrInvalidRData, err)
	}
	prefix := (uint32(flags) << 16) | (uint32(protocol) << 8) | uint32(algorithm)
	return writePrefixedPayload(w, prefix, publicKeyBytes)
}

// writeRDataDS encodes a Delegation Signer record (RFC 4034 §5).
//
// Format: <keyTag> <algorithm> <digestType> <digestHex>
func writeRDataDS(w *packetWriter, rdata string) error {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return fmt.Errorf("%w: invalid DS rdata", ErrInvalidRData)
	}
	keyTag, err1 := strconv.ParseUint(fields[0], 10, 16)
	algorithm, err2 := strconv.ParseUint(fields[1], 10, 8)
	digestType, err3 := strconv.ParseUint(fields[2], 10, 8)
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("%w: invalid DS numeric field", ErrInvalidRData)
	}
	digestString := strings.Join(fields[3:], "")
	digestBytes, err := hex.DecodeString(digestString)
	if err != nil {
		return fmt.Errorf("%w: invalid DS hex digest: %w", ErrInvalidRData, err)
	}
	prefix := (uint32(keyTag) << 16) | (uint32(algorithm) << 8) | uint32(digestType)
	return writePrefixedPayload(w, prefix, digestBytes)
}

func writePrefixedPayload(w *packetWriter, prefix uint32, payload []byte) error {
	if w.offset+4+len(payload) > len(w.buf) {
		return ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(w.buf[w.offset:w.offset+4], prefix)
	copy(w.buf[w.offset+4:], payload)
	w.offset += 4 + len(payload)
	return nil
}

// writeRDataRRSIG encodes a DNSSEC signature record (RFC 4034 §3).
//
// Format: <typeCovered> <algorithm> <labels> <originalTTL> <expiration> <inception> <keyTag> <signerName> <signatureBase64>
func writeRDataRRSIG(w *packetWriter, rdata string) error {
	fields := strings.Fields(rdata)
	if len(fields) < 9 {
		return fmt.Errorf("%w: invalid RRSIG rdata fields count", ErrInvalidRData)
	}

	typeCovered, err1 := ParseType(fields[0])
	algorithm, err2 := strconv.ParseUint(fields[1], 10, 8)
	labels, err3 := strconv.ParseUint(fields[2], 10, 8)
	originalTTL, err4 := strconv.ParseUint(fields[3], 10, 32)
	expirationTime, err5 := parseRRSIGTimestamp(fields[4])
	inceptionTime, err6 := parseRRSIGTimestamp(fields[5])
	keyTag, err7 := strconv.ParseUint(fields[6], 10, 16)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil || err7 != nil {
		return fmt.Errorf("%w: invalid RRSIG numeric field", ErrInvalidRData)
	}

	signatureString := strings.Join(fields[8:], "")
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureString)
	if err != nil {
		return fmt.Errorf("%w: invalid RRSIG base64 signature: %w", ErrInvalidRData, err)
	}

	if w.offset+18 > len(w.buf) {
		return ErrBufferTooSmall
	}

	binary.BigEndian.PutUint16(w.buf[w.offset:w.offset+2], uint16(typeCovered))
	w.buf[w.offset+2] = byte(algorithm)
	w.buf[w.offset+3] = byte(labels)
	binary.BigEndian.PutUint32(w.buf[w.offset+4:w.offset+8], uint32(originalTTL))
	binary.BigEndian.PutUint32(w.buf[w.offset+8:w.offset+12], expirationTime)
	binary.BigEndian.PutUint32(w.buf[w.offset+12:w.offset+16], inceptionTime)
	binary.BigEndian.PutUint16(w.buf[w.offset+16:w.offset+18], uint16(keyTag))
	w.offset += 18

	if err := w.writeUncompressedDomain(fields[7]); err != nil {
		return err
	}

	if w.offset+len(signatureBytes) > len(w.buf) {
		return ErrBufferTooSmall
	}

	copy(w.buf[w.offset:], signatureBytes)
	w.offset += len(signatureBytes)
	return nil
}

// writeRDataNSEC encodes a Next Secure record (RFC 4034 §4).
//
// Format: <nextOwnerName> <type1> <type2> ...
func writeRDataNSEC(w *packetWriter, rdata string) error {
	fields := strings.Fields(rdata)
	if len(fields) < 2 {
		return fmt.Errorf("%w: invalid NSEC rdata fields count", ErrInvalidRData)
	}

	if err := w.writeUncompressedDomain(fields[0]); err != nil {
		return err
	}

	bitmapLen, err := encodeTypeBitMaps(w.buf, w.offset, fields[1:])
	if err != nil {
		return err
	}

	w.offset += bitmapLen
	return nil
}

// writeRDataNSEC3 encodes a Next Secure 3 hashed authenticated denial record (RFC 5155 §3).
//
// Format: <hashAlg> <flags> <iterations> <saltHex> <nextHashedOwnerB32Hex> <type1> ...
func writeRDataNSEC3(w *packetWriter, rdata string) error {
	fields := strings.Fields(rdata)
	if len(fields) < 6 {
		return fmt.Errorf("%w: invalid NSEC3 rdata fields count", ErrInvalidRData)
	}

	hashAlgorithm, err1 := strconv.ParseUint(fields[0], 10, 8)
	flags, err2 := strconv.ParseUint(fields[1], 10, 8)
	iterations, err3 := strconv.ParseUint(fields[2], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("%w: invalid NSEC3 numeric field", ErrInvalidRData)
	}

	var saltBytes []byte
	if fields[3] != "-" {
		var err error
		saltBytes, err = hex.DecodeString(fields[3])
		if err != nil {
			return fmt.Errorf("%w: invalid NSEC3 salt hex: %w", ErrInvalidRData, err)
		}
	}
	if len(saltBytes) > math.MaxUint8 {
		return fmt.Errorf("%w: NSEC3 salt length exceeds uint8", ErrInvalidRData)
	}

	nextOwnerString := strings.ToUpper(fields[4])
	nextOwnerBytes, err := base32HexEncoding.DecodeString(nextOwnerString)
	if err != nil {
		return fmt.Errorf("%w: invalid NSEC3 next hashed owner base32hex: %w", ErrInvalidRData, err)
	}
	if len(nextOwnerBytes) > math.MaxUint8 {
		return fmt.Errorf("%w: NSEC3 hash length exceeds uint8", ErrInvalidRData)
	}

	fixedHeaderLen := 5 + len(saltBytes) + 1 + len(nextOwnerBytes)
	if w.offset+fixedHeaderLen > len(w.buf) {
		return ErrBufferTooSmall
	}

	w.buf[w.offset] = byte(hashAlgorithm)
	w.buf[w.offset+1] = byte(flags)
	binary.BigEndian.PutUint16(w.buf[w.offset+2:w.offset+4], uint16(iterations))

	// #nosec G115
	w.buf[w.offset+4] = byte(len(saltBytes))
	copy(w.buf[w.offset+5:], saltBytes)

	saltEndOffset := w.offset + 5 + len(saltBytes)
	// #nosec G115
	w.buf[saltEndOffset] = byte(len(nextOwnerBytes))
	copy(w.buf[saltEndOffset+1:], nextOwnerBytes)

	ownerEndOffset := saltEndOffset + 1 + len(nextOwnerBytes)

	bitmapLen, err := encodeTypeBitMaps(w.buf, ownerEndOffset, fields[5:])
	if err != nil {
		return err
	}

	w.offset = ownerEndOffset + bitmapLen
	return nil
}

// writeRDataZONEMD encodes a Zone Message Digest record (RFC 8976).
//
// Format: <serial> <scheme> <hashAlgorithm> <digestHex>
func writeRDataZONEMD(w *packetWriter, rdata string) error {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return fmt.Errorf("%w: invalid ZONEMD rdata fields count", ErrInvalidRData)
	}
	serial, err1 := strconv.ParseUint(fields[0], 10, 32)
	scheme, err2 := strconv.ParseUint(fields[1], 10, 8)
	hashAlgorithm, err3 := strconv.ParseUint(fields[2], 10, 8)
	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("%w: invalid ZONEMD numeric field", ErrInvalidRData)
	}

	digestString := strings.Join(fields[3:], "")
	digestBytes, err := hex.DecodeString(digestString)
	if err != nil {
		return fmt.Errorf("%w: invalid ZONEMD hex digest: %w", ErrInvalidRData, err)
	}

	if w.offset+6+len(digestBytes) > len(w.buf) {
		return ErrBufferTooSmall
	}

	binary.BigEndian.PutUint32(w.buf[w.offset:w.offset+4], uint32(serial))
	w.buf[w.offset+4] = byte(scheme)
	w.buf[w.offset+5] = byte(hashAlgorithm)
	copy(w.buf[w.offset+6:], digestBytes)
	w.offset += 6 + len(digestBytes)
	return nil
}

// writeRDataCAA encodes a Certification Authority Authorization record (RFC 8659).
//
// Format: <flags> <tag> <value>
func writeRDataCAA(w *packetWriter, rdata string) error {
	fields := strings.SplitN(rdata, " ", 3)
	if len(fields) < 3 {
		return errors.New("dns: invalid CAA rdata")
	}
	flags, err := strconv.ParseUint(fields[0], 10, 8)
	if err != nil {
		return errors.New("dns: invalid CAA flags")
	}
	tag := fields[1]
	if len(tag) > math.MaxUint8 {
		return errors.New("dns: CAA tag too long")
	}
	val := strings.Trim(fields[2], `"`)
	if w.offset+2+len(tag)+len(val) > len(w.buf) {
		return ErrBufferTooSmall
	}
	w.buf[w.offset] = byte(flags)
	// #nosec G115
	w.buf[w.offset+1] = byte(len(tag))
	copy(w.buf[w.offset+2:], tag)
	copy(w.buf[w.offset+2+len(tag):], val)
	w.offset += 2 + len(tag) + len(val)
	return nil
}

func writeRDataRaw(w *packetWriter, rdata string) error {
	if w.offset+len(rdata) > len(w.buf) {
		return ErrBufferTooSmall
	}
	copy(w.buf[w.offset:], rdata)
	w.offset += len(rdata)
	return nil
}

// encodeTypeBitMaps constructs the RFC 4034 §4.1.2 / RFC 5155 §3.2.1 windowed type bitmap.
//
// Layout: Window Block (1 byte) | Bitmap Length (1 byte) | Bitmap Octets (1-32 bytes)
func encodeTypeBitMaps(buf []byte, offset int, typeStrings []string) (int, error) {
	if len(typeStrings) == 0 {
		return 0, fmt.Errorf("%w: missing NSEC types in bitmap", ErrInvalidRData)
	}

	typeNumbers := make([]uint16, 0, len(typeStrings))
	for _, typeStr := range typeStrings {
		parsedType, err := ParseType(typeStr)
		if err != nil {
			return 0, fmt.Errorf("%w: invalid NSEC type %q: %w", ErrInvalidRData, typeStr, err)
		}
		typeNumbers = append(typeNumbers, uint16(parsedType))
	}

	slices.Sort(typeNumbers)

	originalOffset := offset
	currentBlock := -1
	var blockStartOffset int
	var maxBitInBlock int

	for _, typeNum := range typeNumbers {
		block := int(typeNum / 256)
		if block != currentBlock {
			if currentBlock != -1 {
				bitmapLen := (maxBitInBlock / 8) + 1
				buf[blockStartOffset+1] = byte(bitmapLen)
				offset = blockStartOffset + 2 + bitmapLen
			}
			currentBlock = block
			blockStartOffset = offset
			maxBitInBlock = int(typeNum % 256)

			if offset+34 > len(buf) {
				return 0, ErrBufferTooSmall
			}
			// #nosec G115
			buf[offset] = byte(block)
			clear(buf[offset+2 : offset+34])
		}

		bitPos := int(typeNum % 256)
		if bitPos > maxBitInBlock {
			maxBitInBlock = bitPos
		}

		byteIndex := bitPos / 8
		bitIndex := 7 - (bitPos % 8)
		buf[blockStartOffset+2+byteIndex] |= 1 << bitIndex
	}

	if currentBlock != -1 {
		bitmapLen := (maxBitInBlock / 8) + 1
		buf[blockStartOffset+1] = byte(bitmapLen)
		offset = blockStartOffset + 2 + bitmapLen
	}

	return offset - originalOffset, nil
}

func parseRRSIGTimestamp(timestampStr string) (uint32, error) {
	if len(timestampStr) == 14 {
		parsedTime, err := time.Parse("20060102150405", timestampStr)
		if err == nil {
			seconds := parsedTime.Unix()
			if seconds < 0 || seconds > math.MaxUint32 {
				return 0, fmt.Errorf("%w: timestamp out of uint32 bounds", ErrInvalidRData)
			}
			// #nosec G115
			return uint32(seconds), nil
		}
	}
	numericVal, err := strconv.ParseUint(timestampStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(numericVal), nil
}
