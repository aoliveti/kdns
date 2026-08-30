// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package codec provides binary stream encoding and decoding for DNS records
// utilized in Write-Ahead Log (WAL) persistence journals and memory state snapshots.
//
// In an authoritative DNS server, transactional state persistence requires deterministic,
// zero-allocation binary framing coupled with optional streaming checksum integrity verification
// to detect torn writes, bit-rot, and corrupted disk pages during replay.
//
// Binary Framing Specification (Big-Endian Network Byte Order):
//   - Domain Name: [Length uint16] [ASCII/UTF-8 bytes]
//   - Records Count: [Count uint16]
//   - For each RRSet:
//   - Type: [Type uint16] (RFC 1035 / RFC 3597)
//   - TTL: [TTL uint32]
//   - RData Count: [Count uint16]
//   - For each RData Wire Payload:
//   - Payload: [Length uint16] [Raw RData bytes]
//
// Strict boundary validations (RFC 1035 domain lengths and resource record capacity limits)
// are enforced across every read/write boundary to prevent heap exhaustion attacks.
package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	// ScratchBufferSize defines the fixed buffer size for metadata encoding/decoding.
	ScratchBufferSize = 8

	// MaxDomainLen defines the maximum length of a domain name in octets per RFC 1035.
	MaxDomainLen = 255

	// MaxRecordsPerDomain defines the maximum number of RRSets allowed per domain.
	MaxRecordsPerDomain = 4096

	// MaxRDataCount defines the maximum number of records allowed within a single RRSet.
	MaxRDataCount = 4096

	// MaxRDataLen defines the maximum size in bytes for a single record's wire payload.
	MaxRDataLen = 65535
)

var (
	// ErrCapacityExceeded indicates that an element size or record count exceeds binary safety limits.
	ErrCapacityExceeded = errors.New("codec: element size or count exceeds binary safety limits")

	// ErrCorruptedData indicates that the stream data is malformed or violates safety boundaries.
	ErrCorruptedData = errors.New("codec: corrupted stream data violates binary safety limits")
)

type flusher interface {
	Flush() error
}

// Encoder handles the stateful binary serialization of DNS record sets.
// It formats entire records into an internal contiguous buffer, issuing single-shot
// writes and checksum updates for maximum throughput.
type Encoder struct {
	w    io.Writer
	hash hash.Hash
	buf  []byte
}

// Decoder handles the stateful, zero-allocation binary deserialization of DNS records.
type Decoder struct {
	r       io.Reader
	hash    hash.Hash
	strBuf  []byte
	scratch [ScratchBufferSize]byte
}

// NewEncoder initializes a stream encoder bound to an io.Writer.
// An optional hash.Hash can be provided for real-time checksum calculation (e.g. CRC32-IEEE).
func NewEncoder(w io.Writer, h hash.Hash) *Encoder {
	return &Encoder{
		w:    w,
		hash: h,
		buf:  make([]byte, 0, 512),
	}
}

// NewDecoder initializes a stream decoder bound to an io.Reader.
// An optional hash.Hash can be provided for real-time checksum verification.
func NewDecoder(r io.Reader, h hash.Hash) *Decoder {
	return &Decoder{
		r:      r,
		hash:   h,
		strBuf: make([]byte, 0, 256),
	}
}

// Reset rebinds the encoder to a new writer and hash accumulator, reusing its internal buffer.
func (e *Encoder) Reset(w io.Writer, h hash.Hash) {
	e.w = w
	e.hash = h
	e.buf = e.buf[:0]
}

// Reset rebinds the decoder to a new reader and hash verifier, reusing its internal buffers.
func (d *Decoder) Reset(r io.Reader, h hash.Hash) {
	d.r = r
	d.hash = h
	d.strBuf = d.strBuf[:0]
}

// Flush flushes any underlying flusher or buffered writer.
func (e *Encoder) Flush() error {
	if f, ok := e.w.(flusher); ok {
		if err := f.Flush(); err != nil {
			return fmt.Errorf("codec: buffer flush error: %w", err)
		}
	}
	return nil
}

// WriteRecord serializes a domain name and its associated RRSets into the stream in a single atomic write.
func (e *Encoder) WriteRecord(domain string, records dns.RRSets) error {
	frameSize, err := calculateFrameSize(domain, records)
	if err != nil {
		return err
	}

	if cap(e.buf) < frameSize {
		e.buf = make([]byte, frameSize)
	}
	e.buf = e.buf[:frameSize]

	b := e.buf

	// Pack domain name header: [Length uint16] [ASCII bytes]
	binary.BigEndian.PutUint16(b[0:2], uint16(len(domain))) //nolint:gosec // bounded by calculateFrameSize
	copy(b[2:], domain)
	offset := 2 + len(domain)

	// Pack RRSets collection: [Count uint16]
	binary.BigEndian.PutUint16(b[offset:offset+2], uint16(len(records))) //nolint:gosec // bounded by calculateFrameSize
	offset += 2

	for _, record := range records {
		// Pack RRSet header: [Type uint16] [TTL uint32] [RDataCount uint16]
		binary.BigEndian.PutUint16(b[offset:offset+2], uint16(record.Type))
		binary.BigEndian.PutUint32(b[offset+2:offset+6], record.TTL)
		binary.BigEndian.PutUint16(b[offset+6:offset+8], uint16(len(record.RData))) //nolint:gosec // bounded by calculateFrameSize
		offset += 8

		// Pack RData wire payloads: [Length uint16] [Payload bytes]
		for _, rData := range record.RData {
			binary.BigEndian.PutUint16(b[offset:offset+2], uint16(len(rData))) //nolint:gosec // bounded by calculateFrameSize
			copy(b[offset+2:], rData)
			offset += 2 + len(rData)
		}
	}

	if e.hash != nil {
		_, _ = e.hash.Write(b)
	}

	if _, err := e.w.Write(b); err != nil {
		return fmt.Errorf("codec: write error: %w", err)
	}

	return nil
}

// calculateFrameSize validates resource bounds and computes the total binary frame size in octets.
func calculateFrameSize(domain string, records dns.RRSets) (int, error) {
	if len(domain) > MaxDomainLen {
		return 0, fmt.Errorf("%w: domain length %d exceeds max %d", ErrCapacityExceeded, len(domain), MaxDomainLen)
	}
	if len(records) > MaxRecordsPerDomain {
		return 0, fmt.Errorf("%w: records count %d exceeds max %d", ErrCapacityExceeded, len(records), MaxRecordsPerDomain)
	}

	frameSize := 2 + len(domain) + 2
	for _, record := range records {
		if len(record.RData) > MaxRDataCount {
			return 0, fmt.Errorf("%w: rdata count %d exceeds max %d", ErrCapacityExceeded, len(record.RData), MaxRDataCount)
		}
		frameSize += 8
		for _, rData := range record.RData {
			if len(rData) > MaxRDataLen {
				return 0, fmt.Errorf("%w: rdata payload length %d exceeds max %d", ErrCapacityExceeded, len(rData), MaxRDataLen)
			}
			frameSize += 2 + len(rData)
			// Guard against unreasonable memory usage per domain
			if frameSize > 10*1024*1024 {
				return 0, fmt.Errorf("%w: encoded frame size exceeds 10MB safety limit", ErrCapacityExceeded)
			}
		}
	}
	return frameSize, nil
}

// ReadRecord deserializes a single domain and its associated RRSets from the stream.
func (d *Decoder) ReadRecord() (string, dns.RRSets, error) {
	domainLen, err := d.readUint16()
	if err != nil {
		return "", nil, fmt.Errorf("failed to read domain length: %w", err)
	}
	if domainLen > MaxDomainLen {
		return "", nil, fmt.Errorf("%w: domain length %d exceeds max %d", ErrCorruptedData, domainLen, MaxDomainLen)
	}

	domain, err := d.readString(int(domainLen))
	if err != nil {
		return "", nil, fmt.Errorf("failed to read domain name: %w", err)
	}

	recordsCount, err := d.readUint16()
	if err != nil {
		return "", nil, fmt.Errorf("failed to read records count: %w", err)
	}
	if recordsCount > MaxRecordsPerDomain {
		return "", nil, fmt.Errorf("%w: records count %d exceeds max %d", ErrCorruptedData, recordsCount, MaxRecordsPerDomain)
	}

	records := make(dns.RRSets, recordsCount)
	for i := range recordsCount {
		record, err := d.readRRSet()
		if err != nil {
			return "", nil, err
		}
		records[i] = record
	}

	return domain, records, nil
}

// readBytes reads exactly len(p) bytes from the underlying reader into p,
// updating the streaming checksum hash if one is configured.
func (d *Decoder) readBytes(p []byte) error {
	if _, err := io.ReadFull(d.r, p); err != nil {
		return fmt.Errorf("codec: read error: %w", err)
	}
	if d.hash != nil {
		_, _ = d.hash.Write(p)
	}
	return nil
}

// readUint16 reads a Big-Endian 16-bit unsigned integer using the pre-allocated scratch buffer.
func (d *Decoder) readUint16() (uint16, error) {
	if err := d.readBytes(d.scratch[:2]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(d.scratch[:2]), nil
}

// readString reads an n-byte string reusing the decoder's internal strBuf to minimize allocations.
func (d *Decoder) readString(n int) (string, error) {
	if cap(d.strBuf) < n {
		d.strBuf = make([]byte, n, max(n, 256))
	}
	d.strBuf = d.strBuf[:n]

	if err := d.readBytes(d.strBuf); err != nil {
		return "", err
	}
	return string(d.strBuf), nil
}

// readRRSet reads an entire RRSet (Type, TTL, RDATA count, and individual wire payloads).
func (d *Decoder) readRRSet() (dns.RRSet, error) {
	if err := d.readBytes(d.scratch[:ScratchBufferSize]); err != nil {
		return dns.RRSet{}, fmt.Errorf("failed to read record metadata: %w", err)
	}

	qType := binary.BigEndian.Uint16(d.scratch[:2])
	ttl := binary.BigEndian.Uint32(d.scratch[2:6])
	rDataCount := binary.BigEndian.Uint16(d.scratch[6:8])

	if rDataCount > MaxRDataCount {
		return dns.RRSet{}, fmt.Errorf("%w: rdata count %d exceeds max %d", ErrCorruptedData, rDataCount, MaxRDataCount)
	}

	rData := make([][]byte, rDataCount)
	for j := range rDataCount {
		payloadLen, err := d.readUint16()
		if err != nil {
			return dns.RRSet{}, fmt.Errorf("failed to read rdata length: %w", err)
		}
		if payloadLen > MaxRDataLen {
			return dns.RRSet{}, fmt.Errorf("%w: rdata payload length %d exceeds max %d", ErrCorruptedData, payloadLen, MaxRDataLen)
		}

		wireBytes := make([]byte, payloadLen)
		if err := d.readBytes(wireBytes); err != nil {
			return dns.RRSet{}, fmt.Errorf("failed to read rdata payload: %w", err)
		}
		rData[j] = wireBytes
	}

	return dns.RRSet{
		Type:  dns.Type(qType),
		Class: dns.ClassIN,
		TTL:   ttl,
		RData: rData,
	}, nil
}
