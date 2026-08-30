// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wal provides Write-Ahead Log appending and replay mechanisms for crash safety.
//
// Every mutating transaction (Upsert or Delete) is atomically appended as an in-band
// CRC32-verified frame:
//
// Upsert Frame Layout:
//   - Opcode: [1 byte] (0x01 = OpUpsert)
//   - Codec Payload: [Domain + RRSets binary frame]
//   - Checksum: [4 bytes uint32 CRC32-IEEE over Opcode + Codec Payload]
//
// Delete Frame Layout:
//   - Opcode: [1 byte] (0x02 = OpDelete)
//   - Domain Length: [2 bytes uint16]
//   - Domain Name: [ASCII/UTF-8 bytes]
//   - Checksum: [4 bytes uint32 CRC32-IEEE over Opcode + Length + Domain Name]
//
// Strict boundary validations are enforced to prevent corrupted stream replay and torn writes.
package wal

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"

	"github.com/aoliveti/kdns/internal/codec"
	"github.com/aoliveti/kdns/internal/dns"
)

const (
	// OpUpsert identifies an insert or update transaction frame in the log.
	OpUpsert = byte(0x01)

	// OpDelete identifies a removal transaction frame in the log.
	OpDelete = byte(0x02)

	checksumSize = 4
	scratchSize  = 512
)

var (
	// ErrCorruptedData indicates that stream bytes violate binary safety limits or checksum verification.
	ErrCorruptedData = errors.New("wal: corrupted stream data violates binary safety limits")

	// ErrCapacityExceeded indicates that a domain name or record count exceeds RFC 1035 safety bounds.
	ErrCapacityExceeded = errors.New("wal: element size or count exceeds binary safety limits")

	// ErrInvalidOpcode indicates that an unrecognized transaction operation byte was encountered.
	ErrInvalidOpcode = errors.New("wal: unknown operation code")

	// ErrTruncated indicates that the WAL file ends with an incomplete or truncated frame.
	ErrTruncated = errors.New("wal: truncated tail frame")
)

// Writer manages appending serialized mutation operations to the write-ahead log.
type Writer struct {
	file    *os.File
	bw      *bufio.Writer
	crc     hash.Hash32
	enc     *codec.Encoder
	scratch [scratchSize]byte
}

// NewWriter creates a new WAL writer wrapping the provided file.
func NewWriter(file *os.File) *Writer {
	h32 := crc32.NewIEEE()
	bw := bufio.NewWriter(file)
	return &Writer{
		file: file,
		bw:   bw,
		crc:  h32,
		enc:  codec.NewEncoder(bw, h32),
	}
}

// AppendUpsert serializes and appends an upsert operation frame to the log.
func (w *Writer) AppendUpsert(domain string, records dns.RRSets) error {
	if len(domain) > codec.MaxDomainLen || len(records) > codec.MaxRecordsPerDomain {
		return ErrCapacityExceeded
	}

	w.crc.Reset()

	w.scratch[0] = OpUpsert
	if _, err := w.bw.Write(w.scratch[:1]); err != nil {
		return fmt.Errorf("wal: write upsert opcode: %w", err)
	}
	_, _ = w.crc.Write(w.scratch[:1])

	if err := w.enc.WriteRecord(domain, records); err != nil {
		if errors.Is(err, codec.ErrCapacityExceeded) {
			return ErrCapacityExceeded
		}
		return fmt.Errorf("wal: write upsert payload: %w", err)
	}

	return w.writeChecksum()
}

// AppendDelete serializes and appends a delete operation frame to the log in a single atomic buffer write.
func (w *Writer) AppendDelete(domain string) error {
	if len(domain) > codec.MaxDomainLen {
		return ErrCapacityExceeded
	}

	w.crc.Reset()

	w.scratch[0] = OpDelete
	// #nosec G115
	binary.BigEndian.PutUint16(w.scratch[1:3], uint16(len(domain)))
	copy(w.scratch[3:], domain)
	payloadLen := 3 + len(domain)

	_, _ = w.crc.Write(w.scratch[:payloadLen])
	sum := w.crc.Sum32()

	binary.BigEndian.PutUint32(w.scratch[payloadLen:payloadLen+checksumSize], sum)
	totalLen := payloadLen + checksumSize

	if _, err := w.bw.Write(w.scratch[:totalLen]); err != nil {
		return fmt.Errorf("wal: write delete frame: %w", err)
	}

	return nil
}

// Flush flushes buffered journal frames and forces a physical fsync to disk.
func (w *Writer) Flush() error {
	if err := w.bw.Flush(); err != nil {
		return fmt.Errorf("wal: flush buffer: %w", err)
	}

	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("wal: sync file: %w", err)
	}

	return nil
}

func (w *Writer) writeChecksum() error {
	sum := w.crc.Sum32()
	binary.BigEndian.PutUint32(w.scratch[:checksumSize], sum)
	if _, err := w.bw.Write(w.scratch[:checksumSize]); err != nil {
		return fmt.Errorf("wal: write checksum: %w", err)
	}
	return nil
}

// Replay reads the WAL stream sequentially and executes the callbacks.
// It returns nil only on a clean EOF at frame boundaries. Any truncated
// frame or checksum mismatch is explicitly wrapped and returned.
func Replay(r io.Reader, onUpsert func(string, dns.RRSets), onDelete func(string)) error {
	br := bufio.NewReader(r)
	crcHash := crc32.NewIEEE()
	dec := codec.NewDecoder(br, crcHash)
	var scratch [scratchSize]byte

	for {
		crcHash.Reset()

		if _, err := io.ReadFull(br, scratch[:1]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return normalizeEOF(err, "read opcode")
		}

		op := scratch[0]
		_, _ = crcHash.Write(scratch[:1])

		switch op {
		case OpUpsert:
			if err := replayUpsert(br, dec, crcHash, scratch[:], onUpsert); err != nil {
				return err
			}

		case OpDelete:
			if err := replayDelete(br, crcHash, scratch[:], onDelete); err != nil {
				return err
			}

		default:
			return fmt.Errorf("wal: opcode %#x: %w", op, ErrInvalidOpcode)
		}
	}
}

func replayUpsert(br io.Reader, dec *codec.Decoder, crcHash hash.Hash32, scratch []byte, onUpsert func(string, dns.RRSets)) error {
	domain, records, err := dec.ReadRecord()
	if err != nil {
		return normalizeEOF(err, "replay upsert payload")
	}

	if err := verifyChecksum(br, crcHash, scratch); err != nil {
		return normalizeEOF(err, "replay upsert checksum")
	}

	onUpsert(domain, records)
	return nil
}

func replayDelete(br io.Reader, crcHash hash.Hash32, scratch []byte, onDelete func(string)) error {
	if _, err := io.ReadFull(br, scratch[:2]); err != nil {
		return normalizeEOF(err, "read delete domain length")
	}
	domainLen := binary.BigEndian.Uint16(scratch[:2])
	if domainLen == 0 || int(domainLen) > codec.MaxDomainLen {
		return fmt.Errorf("wal: invalid delete domain length (%d): %w", domainLen, ErrCorruptedData)
	}
	_, _ = crcHash.Write(scratch[:2])

	if _, err := io.ReadFull(br, scratch[:domainLen]); err != nil {
		return normalizeEOF(err, "read delete domain name")
	}
	_, _ = crcHash.Write(scratch[:domainLen])

	domainStr := string(scratch[:domainLen])

	if err := verifyChecksum(br, crcHash, scratch); err != nil {
		return normalizeEOF(err, "replay delete checksum")
	}

	onDelete(domainStr)
	return nil
}

func verifyChecksum(r io.Reader, h hash.Hash32, scratch []byte) error {
	if _, err := io.ReadFull(r, scratch[:checksumSize]); err != nil {
		return fmt.Errorf("read frame crc32: %w", err)
	}

	expected := binary.BigEndian.Uint32(scratch[:checksumSize])
	if expected != h.Sum32() {
		return ErrCorruptedData
	}

	return nil
}

func normalizeEOF(err error, ctx string) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrTruncated
	}
	if errors.Is(err, codec.ErrCorruptedData) {
		return ErrCorruptedData
	}
	return fmt.Errorf("wal: %s: %w", ctx, err)
}
