// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package snapshot manages CRC32-verified state snapshots for persistent storage.
//
// Snapshot framing layout (Big-Endian):
//   - Header:
//   - Magic: "KDNS" [4 bytes]
//   - Version: [1 byte] (0x01)
//   - Total Domains Count: [4 bytes uint32]
//   - Body:
//   - Stream of codec-encoded records: [N records]
//   - Trailer:
//   - Checksum: [4 bytes uint32 CRC32-IEEE over Header + Body]
package snapshot

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/aoliveti/kdns/internal/codec"
	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
)

const (
	snapMagic   = "KDNS"
	snapVersion = byte(0x01)

	headerSize   = len(snapMagic) + 1 + 4 + 4
	checksumSize = 4
)

type flateReader interface {
	io.ReadCloser
	flate.Resetter
}

var (
	bufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}

	flateWriterPool = sync.Pool{
		New: func() any {
			w, _ := flate.NewWriter(io.Discard, flate.BestSpeed)
			return w
		},
	}

	flateReaderPool = sync.Pool{
		New: func() any {
			r, _ := flate.NewReader(strings.NewReader("")).(flateReader)
			return r
		},
	}
)

var (
	// ErrInvalidMagic indicates the snapshot header does not match the expected format.
	ErrInvalidMagic = errors.New("snapshot: invalid magic header")

	// ErrUnsupportedVer indicates that the snapshot format version is not supported.
	ErrUnsupportedVer = errors.New("snapshot: unsupported snapshot version")

	// ErrChecksumFailed indicates the CRC32 verification of the snapshot failed.
	ErrChecksumFailed = errors.New("snapshot: checksum verification failed")

	// ErrCorruptedData indicates that the stream data is corrupted and violates binary safety limits.
	ErrCorruptedData = errors.New("snapshot: corrupted stream data violates binary safety limits")

	// ErrCapacityExceeded indicates that an element exceeds binary safety limits.
	ErrCapacityExceeded = errors.New("snapshot: element size or count exceeds binary safety limits")
)

// Save serializes the entire radix tree state into a binary compressed stream.
// It writes domain count and compressed body length in the header using O(1) Tree.Len(),
// compresses data with flate.BestSpeed, enforces strict memory bounds, and appends a trailing CRC32 checksum.
func Save(w io.Writer, tree *radix.Tree) error {
	domainCount := tree.Len()
	if domainCount > math.MaxUint32 {
		return errors.New("snapshot: total domain count exceeds uint32 capacity limit")
	}

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		buf.Reset()
		bufferPool.Put(buf)
	}()

	fw := flateWriterPool.Get().(*flate.Writer)
	fw.Reset(buf)

	enc := codec.NewEncoder(fw, nil)
	for domain, records := range tree.Walk() {
		if err := enc.WriteRecord(domain, records); err != nil {
			_ = fw.Close()
			flateWriterPool.Put(fw)
			if errors.Is(err, codec.ErrCapacityExceeded) {
				return ErrCapacityExceeded
			}
			return fmt.Errorf("failed to write record for %s: %w", domain, err)
		}
	}

	if err := enc.Flush(); err != nil {
		_ = fw.Close()
		flateWriterPool.Put(fw)
		return fmt.Errorf("failed to flush snapshot encoder: %w", err)
	}

	if err := fw.Close(); err != nil {
		flateWriterPool.Put(fw)
		return fmt.Errorf("failed to close flate writer: %w", err)
	}
	flateWriterPool.Put(fw)

	compressedData := buf.Bytes()
	if len(compressedData) > math.MaxUint32 {
		return errors.New("snapshot: compressed body exceeds uint32 capacity limit")
	}
	// #nosec G115
	bodyLen := uint32(len(compressedData))

	crcHasher := crc32.NewIEEE()
	// #nosec G115
	totalDomains := uint32(domainCount)

	if err := writeHeader(w, crcHasher, totalDomains, bodyLen); err != nil {
		return err
	}

	_, _ = crcHasher.Write(compressedData)
	if _, err := w.Write(compressedData); err != nil {
		return fmt.Errorf("failed to write compressed body: %w", err)
	}

	checksum := crcHasher.Sum32()
	var checksumBuf [checksumSize]byte
	binary.BigEndian.PutUint32(checksumBuf[:], checksum)

	if _, err := w.Write(checksumBuf[:]); err != nil {
		return fmt.Errorf("failed to write final checksum: %w", err)
	}

	return nil
}

// Load reads a binary compressed snapshot stream, streaming records directly into the onRecord callback,
// and verifies stream integrity via trailing CRC32 checksum.
func Load(r io.Reader, onRecord func(domain string, records dns.RRSets)) error {
	crcHasher := crc32.NewIEEE()

	totalDomains, bodyLen, err := readHeader(r, crcHasher)
	if err != nil {
		return err
	}

	lr := io.LimitReader(r, int64(bodyLen))
	tee := io.TeeReader(lr, crcHasher)

	fr := flateReaderPool.Get().(flateReader)
	if err := fr.Reset(tee, nil); err != nil {
		flateReaderPool.Put(fr)
		return fmt.Errorf("failed to reset flate reader: %w", err)
	}

	dec := codec.NewDecoder(fr, nil)
	for range totalDomains {
		domain, records, err := dec.ReadRecord()
		if err != nil {
			_ = fr.Close()
			flateReaderPool.Put(fr)
			if errors.Is(err, codec.ErrCorruptedData) {
				return ErrCorruptedData
			}
			return fmt.Errorf("failed to decode record: %w", err)
		}
		onRecord(domain, records)
	}

	if _, err := io.Copy(io.Discard, tee); err != nil {
		_ = fr.Close()
		flateReaderPool.Put(fr)
		return fmt.Errorf("failed to drain compressed stream: %w", err)
	}

	_ = fr.Close()
	flateReaderPool.Put(fr)

	var checksumBuf [checksumSize]byte
	if _, err := io.ReadFull(r, checksumBuf[:]); err != nil {
		return fmt.Errorf("failed to read checksum: %w", err)
	}

	expectedChecksum := binary.BigEndian.Uint32(checksumBuf[:])
	if crcHasher.Sum32() != expectedChecksum {
		return ErrChecksumFailed
	}

	return nil
}

func writeHeader(w io.Writer, h hash.Hash, totalDomains, bodyLen uint32) error {
	var headerBuf [headerSize]byte

	copy(headerBuf[0:4], snapMagic)
	headerBuf[4] = snapVersion
	binary.BigEndian.PutUint32(headerBuf[5:9], totalDomains)
	binary.BigEndian.PutUint32(headerBuf[9:13], bodyLen)

	_, _ = h.Write(headerBuf[:])
	if _, err := w.Write(headerBuf[:]); err != nil {
		return fmt.Errorf("buffer write error: %w", err)
	}

	return nil
}

func readHeader(r io.Reader, h hash.Hash) (uint32, uint32, error) {
	var headerBuf [headerSize]byte

	if _, err := io.ReadFull(r, headerBuf[:]); err != nil {
		return 0, 0, fmt.Errorf("buffer read error: %w", err)
	}

	if string(headerBuf[0:4]) != snapMagic {
		return 0, 0, ErrInvalidMagic
	}

	if headerBuf[4] != snapVersion {
		return 0, 0, ErrUnsupportedVer
	}

	_, _ = h.Write(headerBuf[:])
	totalDomains := binary.BigEndian.Uint32(headerBuf[5:9])
	bodyLen := binary.BigEndian.Uint32(headerBuf[9:13])
	return totalDomains, bodyLen, nil
}

// ReadChecksum extracts the 4-byte CRC32-IEEE checksum from the snapshot trailer.
func ReadChecksum(r io.ReaderAt, size int64) (uint32, error) {
	if size < int64(checksumSize) {
		return 0, io.ErrUnexpectedEOF
	}
	var checksumBuf [checksumSize]byte
	if _, err := r.ReadAt(checksumBuf[:], size-int64(checksumSize)); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(checksumBuf[:]), nil
}

// CleanStaleTemp scans dir and deletes any orphaned temporary snapshot files (matching
// pattern "state-snap-*.tmp") left behind by previous abnormal process terminations (such
// as SIGKILL, OOM kills, kernel panics, or sudden power cuts).
//
// In production environments where dir is persistent (e.g. Docker volumes or Kubernetes
// PersistentVolumes), CleanStaleTemp ensures that aborted temp writes never accumulate
// or leak disk space over time across daemon restarts.
//
// It uses os.Root to confine removal within dir, preventing symlink-based path traversal.
func CleanStaleTemp(dir string) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && strings.HasPrefix(name, "state-snap-") && strings.HasSuffix(name, ".tmp") {
			_ = root.Remove(name)
		}
	}
}

// CreateTemp creates a new temporary file inside root, opens it for reading and writing,
// and returns the resulting file and its relative name within root.
// It uses the standard library algorithm from os.CreateTemp, but operates strictly via
// root.OpenFile with O_CREATE|O_EXCL, guaranteeing 100% filesystem root confinement.
func CreateTemp(root *os.Root, pattern string) (*os.File, string, error) {
	prefix, suffix, err := prefixAndSuffix(pattern)
	if err != nil {
		return nil, "", &os.PathError{Op: "createtemp", Path: pattern, Err: err}
	}

	try := 0
	for {
		name := prefix + nextRandom() + suffix
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			try++
			if try < 10000 {
				continue
			}
			return nil, "", &os.PathError{Op: "createtemp", Path: prefix + "*" + suffix, Err: os.ErrExist}
		}
		if err != nil {
			return nil, "", err
		}
		return f, name, nil
	}
}

func prefixAndSuffix(pattern string) (string, string, error) {
	for i := range len(pattern) {
		if os.IsPathSeparator(pattern[i]) {
			return "", "", errors.New("pattern contains path separator")
		}
	}
	pos := strings.LastIndexByte(pattern, '*')
	if pos == -1 {
		return pattern, "", nil
	}
	return pattern[:pos], pattern[pos+1:], nil
}

func nextRandom() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(timeNanoFallback(), 10)
	}
	return strconv.FormatUint(binary.BigEndian.Uint64(b[:]), 10)
}

func timeNanoFallback() int64 {
	return 1
}
