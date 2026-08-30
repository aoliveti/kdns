// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wal

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/codec"
	"github.com/aoliveti/kdns/internal/dns"
)

func TestWAL_RoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("StandardSequence", func(t *testing.T) {
		t.Parallel()
		file := createTempFile(t)
		w := NewWriter(file)

		recordsA := dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.168.1.1"), dns.MustPackRData(dns.TypeA, "10.0.0.1")}},
		}
		recordsB := dns.RRSets{
			{Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "v=spf1 ~all")}},
		}

		err := w.AppendUpsert("example.com", recordsA)
		require.NoError(t, err)

		err = w.AppendUpsert("test.org", recordsB)
		require.NoError(t, err)

		err = w.AppendDelete("example.com")
		require.NoError(t, err)

		err = w.Flush()
		require.NoError(t, err)

		_, err = file.Seek(0, 0)
		require.NoError(t, err)

		replayedUpserts := make(map[string]dns.RRSets)
		var deletedDomains []string

		err = Replay(
			file,
			func(domain string, records dns.RRSets) {
				replayedUpserts[domain] = records
			},
			func(domain string) {
				deletedDomains = append(deletedDomains, domain)
			},
		)

		require.NoError(t, err)

		require.Contains(t, replayedUpserts, "example.com")
		assert.Equal(t, recordsA, replayedUpserts["example.com"])

		require.Contains(t, replayedUpserts, "test.org")
		assert.Equal(t, recordsB, replayedUpserts["test.org"])

		assert.Equal(t, []string{"example.com"}, deletedDomains)
	})
}

func TestWAL_CapacityBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		op   func(w *Writer) error
		name string
	}{
		{
			name: "UpsertDomainOverflow",
			op: func(w *Writer) error {
				oversizedDomain := strings.Repeat("a", codec.MaxDomainLen+1)
				r1, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
				records := dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{r1}}}
				return w.AppendUpsert(oversizedDomain, records)
			},
		},
		{
			name: "UpsertRecordsCountOverflow",
			op: func(w *Writer) error {
				oversizedRecords := make(dns.RRSets, codec.MaxRecordsPerDomain+1)
				for i := range oversizedRecords {
					oversizedRecords[i] = dns.RRSet{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}
				}
				return w.AppendUpsert("example.com", oversizedRecords)
			},
		},
		{
			name: "DeleteDomainOverflow",
			op: func(w *Writer) error {
				return w.AppendDelete(strings.Repeat("a", codec.MaxDomainLen+1))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := createTempFile(t)
			w := NewWriter(file)
			err := tc.op(w)
			require.ErrorIs(t, err, ErrCapacityExceeded)
		})
	}
}

func TestWAL_CrashRecovery(t *testing.T) {
	t.Parallel()

	t.Run("TruncatedInPayload", func(t *testing.T) {
		t.Parallel()
		tempDir := t.TempDir()
		root, err := os.OpenRoot(tempDir)
		require.NoError(t, err)
		defer func() { _ = root.Close() }()

		writeTestRecords(t, root, "truncated_payload.wal")

		data, err := root.ReadFile("truncated_payload.wal")
		require.NoError(t, err)

		truncated := data[:len(data)-10]
		require.NoError(t, root.WriteFile("truncated_payload.wal", truncated, 0o600))

		file, err := root.OpenFile("truncated_payload.wal", os.O_RDONLY, 0o600)
		require.NoError(t, err)
		defer func() {
			_ = file.Close()
		}()

		var replayedCount int
		err = Replay(
			file,
			func(_ string, _ dns.RRSets) { replayedCount++ },
			func(_ string) { replayedCount++ },
		)

		require.ErrorIs(t, err, ErrTruncated)
		assert.Equal(t, 1, replayedCount)
	})

	t.Run("TruncatedInCRC32", func(t *testing.T) {
		t.Parallel()
		tempDir := t.TempDir()
		root, err := os.OpenRoot(tempDir)
		require.NoError(t, err)
		defer func() { _ = root.Close() }()

		writeTestRecords(t, root, "truncated_crc.wal")

		data, err := root.ReadFile("truncated_crc.wal")
		require.NoError(t, err)

		truncated := data[:len(data)-2]
		require.NoError(t, root.WriteFile("truncated_crc.wal", truncated, 0o600))

		file, err := root.OpenFile("truncated_crc.wal", os.O_RDONLY, 0o600)
		require.NoError(t, err)
		defer func() {
			_ = file.Close()
		}()

		var replayedCount int
		err = Replay(
			file,
			func(_ string, _ dns.RRSets) { replayedCount++ },
			func(_ string) { replayedCount++ },
		)

		require.ErrorIs(t, err, ErrTruncated)
		assert.Equal(t, 1, replayedCount)
	})

	t.Run("TruncatedDeleteFrame", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		buf.WriteByte(OpDelete)
		buf.WriteByte(0x00) // Truncated length header

		err := Replay(&buf, func(string, dns.RRSets) {}, func(string) {})
		require.ErrorIs(t, err, ErrTruncated)
	})
}

func TestWAL_DataIntegrity(t *testing.T) {
	t.Parallel()

	t.Run("CorruptedPayloadMiddleBitFlip", func(t *testing.T) {
		t.Parallel()
		tempDir := t.TempDir()
		root, err := os.OpenRoot(tempDir)
		require.NoError(t, err)
		defer func() { _ = root.Close() }()

		writeTestRecords(t, root, "corrupted_payload.wal")

		data, err := root.ReadFile("corrupted_payload.wal")
		require.NoError(t, err)

		data[len(data)-8] ^= 0xFF
		require.NoError(t, root.WriteFile("corrupted_payload.wal", data, 0o600))

		file, err := root.OpenFile("corrupted_payload.wal", os.O_RDONLY, 0o600)
		require.NoError(t, err)
		defer func() {
			_ = file.Close()
		}()

		var replayedCount int
		err = Replay(
			file,
			func(_ string, _ dns.RRSets) { replayedCount++ },
			func(_ string) { replayedCount++ },
		)

		require.ErrorIs(t, err, ErrCorruptedData)
		assert.Equal(t, 1, replayedCount)
	})

	t.Run("InvalidOpcode", func(t *testing.T) {
		t.Parallel()
		file := createTempFile(t)

		_, err := file.Write([]byte{0xFF})
		require.NoError(t, err)

		_, err = file.Seek(0, 0)
		require.NoError(t, err)

		err = Replay(file, func(string, dns.RRSets) {}, func(string) {})
		require.ErrorIs(t, err, ErrInvalidOpcode)
	})

	t.Run("DeleteMalformedDomainLength", func(t *testing.T) {
		t.Parallel()
		for _, length := range []uint16{0, codec.MaxDomainLen + 1} {
			var buf bytes.Buffer
			buf.WriteByte(OpDelete)
			var lenBytes [2]byte
			binary.BigEndian.PutUint16(lenBytes[:], length)
			buf.Write(lenBytes[:])

			err := Replay(&buf, func(string, dns.RRSets) {}, func(string) {})
			require.ErrorIs(t, err, ErrCorruptedData)
		}
	})
}

func createTempFile(t *testing.T) *os.File {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	file, err := root.OpenFile("test.wal", os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = file.Close()
		_ = root.Close()
	})
	return file
}

func writeTestRecords(t *testing.T, root *os.Root, name string) {
	t.Helper()
	file, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	defer func() {
		_ = file.Close()
	}()

	w := NewWriter(file)
	r1, _ := dns.PackRData(dns.TypeA, "1.1.1.1")
	records := dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{r1}}}

	err = w.AppendUpsert("first.com", records)
	require.NoError(t, err)

	err = w.AppendUpsert("second.com", records)
	require.NoError(t, err)

	err = w.Flush()
	require.NoError(t, err)
}
