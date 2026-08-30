// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snapshot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/codec"
	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
)

func buildSnapshotWithRecords(t *testing.T, tree *radix.Tree) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, Save(&buf, tree))
	return buf.Bytes()
}

func corruptByteAt(t *testing.T, data []byte, offset int, v byte) []byte {
	t.Helper()
	require.Greater(t, len(data), offset, "snapshot too short to corrupt at offset %d", offset)
	corrupted := make([]byte, len(data))
	copy(corrupted, data)
	corrupted[offset] = v
	return corrupted
}

func TestSnapshot_Lifecycle(t *testing.T) {
	t.Parallel()

	t.Run("SuccessRoundTrip", func(t *testing.T) {
		t.Parallel()
		originalTree := radix.New()
		originalTree.Upsert("example.com", dns.RRSets{
			{Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 86400, RData: [][]byte{dns.MustPackRData(dns.TypeSOA, "ns1.example.com. admin.example.com. 2026081200 7200 3600 1209600 3600")}},
			{Type: dns.TypeNS, Class: dns.ClassIN, TTL: 86400, RData: [][]byte{dns.MustPackRData(dns.TypeNS, "ns1.example.com."), dns.MustPackRData(dns.TypeNS, "ns2.example.com.")}},
			{Type: dns.TypeMX, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeMX, "10 mail.example.com")}},
		})
		originalTree.Upsert("www.example.com", dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.168.1.1")}},
			{Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeAAAA, "2001:db8::1")}},
		})
		originalTree.Upsert("*.example.com", dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 60, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}},
		})
		originalTree.Upsert("service._tcp.sub.example.com", dns.RRSets{
			{Type: dns.TypeSRV, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeSRV, "0 5 5060 sip.example.com")}},
			{Type: dns.TypeCAA, Class: dns.ClassIN, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeCAA, `0 issue "letsencrypt.org"`)}},
		})

		var buf bytes.Buffer
		err := Save(&buf, originalTree)
		require.NoError(t, err)

		restoredTree := radix.New()
		err = restoredTree.ReloadZone(func(onRecord func(string, dns.RRSets)) error {
			return Load(&buf, onRecord)
		})
		require.NoError(t, err)

		originalWalk := maps.Collect(originalTree.Walk())
		restoredWalk := maps.Collect(restoredTree.Walk())

		require.Equal(t, len(originalWalk), len(restoredWalk))
		assert.Equal(t, originalWalk, restoredWalk)
	})

	t.Run("LargeDatasetRoundTrip", func(t *testing.T) {
		t.Parallel()
		tree := radix.New()
		r1, err := dns.PackRData(dns.TypeA, "192.168.1.1")
		require.NoError(t, err)
		r2, err := dns.PackRData(dns.TypeAAAA, "2001:db8::1")
		require.NoError(t, err)

		records := dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{r1}},
			{Type: dns.TypeAAAA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{r2}},
		}

		const totalRecords = 5000
		for i := range totalRecords {
			domain := fmt.Sprintf("node-%d.zone-%d.example.com", i%100, i/100)
			tree.Upsert(domain, records)
		}

		var buf bytes.Buffer
		require.NoError(t, Save(&buf, tree))

		restoredTree := radix.New()
		err = restoredTree.ReloadZone(func(onRecord func(string, dns.RRSets)) error {
			return Load(&buf, onRecord)
		})
		require.NoError(t, err)

		assert.Equal(t, tree.Len(), restoredTree.Len())
	})

	t.Run("EmptyTree", func(t *testing.T) {
		t.Parallel()
		originalTree := radix.New()
		var buf bytes.Buffer

		err := Save(&buf, originalTree)
		require.NoError(t, err)

		restoredTree := radix.New()
		err = restoredTree.ReloadZone(func(onRecord func(string, dns.RRSets)) error {
			return Load(&buf, onRecord)
		})
		require.NoError(t, err)

		restoredWalk := maps.Collect(restoredTree.Walk())
		assert.Empty(t, restoredWalk)
	})
}

func TestSnapshot_CapacityBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		setup func(tree *radix.Tree)
		name  string
	}{
		{
			name: "DomainLengthExceededInTree",
			setup: func(tree *radix.Tree) {
				oversizedDomain := strings.Repeat("a", codec.MaxDomainLen+1)
				records := dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}}
				tree.Upsert(oversizedDomain, records)
			},
		},
		{
			name: "RecordsCountExceededInTree",
			setup: func(tree *radix.Tree) {
				oversizedRecords := make(dns.RRSets, codec.MaxRecordsPerDomain+1)
				for i := range oversizedRecords {
					oversizedRecords[i] = dns.RRSet{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}
				}
				tree.Upsert("example.com", oversizedRecords)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tree := radix.New()
			tc.setup(tree)

			var buf bytes.Buffer
			err := Save(&buf, tree)
			require.ErrorIs(t, err, ErrCapacityExceeded)
		})
	}
}

func TestSnapshot_ValidationAndIntegrity(t *testing.T) {
	t.Parallel()

	t.Run("TruncatedStream", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		err := Load(&buf, func(_ string, _ dns.RRSets) {})
		require.Error(t, err)
	})

	t.Run("InvalidMagicHeader", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		buf.WriteString("BAD!")
		buf.WriteByte(snapVersion)
		_ = binary.Write(&buf, binary.BigEndian, uint32(0))
		_ = binary.Write(&buf, binary.BigEndian, uint32(0))

		err := Load(&buf, func(_ string, _ dns.RRSets) {})
		assert.ErrorIs(t, err, ErrInvalidMagic)
	})

	t.Run("UnsupportedVersion", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		buf.WriteString(snapMagic)
		buf.WriteByte(0xFF)
		_ = binary.Write(&buf, binary.BigEndian, uint32(0))
		_ = binary.Write(&buf, binary.BigEndian, uint32(0))

		err := Load(&buf, func(_ string, _ dns.RRSets) {})
		assert.ErrorIs(t, err, ErrUnsupportedVer)
	})

	t.Run("ChecksumFailure", func(t *testing.T) {
		t.Parallel()
		tree := radix.New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		data := buildSnapshotWithRecords(t, tree)
		tampered := corruptByteAt(t, data, len(data)-1, data[len(data)-1]^0xFF)

		err := Load(bytes.NewBuffer(tampered), func(_ string, _ dns.RRSets) {})
		assert.ErrorIs(t, err, ErrChecksumFailed)
	})

	t.Run("HeaderDeclaresMoreDomainsThanPresent", func(t *testing.T) {
		t.Parallel()
		tree := radix.New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		data := buildSnapshotWithRecords(t, tree)
		corrupted := make([]byte, len(data))
		copy(corrupted, data)
		binary.BigEndian.PutUint32(corrupted[5:9], 5)

		err := Load(bytes.NewBuffer(corrupted), func(_ string, _ dns.RRSets) {})
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrChecksumFailed))
	})

	t.Run("HeaderDeclaresFewerDomainsThanPresent", func(t *testing.T) {
		t.Parallel()
		tree := radix.New()
		tree.Upsert("one.example.com", dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		tree.Upsert("two.example.com", dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})

		data := buildSnapshotWithRecords(t, tree)
		corrupted := make([]byte, len(data))
		copy(corrupted, data)
		binary.BigEndian.PutUint32(corrupted[5:9], 1)

		err := Load(bytes.NewBuffer(corrupted), func(_ string, _ dns.RRSets) {})
		require.ErrorIs(t, err, ErrChecksumFailed)
	})

	t.Run("TruncatedStreamPhases", func(t *testing.T) {
		t.Parallel()
		tree := radix.New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		var buf bytes.Buffer
		err := Save(&buf, tree)
		require.NoError(t, err)

		fullData := buf.Bytes()

		tests := []struct {
			name   string
			offset int
		}{
			{"PartialMagicHeader", 2},
			{"MissingVersion", 4},
			{"PartialDomainCount", 6},
			{"PartialBodyLength", 10},
			{"PartialChecksum", len(fullData) - 2},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				truncatedBuf := bytes.NewBuffer(fullData[:tc.offset])
				err := Load(truncatedBuf, func(_ string, _ dns.RRSets) {})
				assert.Error(t, err)
			})
		}
	})

	t.Run("CorruptedCompressedStream", func(t *testing.T) {
		t.Parallel()
		tree := radix.New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		data := buildSnapshotWithRecords(t, tree)
		corrupted := corruptByteAt(t, data, headerSize+2, 0xFF)

		err := Load(bytes.NewBuffer(corrupted), func(_ string, _ dns.RRSets) {})
		require.Error(t, err)
	})
}

func TestCleanStaleTemp_RemovesStaleFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	stale1 := filepath.Join(tmpDir, "state-snap-998877.tmp")
	stale2 := filepath.Join(tmpDir, "state-snap-001122.tmp")
	validSnap := filepath.Join(tmpDir, "state.snap")
	validWal := filepath.Join(tmpDir, "mutations.wal")
	unrelatedTmp := filepath.Join(tmpDir, "other.tmp")

	require.NoError(t, os.WriteFile(stale1, []byte("stale1"), 0o600))
	require.NoError(t, os.WriteFile(stale2, []byte("stale2"), 0o600))
	require.NoError(t, os.WriteFile(validSnap, []byte("valid-snap"), 0o600))
	require.NoError(t, os.WriteFile(validWal, []byte("valid-wal"), 0o600))
	require.NoError(t, os.WriteFile(unrelatedTmp, []byte("other-tmp"), 0o600))

	CleanStaleTemp(tmpDir)

	assert.NoFileExists(t, stale1, "stale snapshot temp file 1 must be deleted")
	assert.NoFileExists(t, stale2, "stale snapshot temp file 2 must be deleted")
	assert.FileExists(t, validSnap, "valid state.snap must be preserved")
	assert.FileExists(t, validWal, "valid mutations.wal must be preserved")
	assert.FileExists(t, unrelatedTmp, "unrelated files must not be touched")

	// Call on nonexistent directory (should not panic)
	CleanStaleTemp(filepath.Join(tmpDir, "nonexistent-sub"))
}

func TestReadChecksum_Validity(t *testing.T) {
	t.Parallel()

	tree := radix.New()
	tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

	var buf bytes.Buffer
	require.NoError(t, Save(&buf, tree))

	data := buf.Bytes()
	r := bytes.NewReader(data)

	// Valid snapshot checksum
	checksum, err := ReadChecksum(r, int64(len(data)))
	require.NoError(t, err)
	assert.NotZero(t, checksum)

	// Short size (< checksumSize)
	_, err = ReadChecksum(r, 2)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)

	// Invalid offset / truncated read
	_, err = ReadChecksum(r, 999999)
	require.Error(t, err)
}

func TestCreateTemp_FileCreation(t *testing.T) {
	t.Parallel()

	t.Run("WildcardPattern", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		root, err := os.OpenRoot(tmpDir)
		require.NoError(t, err)
		defer func() { _ = root.Close() }()

		f, name, createErr := CreateTemp(root, "state-snap-*.tmp")
		require.NoError(t, createErr)
		require.NotNil(t, f)
		assert.True(t, strings.HasPrefix(name, "state-snap-"))
		assert.True(t, strings.HasSuffix(name, ".tmp"))

		_, writeErr := f.WriteString("temp-data")
		require.NoError(t, writeErr)
		require.NoError(t, f.Close())

		// Verify file exists in root and clean it up
		stat, statErr := root.Stat(name)
		require.NoError(t, statErr)
		assert.Equal(t, int64(9), stat.Size())
		require.NoError(t, root.Remove(name))
	})

	t.Run("NonWildcardPattern", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		root, err := os.OpenRoot(tmpDir)
		require.NoError(t, err)
		defer func() { _ = root.Close() }()

		f, name, createErr := CreateTemp(root, "fixed-prefix")
		require.NoError(t, createErr)
		require.NotNil(t, f)
		assert.True(t, strings.HasPrefix(name, "fixed-prefix"))
		require.NoError(t, f.Close())
		require.NoError(t, root.Remove(name))
	})

	t.Run("PathSeparatorError", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		root, err := os.OpenRoot(tmpDir)
		require.NoError(t, err)
		defer func() { _ = root.Close() }()

		_, _, createErr := CreateTemp(root, "sub/dir-*.tmp")
		require.Error(t, createErr)
	})
}
