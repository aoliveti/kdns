// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/state"
)

func TestStore_ConcurrencyAndRace(t *testing.T) {
	t.Parallel()

	st := state.New(1024)
	s, err := Open(t.TempDir(), st, WithLogger(discardLogger))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	domain := "race.example.com"
	initialRecords := dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}}}
	require.NoError(t, s.Upsert(domain, initialRecords))

	const (
		numWriters   = 4
		opsPerWriter = 50
	)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var wg sync.WaitGroup

	// Concurrent Readers
	for range 2 {
		wg.Go(func() {
			for ctx.Err() == nil {
				_ = st.Resolve(domain, dns.TypeA)
			}
		})
	}

	// Concurrent Writers
	var writersWg sync.WaitGroup
	for w := range numWriters {
		workerID := w
		writersWg.Go(func() {
			wireVal := dns.MustPackRData(dns.TypeA, "10.0.0.2")
			for i := range opsPerWriter {
				d := fmt.Sprintf("race-%d-%d.example.com", workerID, i)
				records := dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{wireVal}}}
				_ = s.Upsert(d, records)
				_ = s.DeleteDomain(d)
			}
		})
	}

	writersWg.Wait()
	cancel()
	wg.Wait()
}

func TestStore_GroupCommit_MassiveParallel(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	st := state.New(1024)
	s, err := Open(dir, st, WithCompactionThreshold(1_000_000), WithLogger(discardLogger))
	require.NoError(t, err)

	const (
		numWorkers     = 20
		itemsPerWorker = 100
		totalItems     = numWorkers * itemsPerWorker
	)

	var wg sync.WaitGroup
	for w := range numWorkers {
		workerID := w
		wg.Go(func() {
			wire, _ := dns.PackRData(dns.TypeA, "10.0.0.1")
			for i := range itemsPerWorker {
				domain := fmt.Sprintf("host-%d-%d.example.com", workerID, i)
				records := dns.RRSets{
					{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{wire}},
				}
				upsertErr := s.Upsert(domain, records)
				assert.NoError(t, upsertErr)
			}
		})
	}
	wg.Wait()

	assert.Equal(t, totalItems, st.Len())
	require.NoError(t, s.Close())
}

func TestStore_AutoIncrementSOA(t *testing.T) {
	t.Parallel()

	st := state.New(1024)
	s, err := Open(t.TempDir(), st, WithLogger(discardLogger))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	soaWire, err := dns.PackRData(dns.TypeSOA, "ns1.example.com admin.example.com 1 7200 3600 1209600 300")
	require.NoError(t, err)

	apexRecords := dns.RRSets{
		{Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{soaWire}},
	}
	require.NoError(t, s.Upsert("example.com", apexRecords))

	// Inserting child record should auto-increment apex SOA serial
	childWire := dns.MustPackRData(dns.TypeA, "192.0.2.1")
	childRecords := dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{childWire}},
	}
	require.NoError(t, s.Upsert("www.example.com", childRecords))

	rrs, ok := st.Get("example.com")
	require.True(t, ok)
	require.Len(t, rrs, 1)
	assert.Equal(t, dns.TypeSOA, rrs[0].Type)

	// Verify serial was incremented from 1 to 2
	updatedSOA := rrs[0].RData[0]
	assert.NotEqual(t, soaWire, updatedSOA)

	// Deleting child record should also auto-increment apex SOA serial
	require.NoError(t, s.DeleteDomain("www.example.com"))
	rrsAfterDel, ok := st.Get("example.com")
	require.True(t, ok)
	assert.NotEqual(t, updatedSOA, rrsAfterDel[0].RData[0])
}

func TestIncrementSOASerial_EdgeCases(t *testing.T) {
	t.Parallel()

	// Truncated / malformed data
	assert.Nil(t, incrementSOASerial(nil))
	assert.Equal(t, []byte{1, 2}, incrementSOASerial([]byte{1, 2}))

	// Valid domain name but truncated SOA timers (< 20 bytes after mname/rname)
	mnameWire := []byte{3, 'n', 's', '1', 0, 4, 'h', 'o', 's', 't', 0, 1, 2, 3} // Only 3 bytes of timers
	assert.Equal(t, mnameWire, incrementSOASerial(mnameWire))

	// Invalid label length (skipDomainName returns -1)
	invalidDomain := []byte{50, 'a', 'b'}
	assert.Equal(t, invalidDomain, incrementSOASerial(invalidDomain))
}

func TestStore_CommitBatch_EmptySliceGuard(t *testing.T) {
	t.Parallel()

	// Direct commitBatch empty slice guard
	st := state.New(10)
	s, err := Open(t.TempDir(), st, WithLogger(discardLogger))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	s.commitBatch(nil)
	s.commitBatch([]mutationOp{})
}

func TestStore_DrainMutations(t *testing.T) {
	t.Parallel()

	st := state.New(10)
	s, err := Open(t.TempDir(), st, WithLogger(discardLogger))
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	done := make(chan error, 1)
	s.mutationCh <- mutationOp{
		opType:  opUpsert,
		domain:  "drain.test.",
		records: dns.RRSets{{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{{1, 2, 3, 4}}}},
		done:    done,
	}
	s.drainMutations()
	require.NoError(t, <-done)

	rrs, ok := st.Get("drain.test.")
	require.True(t, ok)
	require.Len(t, rrs, 1)
}
