// Copyright 2026 Andrea Oliveti
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package radix

import (
	"errors"
	"sync"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTree_Len validates O(1) active domain counting across CRUD operations and concurrency.
func TestTree_Len(t *testing.T) {
	t.Parallel()

	t.Run("BasicCountingAndENT", func(t *testing.T) {
		t.Parallel()

		tree := New()
		assert.Equal(t, 0, tree.Len())

		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		assert.Equal(t, 1, tree.Len())

		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "txt")}}})
		assert.Equal(t, 1, tree.Len())

		tree.Upsert("sub.ent.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})
		assert.Equal(t, 2, tree.Len())

		tree.DeleteDomain("example.com")
		assert.Equal(t, 1, tree.Len())

		tree.DeleteDomain("missing.com")
		assert.Equal(t, 1, tree.Len())

		tree.DeleteDomain("sub.ent.example.com")
		assert.Equal(t, 0, tree.Len())
	})

	t.Run("EmptyUpsertDecrement", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1"), dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})
		assert.Equal(t, 1, tree.Len())

		// Submitting an empty slice to an active domain must decrement the counter
		tree.Upsert("example.com", dns.RRSets{})
		assert.Equal(t, 0, tree.Len())
	})

	t.Run("ReloadZoneCountConsistency", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("old.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		assert.Equal(t, 1, tree.Len())

		err := tree.ReloadZone(func(onRecord func(domain string, records dns.RRSets)) error {
			onRecord("new1.com", dns.RRSets{
				{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}},
				{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "txt")}},
			})
			onRecord("new2.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.2")}}})
			return nil
		})

		require.NoError(t, err)
		assert.Equal(t, 2, tree.Len())

		errSimulated := errors.New("loader failed")
		err = tree.ReloadZone(func(onRecord func(domain string, records dns.RRSets)) error {
			onRecord("abort.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "0.0.0.0")}}})
			return errSimulated
		})

		require.ErrorIs(t, err, errSimulated)
		assert.Equal(t, 2, tree.Len())
	})

	t.Run("ConcurrentCountingStress", func(t *testing.T) {
		t.Parallel()

		tree := New()
		var wg sync.WaitGroup
		startCh := make(chan struct{})

		for range 50 {
			wg.Go(func() {
				<-startCh
				for i := range 100 {
					tree.Upsert("shared.com", dns.RRSets{{Type: dns.TypeA, TTL: 60, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
					if i%2 == 0 {
						tree.DeleteDomain("shared.com")
					}
				}
			})
		}

		close(startCh)
		wg.Wait()

		walkCount := 0
		for range tree.Walk() {
			walkCount++
		}
		assert.Equal(t, walkCount, tree.Len())
	})
}

// TestTree_InternalMechanics validates structural, concurrency, and performance internals.
func TestTree_InternalMechanics(t *testing.T) {
	t.Parallel()

	t.Run("EmptyNonTerminalTraversal", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("parent.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		tree.Upsert("deep.parent.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})

		// Removing the parent domain but retaining the structural node for the child
		tree.DeleteDomain("parent.example.com")

		resParent := tree.Resolve("parent.example.com", dns.TypeA)
		// parent.example.com is an ENT after deletion: deep.parent.example.com still exists.
		assert.Equal(t, dns.RCodeSuccess, resParent.RCode) // NODATA: ENT, not NXDOMAIN

		resDeep := tree.Resolve("deep.parent.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, resDeep.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "2.2.2.2"), resDeep.Answer.RData[0])
	})

	t.Run("BinarySearchEdgeThreshold", func(t *testing.T) {
		t.Parallel()

		tree := New()

		for i := byte('a'); i <= byte('z'); i++ {
			domain := string(i) + ".example.com"
			tree.Upsert(domain, dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "127.0.0.1")}}})
		}

		res := tree.Resolve("m.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "127.0.0.1"), res.Answer.RData[0])

		resMissing := tree.Resolve("1.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resMissing.RCode)
	})

	t.Run("ConcurrencyStress", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("stress.com", dns.RRSets{{Type: dns.TypeA, TTL: 60, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		var wg sync.WaitGroup
		startCh := make(chan struct{})

		wg.Go(func() {
			<-startCh
			for range 1000 {
				tree.Upsert("stress.com", dns.RRSets{{Type: dns.TypeA, TTL: 60, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.2")}}})
				tree.Upsert("another.com", dns.RRSets{{Type: dns.TypeA, TTL: 60, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1"), dns.MustPackRData(dns.TypeA, "10.0.0.2")}}})
				tree.DeleteDomain("another.com")
				tree.Upsert("domain.com", dns.RRSets{{Type: dns.TypeA, TTL: 60, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.3")}}})
				tree.DeleteDomain("domain.com")
			}
		})

		for range 10 {
			wg.Go(func() {
				<-startCh
				for range 1000 {
					res := tree.Resolve("stress.com", dns.TypeA)
					if res.RCode == dns.RCodeSuccess {
						assert.NotEmpty(t, res.Answer.RData[0])
					}
				}
			})
		}

		close(startCh)
		wg.Wait()
	})
}
