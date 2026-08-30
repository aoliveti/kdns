// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestCache_CRUD(t *testing.T) {
	t.Parallel()

	t.Run("InitializationMinimumCapacity", func(t *testing.T) {
		t.Parallel()

		c := New(10)

		for i := range shardCount {
			s := &c.shards[i]
			assert.Equal(t, 1, s.capacity)
		}
	})

	t.Run("SetAndGet", func(t *testing.T) {
		t.Parallel()

		c := New(1024)
		assert.Equal(t, 0, c.Len())

		key := Key{Name: "example.com", Type: dns.TypeA}
		wireA, err := dns.PackRData(dns.TypeA, "192.168.1.1")
		require.NoError(t, err)

		record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}
		c.Set(key, record, 5*time.Minute)

		assert.Equal(t, 1, c.Len())
		got, found := c.Get(key)
		require.True(t, found)
		assert.Equal(t, dns.TypeA, got.Type)
		assert.Equal(t, uint32(300), got.TTL)
		assert.Equal(t, wireA, got.RData[0])

		c.Clear()
		assert.Equal(t, 0, c.Len())
	})

	t.Run("OverwriteExisting_HeadAndNonHead", func(t *testing.T) {
		t.Parallel()

		c := New(shardCount * 4)
		targetShard := &c.shards[0]

		var keys []Key
		for i := 0; len(keys) < 2; i++ {
			k := Key{Name: fmt.Sprintf("ovw-%d.com", i), Type: dns.TypeA}
			if c.getShard(k) == targetShard {
				keys = append(keys, k)
			}
		}

		wire1, err := dns.PackRData(dns.TypeA, "192.168.1.1")
		require.NoError(t, err)
		wire2, err := dns.PackRData(dns.TypeA, "192.168.1.2")
		require.NoError(t, err)
		wireUpdated, err := dns.PackRData(dns.TypeA, "10.0.0.99")
		require.NoError(t, err)

		// Shard state: [keys[1] (head), keys[0] (tail)]
		c.Set(keys[0], dns.RRSet{Type: dns.TypeA, RData: [][]byte{wire1}}, 5*time.Minute)
		c.Set(keys[1], dns.RRSet{Type: dns.TypeA, RData: [][]byte{wire2}}, 5*time.Minute)

		// Overwrite keys[0] (tail): must update value and promote to head -> [keys[0] (head), keys[1] (tail)]
		c.Set(keys[0], dns.RRSet{Type: dns.TypeA, RData: [][]byte{wireUpdated}}, 10*time.Minute)

		got0, found0 := c.Get(keys[0])
		require.True(t, found0)
		assert.Equal(t, wireUpdated, got0.RData[0])

		targetShard.mu.Lock()
		assert.Equal(t, keys[0], targetShard.head.next.key)
		assert.Equal(t, keys[1], targetShard.tail.prev.key)
		targetShard.mu.Unlock()
	})

	t.Run("TypeIsolation", func(t *testing.T) {
		t.Parallel()

		c := New(1024)
		keyA := Key{Name: "example.com", Type: dns.TypeA}
		keyAAAA := Key{Name: "example.com", Type: dns.TypeAAAA}
		keyTXT := Key{Name: "example.com", Type: dns.TypeTXT}

		wireA, err := dns.PackRData(dns.TypeA, "192.0.2.1")
		require.NoError(t, err)
		wireAAAA, err := dns.PackRData(dns.TypeAAAA, "2001:db8::1")
		require.NoError(t, err)
		wireTXT, err := dns.PackRData(dns.TypeTXT, "v=spf1 -all")
		require.NoError(t, err)

		c.Set(keyA, dns.RRSet{Type: dns.TypeA, RData: [][]byte{wireA}}, time.Minute)
		c.Set(keyAAAA, dns.RRSet{Type: dns.TypeAAAA, RData: [][]byte{wireAAAA}}, time.Minute)
		c.Set(keyTXT, dns.RRSet{Type: dns.TypeTXT, RData: [][]byte{wireTXT}}, time.Minute)

		gotA, foundA := c.Get(keyA)
		require.True(t, foundA)
		assert.Equal(t, wireA, gotA.RData[0])

		gotAAAA, foundAAAA := c.Get(keyAAAA)
		require.True(t, foundAAAA)
		assert.Equal(t, wireAAAA, gotAAAA.RData[0])

		gotTXT, foundTXT := c.Get(keyTXT)
		require.True(t, foundTXT)
		assert.Equal(t, wireTXT, gotTXT.RData[0])
	})

	t.Run("Delete", func(t *testing.T) {
		t.Parallel()

		c := New(1024)
		key := Key{Name: "delete.com", Type: dns.TypeA}
		missingKey := Key{Name: "missing.com", Type: dns.TypeA}

		c.Set(key, dns.RRSet{}, 5*time.Minute)

		c.Delete(key)
		c.Delete(missingKey)

		_, found := c.Get(key)
		assert.False(t, found)

		_, foundMissing := c.Get(missingKey)
		assert.False(t, foundMissing)
	})

	t.Run("ClearAndReuse", func(t *testing.T) {
		t.Parallel()

		c := New(1024)
		key1 := Key{Name: "clear1.com", Type: dns.TypeA}
		key2 := Key{Name: "clear2.com", Type: dns.TypeAAAA}

		c.Set(key1, dns.RRSet{Type: dns.TypeA}, 5*time.Minute)
		c.Set(key2, dns.RRSet{Type: dns.TypeAAAA}, 5*time.Minute)

		c.Clear()

		_, found1 := c.Get(key1)
		assert.False(t, found1)
		_, found2 := c.Get(key2)
		assert.False(t, found2)

		for i := range shardCount {
			s := &c.shards[i]
			s.mu.Lock()
			assert.Empty(t, s.items)
			assert.Equal(t, s.tail, s.head.next)
			assert.Equal(t, s.head, s.tail.prev)
			s.mu.Unlock()
		}

		c.Set(key1, dns.RRSet{Type: dns.TypeA}, 5*time.Minute)
		_, foundAfterClear := c.Get(key1)
		assert.True(t, foundAfterClear)
	})
}

func TestCache_TTL(t *testing.T) {
	t.Parallel()

	t.Run("LazyExpiration", func(t *testing.T) {
		t.Parallel()

		c := New(1024)
		key := Key{Name: "ephemeral.com", Type: dns.TypeA}
		wireA, err := dns.PackRData(dns.TypeA, "10.0.0.1")
		require.NoError(t, err)

		c.Set(key, dns.RRSet{Type: dns.TypeA, RData: [][]byte{wireA}}, 20*time.Millisecond)

		got, found := c.Get(key)
		require.True(t, found)
		assert.Equal(t, wireA, got.RData[0])

		time.Sleep(30 * time.Millisecond)

		_, foundExpired := c.Get(key)
		assert.False(t, foundExpired)

		s := c.getShard(key)
		s.mu.Lock()
		assert.Empty(t, s.items)
		s.mu.Unlock()
	})

	t.Run("NegativeOrZeroTTL", func(t *testing.T) {
		t.Parallel()

		c := New(1024)
		keyZero := Key{Name: "zero-ttl.com", Type: dns.TypeA}
		keyNeg := Key{Name: "neg-ttl.com", Type: dns.TypeA}

		c.Set(keyZero, dns.RRSet{}, 0)
		c.Set(keyNeg, dns.RRSet{}, -1*time.Second)

		_, foundZero := c.Get(keyZero)
		assert.False(t, foundZero)

		_, foundNeg := c.Get(keyNeg)
		assert.False(t, foundNeg)
	})

	t.Run("EmptyNegativeRRSet", func(t *testing.T) {
		t.Parallel()

		c := New(1024)
		key := Key{Name: "nodata.example.com", Type: dns.TypeAAAA}

		c.Set(key, dns.RRSet{Type: dns.TypeAAAA, TTL: 60, RData: nil}, time.Minute)

		got, found := c.Get(key)
		require.True(t, found)
		assert.Equal(t, dns.TypeAAAA, got.Type)
		assert.Empty(t, got.RData)
	})
}

func TestCache_LRU(t *testing.T) {
	t.Parallel()

	t.Run("EvictionOrderWithPromotion", func(t *testing.T) {
		t.Parallel()

		c := New(shardCount * 2)
		targetShard := &c.shards[0]

		var keys []Key
		for i := 0; len(keys) < 3; i++ {
			k := Key{Name: fmt.Sprintf("lru-%d.com", i), Type: dns.TypeA}
			if c.getShard(k) == targetShard {
				keys = append(keys, k)
			}
		}

		c.Set(keys[0], dns.RRSet{Type: dns.TypeA}, time.Hour)
		c.Set(keys[1], dns.RRSet{Type: dns.TypeA}, time.Hour)

		// Promote keys[0] to head
		_, found := c.Get(keys[0])
		require.True(t, found)

		// Saturated insert triggers eviction of least recently used tail (keys[1])
		c.Set(keys[2], dns.RRSet{Type: dns.TypeA}, time.Hour)

		_, foundPromoted := c.Get(keys[0])
		assert.True(t, foundPromoted)

		_, foundEvicted := c.Get(keys[1])
		assert.False(t, foundEvicted)

		_, foundNewest := c.Get(keys[2])
		assert.True(t, foundNewest)
	})

	t.Run("HotKeyFastPathIntegrity", func(t *testing.T) {
		t.Parallel()

		c := New(1024)
		key := Key{Name: "hotkey.example.com", Type: dns.TypeA}
		wireA, err := dns.PackRData(dns.TypeA, "1.1.1.1")
		require.NoError(t, err)

		c.Set(key, dns.RRSet{Type: dns.TypeA, RData: [][]byte{wireA}}, time.Hour)

		// Repeated Get calls on the head element must preserve sentinel link integrity
		for range 10 {
			got, found := c.Get(key)
			require.True(t, found)
			assert.Equal(t, wireA, got.RData[0])
		}

		s := c.getShard(key)
		s.mu.Lock()
		assert.Equal(t, key, s.head.next.key)
		assert.Equal(t, key, s.tail.prev.key)
		assert.Equal(t, s.head, s.head.next.prev)
		assert.Equal(t, s.tail, s.tail.prev.next)
		s.mu.Unlock()
	})

	t.Run("TotalCapacityEnforcement", func(t *testing.T) {
		t.Parallel()

		c := New(256)
		wireA, err := dns.PackRData(dns.TypeA, "127.0.0.1")
		require.NoError(t, err)
		record := dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}}

		for i := range 5000 {
			key := Key{Name: fmt.Sprintf("host-%d.com", i), Type: dns.TypeA}
			c.Set(key, record, 5*time.Minute)
		}

		totalItems := 0
		for i := range shardCount {
			s := &c.shards[i]
			s.mu.Lock()
			totalItems += len(s.items)
			assert.LessOrEqual(t, len(s.items), s.capacity)
			s.mu.Unlock()
		}

		assert.LessOrEqual(t, totalItems, 256)
	})
}

func TestCache_Concurrency(t *testing.T) {
	t.Run("ZeroAllocationShardRouting", func(t *testing.T) {
		c := New(1024)
		key := Key{Name: "zero-alloc.example.com", Type: dns.TypeAAAA}

		allocs := testing.AllocsPerRun(1000, func() {
			_ = c.getShard(key)
		})

		assert.Equal(t, float64(0), allocs)
	})

	t.Run("ZeroAllocationSetSteadyState", func(t *testing.T) {
		c := New(shardCount)
		targetShard := &c.shards[0]
		record := dns.RRSet{Type: dns.TypeA}

		var keys []Key
		for i := 0; len(keys) < 100; i++ {
			k := Key{Name: fmt.Sprintf("steady-%d.com", i), Type: dns.TypeA}
			if c.getShard(k) == targetShard {
				keys = append(keys, k)
			}
		}

		// Fill capacity (1 item per shard)
		c.Set(keys[0], record, time.Hour)

		// Subsequent Set operations recycle the tail entry in-place
		var idx int
		allocs := testing.AllocsPerRun(100, func() {
			idx++
			c.Set(keys[idx%len(keys)], record, time.Hour)
		})

		assert.Equal(t, float64(0), allocs)
	})

	t.Run("HighContentionStress", func(t *testing.T) {
		c := New(1024)
		var wg sync.WaitGroup

		wireA, err := dns.PackRData(dns.TypeA, "1.1.1.1")
		require.NoError(t, err)
		record := dns.RRSet{Type: dns.TypeA, RData: [][]byte{wireA}}

		for range 16 {
			wg.Go(func() {
				for j := range 500 {
					key := Key{Name: fmt.Sprintf("domain-%d.com", j%20), Type: dns.TypeA}
					switch {
					case j%3 == 0:
						c.Set(key, record, time.Minute)
					case j%7 == 0:
						c.Delete(key)
					default:
						c.Get(key)
					}
				}
			})
		}

		wg.Wait()
	})

	t.Run("ConcurrentExpiredReads", func(t *testing.T) {
		c := New(1024)
		key := Key{Name: "expire-stress.com", Type: dns.TypeA}
		wireA, err := dns.PackRData(dns.TypeA, "10.0.0.99")
		require.NoError(t, err)
		record := dns.RRSet{Type: dns.TypeA, RData: [][]byte{wireA}}

		c.Set(key, record, 10*time.Millisecond)
		time.Sleep(15 * time.Millisecond)

		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				_, _ = c.Get(key)
			})
		}
		wg.Wait()

		_, found := c.Get(key)
		assert.False(t, found)
	})
}
