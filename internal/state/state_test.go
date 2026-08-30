// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package state

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
)

type testMetricsCollector struct {
	hits    atomic.Int64
	misses  atomic.Int64
	domains atomic.Int64
}

func (m *testMetricsCollector) IncCacheHit()        { m.hits.Add(1) }
func (m *testMetricsCollector) IncCacheMiss()       { m.misses.Add(1) }
func (m *testMetricsCollector) SetDomains(c int)    { m.domains.Store(int64(c)) }
func (m *testMetricsCollector) SetCacheEntries(int) {}

func TestState_LifecycleAndSwap(t *testing.T) {
	t.Parallel()

	m := &testMetricsCollector{}
	st := New(0, WithMetrics(m)) // Test default capacity fallback
	assert.Equal(t, 0, st.Len())

	newTree := radix.New()
	newTree.Upsert("example.com", dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "1.2.3.4")})

	st.Swap(newTree)
	assert.Equal(t, 1, st.Len())
	assert.Equal(t, int64(1), m.domains.Load())

	// Cache miss on first lookup
	res := st.Resolve("example.com", dns.TypeA)
	require.Equal(t, dns.RCodeSuccess, res.RCode)
	assert.Equal(t, dns.MustPackRData(dns.TypeA, "1.2.3.4"), res.Answer.RData[0])
	assert.Equal(t, int64(1), m.misses.Load())

	// Cache hit on second lookup
	resCached := st.Resolve("example.com", dns.TypeA)
	require.Equal(t, dns.RCodeSuccess, resCached.RCode)
	assert.Equal(t, int64(1), m.hits.Load())

	st.Update(func(target *radix.Tree) {
		target.Upsert("sub.example.com", dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "5.6.7.8")})
	})
	assert.Equal(t, 2, st.Len())
	assert.Equal(t, int64(2), m.domains.Load())

	treeSnap := st.SnapshotTree()
	assert.Equal(t, 2, treeSnap.Len())

	st.ClearCache()
}

func TestState_QueryViews(t *testing.T) {
	t.Parallel()

	st := New(1024)
	tree := radix.New()
	tree.Upsert("alpha.example.com", dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "1.1.1.1")})
	tree.Upsert("beta.example.com", dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "2.2.2.2")})
	tree.Upsert("gamma.example.com", dns.RRSets{dns.NewRRSet(dns.TypeA, 300, "3.3.3.3")})

	st.Swap(tree)

	t.Run("Get", func(t *testing.T) {
		t.Parallel()
		rrs, ok := st.Get("alpha.example.com")
		require.True(t, ok)
		assert.Len(t, rrs, 1)

		_, okMissing := st.Get("missing.com")
		assert.False(t, okMissing)
	})

	t.Run("Walk", func(t *testing.T) {
		t.Parallel()
		var domains []string
		for d := range st.Walk() {
			domains = append(domains, d)
		}
		assert.Len(t, domains, 3)
	})

	t.Run("Seek", func(t *testing.T) {
		t.Parallel()
		var afterAlpha []string
		for d := range st.Seek("alpha.example.com") {
			afterAlpha = append(afterAlpha, d)
		}
		assert.Len(t, afterAlpha, 2)
	})

	t.Run("Search", func(t *testing.T) {
		t.Parallel()
		var matches []string
		for d := range st.Search("beta") {
			matches = append(matches, d)
		}
		assert.Equal(t, []string{"beta.example.com"}, matches)
	})
}

func TestState_Resolve(t *testing.T) {
	t.Parallel()

	st := New(1024)
	tree := radix.New()
	tree.Upsert("example.com", dns.RRSets{
		dns.NewRRSet(dns.TypeA, 300, "1.2.3.4"),
		dns.NewRRSet(dns.TypeTXT, 300, "v=spf1 -all"),
	})
	tree.Upsert("cname.example.com", dns.RRSets{
		dns.NewRRSet(dns.TypeCNAME, 300, "example.com."),
	})
	tree.Upsert("*.wild.example.com", dns.RRSets{
		dns.NewRRSet(dns.TypeA, 300, "9.9.9.9"),
	})

	st.Swap(tree)

	t.Run("DirectHitAndCacheMissThenHit", func(t *testing.T) {
		t.Parallel()
		res1 := st.Resolve("example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res1.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "1.2.3.4"), res1.Answer.RData[0])

		res2 := st.Resolve("example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res2.RCode)
		assert.Equal(t, res1.Answer, res2.Answer)
	})

	t.Run("CaseInsensitiveLookupAndCache", func(t *testing.T) {
		t.Parallel()
		resUpper := st.Resolve("ExAmPlE.CoM", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, resUpper.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "1.2.3.4"), resUpper.Answer.RData[0])

		resUpperCached := st.Resolve("EXAMPLE.COM", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, resUpperCached.RCode)
	})

	t.Run("CNAMETransparency", func(t *testing.T) {
		t.Parallel()
		res := st.Resolve("cname.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.TypeCNAME, res.Answer.Type)
	})

	t.Run("WildcardMatch", func(t *testing.T) {
		t.Parallel()
		res := st.Resolve("foo.wild.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "9.9.9.9"), res.Answer.RData[0])
	})

	t.Run("NXDOMAIN", func(t *testing.T) {
		t.Parallel()
		res := st.Resolve("nonexistent.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, res.RCode)
	})
}
