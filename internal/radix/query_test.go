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
	"maps"
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTree_Get_ControlPlane validates the control-plane Get method which returns
// all RRSets stored at an exact domain without wildcard synthesis or type filtering.
func TestTree_Get_ControlPlane(t *testing.T) {
	t.Parallel()

	t.Run("returns all record types for an existing domain", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}},
			{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "v=spf1 -all")}},
		})

		rrs, ok := tree.Get("example.com")
		require.True(t, ok)
		assert.Len(t, rrs, 2)
	})

	t.Run("absent domain returns false", func(t *testing.T) {
		t.Parallel()

		tree := New()

		rrs, ok := tree.Get("missing.example.com")
		assert.False(t, ok)
		assert.Nil(t, rrs)
	})

	t.Run("ENT node returns false", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("deep.ent.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		// ent.example.com exists structurally but has no records of its own.
		rrs, ok := tree.Get("ent.example.com")
		assert.False(t, ok)
		assert.Nil(t, rrs)
	})

	t.Run("wildcard node accessible by its literal name", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}}})

		// The control plane can read the wildcard node directly.
		rrs, ok := tree.Get("*.example.com")
		require.True(t, ok)
		assert.Equal(t, dns.TypeA, rrs[0].Type)
	})

	t.Run("no wildcard synthesis: non-existent name returns false", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}}})

		// Get does NOT apply wildcard synthesis.
		rrs, ok := tree.Get("foo.example.com")
		assert.False(t, ok)
		assert.Nil(t, rrs)
	})
}

// TestTree_SearchAndSeek validates the lock-free, zero-allocation algorithms used for the Control Plane API.
func TestTree_SearchAndSeek(t *testing.T) {
	t.Parallel()

	t.Run("Search_SubstringMatch", func(t *testing.T) {
		t.Parallel()

		tree := New()
		records := dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "127.0.0.1")}}}

		tree.Upsert("example.com", records)
		tree.Upsert("test.example.com", records)
		tree.Upsert("example.net", records)
		tree.Upsert("other.org", records)

		var results []string
		for domain := range tree.Search("test") {
			results = append(results, domain)
		}
		assert.Equal(t, []string{"test.example.com"}, results)

		results = nil
		for domain := range tree.Search("example") {
			results = append(results, domain)
		}
		assert.ElementsMatch(t, []string{"example.com", "test.example.com", "example.net"}, results)
	})

	t.Run("Search_EmptyTree", func(t *testing.T) {
		t.Parallel()

		tree := New()
		var results []string
		for domain := range tree.Search("test") {
			results = append(results, domain)
		}
		assert.Empty(t, results)
	})

	t.Run("Seek_Pagination", func(t *testing.T) {
		t.Parallel()

		tree := New()
		records := dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "127.0.0.1")}}}

		tree.Upsert("a.com", records)
		tree.Upsert("b.com", records)
		tree.Upsert("c.com", records)
		tree.Upsert("d.com", records)

		var results []string
		limit := 2
		for domain := range tree.Seek("b.com") {
			if limit == 0 {
				break
			}
			results = append(results, domain)
			limit--
		}

		assert.Equal(t, []string{"c.com", "d.com"}, results)
	})

	t.Run("Seek_FromBeginning", func(t *testing.T) {
		t.Parallel()

		tree := New()
		records := dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "127.0.0.1")}}}

		tree.Upsert("a.com", records)
		tree.Upsert("b.com", records)

		var results []string
		for domain := range tree.Seek("") {
			results = append(results, domain)
		}
		assert.Equal(t, []string{"a.com", "b.com"}, results)
	})

	t.Run("Seek_FromBeginning_WithLimit", func(t *testing.T) {
		t.Parallel()

		tree := New()
		records := dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "127.0.0.1")}}}

		tree.Upsert("a.com", records)
		tree.Upsert("b.com", records)
		tree.Upsert("c.com", records)
		tree.Upsert("d.com", records)

		var results []string
		limit := 2
		for domain := range tree.Seek("") {
			if limit == 0 {
				break
			}
			results = append(results, domain)
			limit--
		}

		assert.Equal(t, []string{"a.com", "b.com"}, results)
	})

	t.Run("WildcardEarlyExit", func(t *testing.T) {
		t.Parallel()

		tree := New()
		records := dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}}

		tree.Upsert("*.api.example.com", records)
		tree.Upsert("*.example.com", records)
		tree.Upsert("sub.*.example.com", records)

		var searchResults []string
		for domain := range tree.Search("*") {
			searchResults = append(searchResults, domain)
		}
		assert.ElementsMatch(t, []string{"*.api.example.com", "*.example.com", "sub.*.example.com"}, searchResults)

		var seekResults []string
		limit := 1
		for domain := range tree.Seek("*.example.com") {
			if limit == 0 {
				break
			}
			seekResults = append(seekResults, domain)
			limit--
		}

		assert.Len(t, seekResults, 1)
		assert.Equal(t, "sub.*.example.com", seekResults[0])
	})

	t.Run("Seek_EmptyNonTerminalSkip", func(t *testing.T) {
		t.Parallel()

		tree := New()
		records := dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}}

		tree.Upsert("deep.parent.com", records)
		tree.Upsert("other.com", records)

		var results []string
		for domain := range tree.Seek("parent.com") {
			results = append(results, domain)
		}

		assert.Contains(t, results, "deep.parent.com")
	})

	t.Run("Seek_MissingDomainSkip", func(t *testing.T) {
		t.Parallel()

		tree := New()
		records := dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}}

		tree.Upsert("a.com", records)
		tree.Upsert("b.com", records)

		var results []string
		for domain := range tree.Seek("missing.com") {
			results = append(results, domain)
		}

		assert.Empty(t, results)
	})
}

// TestTree_Walk validates full depth-first iteration over the radix tree.
func TestTree_Walk(t *testing.T) {
	t.Parallel()

	t.Run("EmptyTree", func(t *testing.T) {
		t.Parallel()

		tree := New()
		results := maps.Collect(tree.Walk())
		assert.Empty(t, results)
	})

	t.Run("PathReconstructionAndFiltering", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		tree.Upsert("sub.example.com", dns.RRSets{{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "txt-data")}}})
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "9.9.9.9")}}})
		tree.Upsert("*", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "0.0.0.0")}}})

		tree.Upsert("deep.ent.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})
		tree.DeleteDomain("deep.ent.example.com")

		results := maps.Collect(tree.Walk())

		require.Len(t, results, 4)
		assert.Contains(t, results, "example.com")
		assert.Contains(t, results, "sub.example.com")
		assert.Contains(t, results, "*.example.com")
		assert.Contains(t, results, "*")
		assert.NotContains(t, results, "ent.example.com")
	})

	t.Run("EarlyExitPropagation", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("a.node.com", dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		tree.Upsert("*.node.com", dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})
		tree.Upsert("b.node.com", dns.RRSets{{Type: dns.TypeA, RData: [][]byte{dns.MustPackRData(dns.TypeA, "3.3.3.3")}}})

		visited := 0
		for range tree.Walk() {
			visited++
			if visited == 2 {
				break
			}
		}

		assert.Equal(t, 2, visited)
	})
}
