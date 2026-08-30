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
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTree_CRUD validates core routing mutations, absolute state replacement, and deletion semantics.
func TestTree_CRUD(t *testing.T) {
	t.Parallel()

	t.Run("Initialization", func(t *testing.T) {
		t.Parallel()

		tree := New()
		require.NotNil(t, tree)

		res := tree.Resolve("example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, res.RCode)
	})

	t.Run("BasicUpsertAndGet", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.168.1.1")}}})

		res := tree.Resolve("example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "192.168.1.1"), res.Answer.RData[0])

		resTXT := tree.Resolve("example.com", dns.TypeTXT)
		assert.Equal(t, dns.RCodeSuccess, resTXT.RCode) // NODATA: name exists, TXT absent

		resMissing := tree.Resolve("missing.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resMissing.RCode)
	})

	t.Run("AbsoluteStateReplacement", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		// This must completely replace the previous state, dropping the A record
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeTXT, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "v=spf1")}}})

		resA := tree.Resolve("example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, resA.RCode) // NODATA: A was replaced by TXT, name still exists

		resTXT := tree.Resolve("example.com", dns.TypeTXT)
		require.Equal(t, dns.RCodeSuccess, resTXT.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeTXT, "v=spf1"), resTXT.Answer.RData[0])
	})

	t.Run("DeleteDomain", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.168.1.1")}},
			{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "text")}},
		})
		tree.Upsert("sub.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}}})

		tree.DeleteDomain("example.com")

		resA := tree.Resolve("example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, resA.RCode) // NODATA: example.com is an ENT (sub.example.com survives)

		resChild := tree.Resolve("sub.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, resChild.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "10.0.0.1"), resChild.Answer.RData[0])
	})

	t.Run("NonExistentTargets", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		tree.DeleteDomain("missing.com")

		resAfter := tree.Resolve("z-missing.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resAfter.RCode)

		res := tree.Resolve("example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "1.1.1.1"), res.Answer.RData[0])
	})
}

// TestTree_GhostNodesMemoryLeak ensures that DeleteDomain and empty Upserts
// clear the RRSets and prune empty structural nodes to prevent memory leaks.
func TestTree_GhostNodesMemoryLeak(t *testing.T) {
	t.Parallel()

	t.Run("DeleteDomainPruning", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("deep.sub.example.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}},
		})
		assert.Equal(t, 1, tree.Len(), "tree should contain active domain")

		tree.DeleteDomain("deep.sub.example.com")
		assert.Equal(t, 0, tree.Len(), "tree should be logically empty")

		root := tree.state.Load().root
		assert.Empty(t, root.Children, "root should have zero children after emptying the tree")
	})

	t.Run("EmptyUpsertPruning", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("ghost.example.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.2.3.4")}},
		})
		require.Equal(t, 1, tree.Len())

		tree.Upsert("ghost.example.com", nil) // Empty Upsert acts as deletion
		require.Equal(t, 0, tree.Len())

		root := tree.state.Load().root
		comNode := findNode(root, "com")
		assert.Nil(t, comNode, "structural nodes must be destroyed from memory after empty upsert")
	})
}

// TestTree_ReloadZone verifies offline tree construction and atomic replacement mechanics.
func TestTree_ReloadZone(t *testing.T) {
	t.Parallel()

	t.Run("SuccessfulReload", func(t *testing.T) {
		t.Parallel()
		tree := New()
		tree.Upsert("other.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "0.0.0.0")}}})

		loader := func(onRecord func(domain string, records dns.RRSets)) error {
			onRecord("example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "192.168.1.1")}}})
			onRecord("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "5.5.5.5")}}})
			onRecord("sub.*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "6.6.6.6")}}})
			return nil
		}

		err := tree.ReloadZone(loader)
		require.NoError(t, err)

		resOld := tree.Resolve("other.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resOld.RCode)

		res := tree.Resolve("example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "192.168.1.1"), res.Answer.RData[0])

		resWild := tree.Resolve("sub.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, resWild.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "5.5.5.5"), resWild.Answer.RData[0])

		resNestedWild := tree.Resolve("sub.*.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, resNestedWild.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "6.6.6.6"), resNestedWild.Answer.RData[0])
	})

	t.Run("AbortedReloadOnError", func(t *testing.T) {
		t.Parallel()
		tree := New()
		tree.Upsert("active.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		errSimulated := errors.New("loader failed mid-stream")
		loader := func(onRecord func(domain string, records dns.RRSets)) error {
			onRecord("partial.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})
			return errSimulated
		}

		err := tree.ReloadZone(loader)
		require.ErrorIs(t, err, errSimulated)

		res := tree.Resolve("active.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "1.1.1.1"), res.Answer.RData[0])

		resPartial := tree.Resolve("partial.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resPartial.RCode)
	})
}
