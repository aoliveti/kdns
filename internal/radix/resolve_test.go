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
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTree_Resolve_RCode validates the DNS response code returned by Tree.Resolve across
// all structural states: NXDOMAIN (name entirely absent), NODATA (name exists,
// type absent — including ENT and wildcard synthesis), and exact record hits.
func TestTree_Resolve_RCode(t *testing.T) {
	t.Parallel()

	soaSet := dns.RRSets{{
		Type:  dns.TypeSOA,
		Class: dns.ClassIN,
		TTL:   3600,
		RData: [][]byte{dns.MustPackRData(dns.TypeSOA, "ns1.example.com. admin.example.com. 1 7200 3600 1209600 300")},
	}}

	t.Run("NXDOMAIN: completely absent name attaches enclosing SOA", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", soaSet)

		res := tree.Resolve("nxdomain.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, res.RCode)
		assert.True(t, res.HasAuthority())
		assert.Equal(t, dns.TypeSOA, res.Authority.Type)
		assert.Equal(t, "example.com", res.AuthorityName)
	})

	t.Run("NODATA: existing name with absent type attaches enclosing SOA", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", append(soaSet, dns.RRSet{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}))

		res := tree.Resolve("example.com", dns.TypeMX)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.False(t, res.HasAnswer())
		assert.True(t, res.HasAuthority())
		assert.Equal(t, dns.TypeSOA, res.Authority.Type)
		assert.Equal(t, "example.com", res.AuthorityName)
	})

	t.Run("HIT: exact record found", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		res := tree.Resolve("example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.True(t, res.HasAnswer())
		assert.False(t, res.HasAuthority())
	})

	t.Run("NODATA: empty non-terminal (ENT)", func(t *testing.T) {
		t.Parallel()

		tree := New()
		// "ent.example.com" is a structural node whose child carries the record.
		tree.Upsert("sub.ent.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})

		res := tree.Resolve("ent.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode, "ENT returns NODATA (NOERROR + 0 records)")
		assert.False(t, res.HasAnswer())
	})

	t.Run("HIT: wildcard synthesis", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}}})

		res := tree.Resolve("any.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.True(t, res.HasAnswer())
	})

	t.Run("NODATA: wildcard covers name but type absent", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}}})

		res := tree.Resolve("any.example.com", dns.TypeMX)
		assert.Equal(t, dns.RCodeSuccess, res.RCode, "wildcard covers the name: NODATA not NXDOMAIN")
		assert.False(t, res.HasAnswer())
	})

	t.Run("NXDOMAIN: deleted leaf with no children", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("leaf.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		tree.DeleteDomain("leaf.example.com")

		res := tree.Resolve("leaf.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, res.RCode, "deleted leaf with no children is NXDOMAIN")
	})

	t.Run("NODATA: deleted parent is ENT because child survives", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("parent.com", dns.RRSets{{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "txt")}}})
		tree.Upsert("child.parent.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		tree.DeleteDomain("parent.com")

		res := tree.Resolve("parent.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode) // NODATA, not NXDOMAIN
		assert.False(t, res.HasAnswer())
	})

	t.Run("HIT: TypeANY returns minimal response", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("any.com", dns.RRSets{{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "txt")}}})
		tree.Upsert("any.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})

		// Querying ANY should return the first available RRSet (minimal response RFC 8482)
		res := tree.Resolve("any.com", dns.TypeANY)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)
		require.True(t, res.HasAnswer())
		// It should be one of the types inserted, not an exact match guarantee on which one
		assert.True(t, res.Answer.Type == dns.TypeTXT || res.Answer.Type == dns.TypeA)
	})
}

// TestTree_RFC4592_Wildcards validates strict DNS wildcard behavior per RFC 4592.
func TestTree_RFC4592_Wildcards(t *testing.T) {
	t.Parallel()

	t.Run("BasicFallback", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.100")}}})

		res := tree.Resolve("api.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "10.0.0.100"), res.Answer.RData[0])

		resDeep := tree.Resolve("deep.api.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, resDeep.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "10.0.0.100"), resDeep.Answer.RData[0])

		treeNoWild := New()
		resNoWild := treeNoWild.Resolve("*", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resNoWild.RCode)
	})

	t.Run("UpdateAndMutateWildcard", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "v=spf1")}}})

		resA := tree.Resolve("sub.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, resA.RCode) // NODATA: wildcard covers name, A type absent after Upsert

		resTXT := tree.Resolve("sub.example.com", dns.TypeTXT)
		require.Equal(t, dns.RCodeSuccess, resTXT.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeTXT, "v=spf1"), resTXT.Answer.RData[0])

		tree.DeleteDomain("*.example.com")
		resDeleted := tree.Resolve("sub.example.com", dns.TypeTXT)
		assert.Equal(t, dns.RCodeNameError, resDeleted.RCode)
	})

	t.Run("WildcardFallbackOnDeletedNode", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.100")}}})
		tree.Upsert("deleted.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.200")}}})
		tree.DeleteDomain("deleted.example.com")

		res := tree.Resolve("deleted.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "10.0.0.100"), res.Answer.RData[0])
	})

	t.Run("ExactMatchSuppression", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.100")}}})
		tree.Upsert("api.example.com", dns.RRSets{{Type: dns.TypeTXT, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeTXT, "specific")}}})

		resA := tree.Resolve("api.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, resA.RCode) // NODATA: api.example.com exists (has TXT), A is absent

		resTXT := tree.Resolve("api.example.com", dns.TypeTXT)
		require.Equal(t, dns.RCodeSuccess, resTXT.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeTXT, "specific"), resTXT.Answer.RData[0])
	})

	t.Run("EmptyNonTerminalSuppression", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.100")}}})
		tree.Upsert("sub.ent.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.2")}}})

		resEnt := tree.Resolve("ent.example.com", dns.TypeA)
		// Per RFC 4592 §2.2, ent.example.com is an ENT that suppresses wildcard synthesis.
		// The ENT node exists (has child sub.ent.example.com) so the response is NODATA, not NXDOMAIN.
		assert.Equal(t, dns.RCodeSuccess, resEnt.RCode)
	})

	t.Run("LiteralAsterisk", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("sub.*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.2.3.4")}}})

		resLiteral := tree.Resolve("sub.*.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, resLiteral.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "1.2.3.4"), resLiteral.Answer.RData[0])
	})

	t.Run("SpecificWildcardOverridesGeneric", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		tree.Upsert("*.sub.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})

		res := tree.Resolve("foo.sub.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "2.2.2.2"), res.Answer.RData[0])
	})

	t.Run("ENTWildcardIntercept", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.rfc.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.1.1.1")}}})
		tree.Upsert("deep.*.sub.rfc.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "2.2.2.2")}}})

		resENT := tree.Resolve("missing.sub.rfc.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resENT.RCode)
	})
}

// TestTree_Resolve_CNAMETransparency validates RFC 1034 §3.6.2 CNAME transparency.
// When a name has a CNAME record and the queried type is absent, the CNAME is
// returned so the client resolver can follow the pointer. The server does NOT
// chase the chain (that is the recursive resolver's job per RFC 1034 §5.3.2).
func TestTree_Resolve_CNAMETransparency(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		qType dns.Type
	}{
		{"query for absent type returns CNAME", dns.TypeA},
		{"query for CNAME type returns CNAME directly", dns.TypeCNAME},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tree := New()
			tree.Upsert("foo.example.com", dns.RRSets{{Type: dns.TypeCNAME, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeCNAME, "bar.example.com")}}})

			res := tree.Resolve("foo.example.com", tt.qType)
			require.Equal(t, dns.RCodeSuccess, res.RCode)
			assert.Equal(t, dns.TypeCNAME, res.Answer.Type)
			assert.Equal(t, dns.MustPackRData(dns.TypeCNAME, "bar.example.com"), res.Answer.RData[0])
		})
	}

	t.Run("exact type match takes precedence over CNAME", func(t *testing.T) {
		t.Parallel()

		// RFC 1034 §3.6.2: a node should not have both CNAME and other types,
		// but if it does the exact match must win.
		tree := New()
		tree.Upsert("foo.example.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.2.3.4")}},
			{Type: dns.TypeCNAME, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeCNAME, "bar.example.com")}},
		})

		res := tree.Resolve("foo.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.TypeA, res.Answer.Type)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "1.2.3.4"), res.Answer.RData[0])
	})

	t.Run("absent name with CNAME-only is NXDOMAIN", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("other.example.com", dns.RRSets{{Type: dns.TypeCNAME, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeCNAME, "bar.example.com")}}})

		res := tree.Resolve("missing.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, res.RCode)
	})

	t.Run("no CNAME and absent type is NODATA", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("foo.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.2.3.4")}}})

		res := tree.Resolve("foo.example.com", dns.TypeMX)
		assert.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.False(t, res.HasAnswer())
	})

	t.Run("wildcard CNAME synthesis for absent type", func(t *testing.T) {
		t.Parallel()

		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeCNAME, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeCNAME, "target.example.com")}}})

		res := tree.Resolve("foo.example.com", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.TypeCNAME, res.Answer.Type)
		assert.Equal(t, dns.MustPackRData(dns.TypeCNAME, "target.example.com"), res.Answer.RData[0])
	})

	t.Run("wildcard CNAME not synthesized for CNAME query type", func(t *testing.T) {
		t.Parallel()

		// A direct CNAME query against a wildcard CNAME node is a hit, not transparency.
		tree := New()
		tree.Upsert("*.example.com", dns.RRSets{{Type: dns.TypeCNAME, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeCNAME, "target.example.com")}}})

		res := tree.Resolve("foo.example.com", dns.TypeCNAME)
		require.Equal(t, dns.RCodeSuccess, res.RCode)
		assert.Equal(t, dns.TypeCNAME, res.Answer.Type)
	})
}

// TestTree_DelegationReferrals validates RFC 1034 4.3.2 zone cuts.
// The tree must return a referral with NS records in the Authority section
// when crossing a delegated zone cut, instead of returning NXDOMAIN.
func TestTree_DelegationReferrals(t *testing.T) {
	t.Parallel()

	tree := New()
	tree.Upsert("example.com", dns.RRSets{
		{Type: dns.TypeSOA, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeSOA, "ns1.example.com. admin.example.com. 1 7200 3600 1209600 300")}},
		{Type: dns.TypeNS, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeNS, "ns1.example.com.")}},
	})

	tree.Upsert("sub.example.com", dns.RRSets{
		{Type: dns.TypeNS, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeNS, "ns1.sub.example.com.")}},
	})

	t.Run("StandardReferral", func(t *testing.T) {
		t.Parallel()

		res := tree.Resolve("www.sub.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, res.RCode, "delegation referral should return NOERROR")
		assert.False(t, res.HasAnswer(), "delegation should not contain an answer")
		require.True(t, res.HasAuthority(), "delegation must include NS records in authority")
		assert.Equal(t, dns.TypeNS, res.Authority.Type, "authority must be the NS record of the delegated zone")
		assert.Equal(t, "sub.example.com", res.AuthorityName, "authority name must match the delegated zone apex")
	})

	t.Run("RFC4035_DSReferralException", func(t *testing.T) {
		t.Parallel()

		// Exact match DS query at the delegation point MUST NOT return a referral.
		// Instead, it should process normally. Since there is no DS record inserted,
		// it correctly returns a NODATA response (NOERROR + SOA in Authority).
		resExact := tree.Resolve("sub.example.com", dns.TypeDS)
		require.Equal(t, dns.RCodeSuccess, resExact.RCode)
		assert.False(t, resExact.HasAnswer(), "NODATA response should have no answers")
		require.NotEmpty(t, resExact.Authority, "Authority must contain SOA for negative caching")
		assert.Equal(t, dns.TypeSOA, resExact.Authority.Type, "DS query at exact delegation point must return SOA (NODATA), not NS referral")

		// DS query below the delegation point MUST return a referral.
		resSub := tree.Resolve("deep.sub.example.com", dns.TypeDS)
		require.NotEmpty(t, resSub.Authority, "DS query below delegation point must produce NS referral")
		assert.Equal(t, dns.TypeNS, resSub.Authority.Type)
		assert.Equal(t, "sub.example.com", resSub.AuthorityName)
	})
}

func TestTree_CornerCasesAndRFCCompliance(t *testing.T) {
	t.Parallel()

	t.Run("CaseInsensitiveMatching", func(t *testing.T) {
		t.Parallel()

		tree := New()
		records := dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.2.3.4")}}}

		tree.Upsert("ExAmPlE.CoM", records)

		res := tree.Resolve("wWw.EXAMPLE.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, res.RCode)

		resExact := tree.Resolve("example.COM", dns.TypeA)
		require.Equal(t, dns.RCodeSuccess, resExact.RCode)
		assert.Equal(t, dns.MustPackRData(dns.TypeA, "1.2.3.4"), resExact.Answer.RData[0])

		rrs, ok := tree.Get("EXAMPLE.com")
		require.True(t, ok)
		assert.Equal(t, dns.TypeA, rrs[0].Type)
	})

	t.Run("RootZoneApexRecord", func(t *testing.T) {
		t.Parallel()

		tree := New()
		rootSOA := dns.RRSets{
			{Type: dns.TypeSOA, TTL: 86400, RData: [][]byte{dns.MustPackRData(dns.TypeSOA, "a.root-servers.net. nstld.verisign-grs.com. 2026081600 1800 900 604800 86400")}},
			{Type: dns.TypeNS, TTL: 518400, RData: [][]byte{dns.MustPackRData(dns.TypeNS, "a.root-servers.net.")}},
		}

		tree.Upsert(".", rootSOA)
		assert.Equal(t, 1, tree.Len())

		resSOA := tree.Resolve(".", dns.TypeSOA)
		require.Equal(t, dns.RCodeSuccess, resSOA.RCode)
		assert.Equal(t, dns.TypeSOA, resSOA.Answer.Type)

		resNX := tree.Resolve("missing.tld", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resNX.RCode)
		assert.True(t, resNX.HasAuthority())
		assert.Equal(t, ".", resNX.AuthorityName)
	})

	t.Run("DeepEnclosingSOAPreservation", func(t *testing.T) {
		t.Parallel()

		tree := New()
		soaSet := dns.RRSets{
			{Type: dns.TypeSOA, TTL: 3600, RData: [][]byte{dns.MustPackRData(dns.TypeSOA, "ns1.example.com. admin.example.com. 1 7200 3600 1209600 300")}},
		}
		tree.Upsert("example.com", soaSet)
		tree.Upsert("sub.example.com", dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}}})

		res := tree.Resolve("missing.deep.sub.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, res.RCode)
		require.True(t, res.HasAuthority())
		assert.Equal(t, dns.TypeSOA, res.Authority.Type)
		assert.Equal(t, "example.com", res.AuthorityName)
	})

	t.Run("UnorderedEdgeInsertionBinarySearchStability", func(t *testing.T) {
		t.Parallel()

		tree := New()
		labels := []string{"zeta", "alpha", "mike", "bravo", "whiskey", "charlie", "tango", "delta", "kilo", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "lima", "november", "oscar", "papa", "quebec"}

		rA := dns.MustPackRData(dns.TypeA, "10.0.0.1")
		for _, label := range labels {
			domain := label + ".example.com"
			tree.Upsert(domain, dns.RRSets{{Type: dns.TypeA, TTL: 300, RData: [][]byte{rA}}})
		}

		assert.Equal(t, len(labels), tree.Len())

		for _, label := range labels {
			domain := label + ".example.com"
			res := tree.Resolve(domain, dns.TypeA)
			require.Equal(t, dns.RCodeSuccess, res.RCode)
			assert.Equal(t, rA, res.Answer.RData[0])
		}
	})

	t.Run("EmptyRRSetsLeafAndENTSemantics", func(t *testing.T) {
		t.Parallel()

		tree := New()

		// 1. A leaf domain with empty records and no children is non-existent (NXDOMAIN)
		tree.Upsert("leaf-empty.example.com", dns.RRSets{})
		assert.Equal(t, 0, tree.Len())

		resLeaf := tree.Resolve("leaf-empty.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeNameError, resLeaf.RCode)

		rrsLeaf, ok := tree.Get("leaf-empty.example.com")
		assert.False(t, ok)
		assert.Nil(t, rrsLeaf)

		// 2. An empty domain that has active children becomes a valid ENT (NODATA / NOERROR)
		tree.Upsert("child.ent.example.com", dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{dns.MustPackRData(dns.TypeA, "10.0.0.1")}},
		})
		assert.Equal(t, 1, tree.Len())

		resENT := tree.Resolve("ent.example.com", dns.TypeA)
		assert.Equal(t, dns.RCodeSuccess, resENT.RCode)
		assert.False(t, resENT.HasAnswer())

		rrsENT, ok := tree.Get("ent.example.com")
		assert.False(t, ok)
		assert.Nil(t, rrsENT)
	})
}
