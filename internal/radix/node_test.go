// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestNode_CloneAndSearch(t *testing.T) {
	t.Parallel()

	node := &Node{
		RRSets: dns.RRSets{
			{Type: dns.TypeA, TTL: 300, RData: [][]byte{{1, 2, 3, 4}}},
		},
		Children: []Edge{
			{Label: "com", Node: &Node{}},
		},
	}

	cloned := node.clone()
	require.NotNil(t, cloned)
	assert.Len(t, cloned.RRSets, 1)
	assert.Len(t, cloned.Children, 1)

	// searchRRSet
	rr, ok := searchRRSet(node, dns.TypeA)
	assert.True(t, ok)
	assert.Equal(t, dns.TypeA, rr.Type)

	_, ok = searchRRSet(node, dns.TypeTXT)
	assert.False(t, ok)

	_, ok = searchRRSet(nil, dns.TypeA)
	assert.False(t, ok)
}

func TestNode_FindEdge_BinarySearch(t *testing.T) {
	t.Parallel()

	// Create more than 16 edges to exercise binary search branch (> 16)
	edges := make([]Edge, 0, 30)
	for i := range 30 {
		label := fmt.Sprintf("label%02d", i)
		edges = append(edges, Edge{Label: label, Node: &Node{}})
	}

	idx, found := findEdge(edges, "label15")
	assert.True(t, found)
	assert.Equal(t, 15, idx)

	idx, found = findEdge(edges, "label99")
	assert.False(t, found)
	assert.Equal(t, 30, idx)

	idx, found = findEdge(edges, "aaa")
	assert.False(t, found)
	assert.Equal(t, 0, idx)
}
