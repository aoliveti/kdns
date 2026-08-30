// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"github.com/aoliveti/kdns/internal/dns"
)

// Edge represents a directed connection to a child node via a string label.
type Edge struct {
	Node  *Node
	Label string
}

// Node represents a single structural element within the radix tree hierarchy.
type Node struct {
	Wildcard *Node
	RRSets   dns.RRSets
	Children []Edge
}

// clone creates a shallow copy of the node and its immediate edges.
// It is the foundation of the Copy-on-Write (CoW) mutation model, ensuring
// that concurrent readers traversing the old state are not affected by writes.
func (n *Node) clone() *Node {
	newNode := &Node{
		Wildcard: n.Wildcard,
		RRSets:   n.RRSets.Clone(),
		Children: make([]Edge, len(n.Children)),
	}
	copy(newNode.Children, n.Children)
	return newNode
}

// state represents an atomic snapshot of the routing tree.
type state struct {
	root *Node
	size int64
}

// searchRRSet performs an optimized linear search for a specific query type
// within a node's resource record sets.
func searchRRSet(node *Node, qt dns.Type) (dns.RRSet, bool) {
	if node == nil {
		return dns.RRSet{}, false
	}
	for i := range node.RRSets {
		if node.RRSets[i].Type == qt {
			return node.RRSets[i], true
		}
	}
	return dns.RRSet{}, false
}

// findNode traverses the tree and returns the exact node for the given domain.
// It returns nil if the domain does not exist.
func findNode(root *Node, domain string) *Node {
	currentNode := root
	var labelBuf [64]byte
	it := NewDomainIterator(domain)

	for {
		label, hasNext := it.NextLower(labelBuf[:])
		if !hasNext {
			break
		}

		if label == "*" {
			if currentNode.Wildcard == nil {
				return nil
			}
			currentNode = currentNode.Wildcard
			continue
		}

		idx, found := findEdge(currentNode.Children, label)
		if !found {
			return nil
		}
		currentNode = currentNode.Children[idx].Node
	}

	return currentNode
}

// findEdge determines the index of an edge using a hybrid search strategy.
// It uses a linear scan for small arrays (<= 16) to avoid branch mispredictions,
// and switches to binary search for larger slices.
func findEdge(edges []Edge, label string) (int, bool) {
	n := len(edges)
	if n <= 16 {
		for i := range n {
			if edges[i].Label == label {
				return i, true
			}
			if edges[i].Label > label {
				return i, false
			}
		}
		return n, false
	}

	l, r := 0, n-1
	for l <= r {
		m := int(uint(l+r) >> 1)
		if edges[m].Label == label {
			return m, true
		}
		if edges[m].Label < label {
			l = m + 1
			continue
		}
		r = m - 1
	}
	return l, false
}
