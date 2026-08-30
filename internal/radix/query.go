// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"bytes"
	"iter"

	"github.com/aoliveti/kdns/internal/dns"
)

// Get returns all RRSets stored at a specific domain for use by the control plane.
// It performs an exact match and does not execute wildcard synthesis.
func (t *Tree) Get(domain string) (dns.RRSets, bool) {
	s := t.state.Load()
	if s == nil || s.root == nil {
		return nil, false
	}

	currentNode := s.root
	var labelBuf [64]byte
	it := NewDomainIterator(domain)

	for {
		label, hasNext := it.NextLower(labelBuf[:])
		if !hasNext {
			break
		}

		if label == "*" {
			if currentNode.Wildcard != nil {
				currentNode = currentNode.Wildcard
				continue
			}
			return nil, false
		}

		idx, edgeFound := findEdge(currentNode.Children, label)
		if !edgeFound {
			return nil, false
		}
		currentNode = currentNode.Children[idx].Node
	}

	if len(currentNode.RRSets) == 0 {
		return nil, false
	}
	return currentNode.RRSets, true
}

// Walk returns an iterator over all domain name keys and RRSets stored in the tree.
func (t *Tree) Walk() iter.Seq2[string, dns.RRSets] {
	return t.Seek("")
}

// Search performs a lock-free scan of the tree to find domains containing the query substring.
func (t *Tree) Search(query string) iter.Seq2[string, dns.RRSets] {
	return func(yield func(string, dns.RRSets) bool) {
		s := t.state.Load()
		if s == nil || s.root == nil {
			return
		}

		queryBytes := []byte(query)
		walkTree(s.root, func(n *Node, domainBytes []byte) bool {
			if len(n.RRSets) > 0 && bytes.Contains(domainBytes, queryBytes) {
				return yield(string(domainBytes), n.RRSets)
			}
			return true
		})
	}
}

// Seek performs a lock-free traversal of the tree for pagination,
// starting lexicographically after the provided domain name.
func (t *Tree) Seek(afterDomain string) iter.Seq2[string, dns.RRSets] {
	return func(yield func(string, dns.RRSets) bool) {
		s := t.state.Load()
		if s == nil || s.root == nil {
			return
		}

		if afterDomain != "" {
			target := findNode(s.root, afterDomain)
			if target == nil {
				return
			}
		}

		skipping := afterDomain != ""
		afterBytes := []byte(afterDomain)

		walkTree(s.root, func(n *Node, domainBytes []byte) bool {
			if skipping {
				if bytes.Equal(domainBytes, afterBytes) {
					skipping = false
				}
				return true
			}
			if len(n.RRSets) > 0 {
				return yield(string(domainBytes), n.RRSets)
			}
			return true
		})
	}
}

// walkTree recursively iterates through the radix structure, maintaining the fully
// qualified domain name in a stack-allocated buffer to achieve zero-allocation traversal.
func walkTree(root *Node, visit func(n *Node, domainBytes []byte) bool) {
	if root == nil {
		return
	}

	var pathBuf [256]byte
	var walk func(n *Node, offset int) bool

	walk = func(n *Node, offset int) bool {
		if !visit(n, pathBuf[offset:256]) {
			return false
		}

		if n.Wildcard != nil {
			newOffset := offset - 2
			switch {
			case offset == 256:
				newOffset = 255
				pathBuf[255] = '*'
			case newOffset >= 0:
				pathBuf[newOffset] = '*'
				pathBuf[newOffset+1] = '.'
			}
			if newOffset >= 0 && !walk(n.Wildcard, newOffset) {
				return false
			}
		}

		for _, edge := range n.Children {
			lblLen := len(edge.Label)
			newOffset := offset - lblLen
			if offset < 256 {
				newOffset--
			}

			if newOffset < 0 {
				continue
			}

			if offset < 256 {
				pathBuf[newOffset+lblLen] = '.'
			}
			copy(pathBuf[newOffset:newOffset+lblLen], edge.Label)

			if !walk(edge.Node, newOffset) {
				return false
			}
		}
		return true
	}

	walk(root, 256)
}
