// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"slices"

	"github.com/aoliveti/kdns/internal/dns"
)

// Upsert replaces the entire DNS record set for a given domain atomically.
// It utilizes Copy-on-Write to duplicate only the modified path, allowing
// concurrent readers to traverse the old state without blocking.
func (t *Tree) Upsert(domain string, records dns.RRSets) {
	if len(records) == 0 {
		t.DeleteDomain(domain)
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	currentState := t.state.Load()
	currentRoot := currentState.root
	newSize := currentState.size

	newRoot := currentRoot.clone()
	currentNode := newRoot
	var labelBuf [64]byte
	it := NewDomainIterator(domain)

	for {
		label, hasNext := it.NextLower(labelBuf[:])
		if !hasNext {
			break
		}

		if label == "*" {
			if currentNode.Wildcard == nil {
				currentNode.Wildcard = &Node{}
				currentNode = currentNode.Wildcard
				continue
			}
			currentNode.Wildcard = currentNode.Wildcard.clone()
			currentNode = currentNode.Wildcard
			continue
		}

		idx, found := findEdge(currentNode.Children, label)
		if !found {
			child := &Node{}
			e := Edge{Label: label, Node: child}
			currentNode.Children = slices.Insert(currentNode.Children, idx, e)
			currentNode = child
			continue
		}

		child := currentNode.Children[idx].Node.clone()
		currentNode.Children[idx].Node = child
		currentNode = child
	}

	wasEmpty := len(currentNode.RRSets) == 0
	currentNode.RRSets = records.Clone()

	switch {
	case wasEmpty && len(currentNode.RRSets) > 0:
		newSize++
	case !wasEmpty && len(currentNode.RRSets) == 0:
		newSize--
	}

	t.state.Store(&state{root: newRoot, size: newSize})
}

// DeleteDomain completely removes all DNS records associated with a given domain.
// Empty structural nodes are pruned bottom-up to prevent memory leaks.
func (t *Tree) DeleteDomain(domain string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	currentState := t.state.Load()
	if currentState == nil || currentState.root == nil {
		return
	}

	targetNode := findNode(currentState.root, domain)
	if targetNode == nil || len(targetNode.RRSets) == 0 {
		return
	}

	var labelBuf [64]byte
	newRoot, deleted := deletePath(currentState.root, NewDomainIterator(domain), labelBuf[:])
	if !deleted {
		return
	}

	if newRoot == nil {
		newRoot = &Node{}
	}

	t.state.Store(&state{root: newRoot, size: currentState.size - 1})
}

// ReloadZone builds a new routing tree completely offline and performs an atomic swap.
// This is heavily optimized for initial zone loading and SIGHUP reloads.
func (t *Tree) ReloadZone(loader func(onRecord func(domain string, records dns.RRSets)) error) error {
	newRoot := &Node{}
	var count int64

	addRecord := func(domain string, records dns.RRSets) {
		if insert(newRoot, domain, records) {
			count++
		}
	}

	if err := loader(addRecord); err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.state.Store(&state{root: newRoot, size: count})
	return nil
}

// deletePath navigates to the target node, clears its records, and recursively
// prunes empty branches on the way back up to prevent ghost nodes from leaking memory.
func deletePath(node *Node, it DomainIterator, labelBuf []byte) (*Node, bool) {
	label, hasNext := it.NextLower(labelBuf)
	if !hasNext {
		if len(node.RRSets) == 0 {
			return node, false
		}
		newNode := node.clone()
		newNode.RRSets = nil
		if len(newNode.Children) == 0 && newNode.Wildcard == nil {
			return nil, true
		}
		return newNode, true
	}

	if label == "*" {
		if node.Wildcard == nil {
			return node, false
		}
		newWildcard, deleted := deletePath(node.Wildcard, it, labelBuf)
		if !deleted {
			return node, false
		}
		newNode := node.clone()
		newNode.Wildcard = newWildcard
		if len(newNode.RRSets) == 0 && len(newNode.Children) == 0 && newNode.Wildcard == nil {
			return nil, true
		}
		return newNode, true
	}

	idx, found := findEdge(node.Children, label)
	if !found {
		return node, false
	}

	newChild, deleted := deletePath(node.Children[idx].Node, it, labelBuf)
	if !deleted {
		return node, false
	}

	newNode := node.clone()
	if newChild == nil {
		newNode.Children = slices.Delete(newNode.Children, idx, idx+1)
		if len(newNode.RRSets) == 0 && len(newNode.Children) == 0 && newNode.Wildcard == nil {
			return nil, true
		}
		return newNode, true
	}

	newNode.Children[idx].Node = newChild
	return newNode, true
}

// insert performs an in-place mutation without CoW overhead.
// It is exclusively used by ReloadZone on an offline root node.
func insert(currentNode *Node, domain string, records dns.RRSets) bool {
	var labelBuf [64]byte
	it := NewDomainIterator(domain)

	for {
		label, hasNext := it.NextLower(labelBuf[:])
		if !hasNext {
			break
		}

		if label == "*" {
			if currentNode.Wildcard == nil {
				currentNode.Wildcard = &Node{}
			}
			currentNode = currentNode.Wildcard
			continue
		}

		idx, found := findEdge(currentNode.Children, label)
		if !found {
			child := &Node{}
			e := Edge{Label: label, Node: child}
			currentNode.Children = slices.Insert(currentNode.Children, idx, e)
			currentNode = child
			continue
		}
		currentNode = currentNode.Children[idx].Node
	}

	wasEmpty := len(currentNode.RRSets) == 0
	currentNode.RRSets = records.Clone()
	return wasEmpty && len(currentNode.RRSets) > 0
}
