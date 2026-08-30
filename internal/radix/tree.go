// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package radix implements a lock-free, zero-allocation radix tree tailored for authoritative DNS routing.
//
// Structural Hierarchy & Traversal:
//   - Domains are indexed in reverse-label order from right to left (Root '.' -> TLD -> Domain -> Subdomains).
//   - Traversal utilizes stack-allocated label iterators with zero heap allocations during the resolution hot path.
//
// Concurrency & Mutation Model (CQRS):
//   - Reads (Resolve, Get, Walk, Search, Seek) are completely lock-free, executing atomic dereferencing
//     against an atomic.Pointer[state].
//   - Writes (Upsert, DeleteDomain) operate via Copy-on-Write (CoW) path duplication under a synchronization
//     mutex, swapping the root state atomically upon completion.
//
// DNS Protocol Invariants Supported:
//   - RFC 1034 §3.6.2: CNAME transparency.
//   - RFC 1034 §4.3.2: Zone cuts & Delegation Referrals.
//   - RFC 4592: Deterministic wildcard synthesis and Empty Non-Terminal (ENT) wildcard suppression.
//   - RFC 2308: Negative caching authority attachment.
//   - RFC 8482: Minimal response synthesis on TypeANY queries.
package radix

import (
	"sync"
	"sync/atomic"
)

// Tree represents the concurrent routing structure optimized for DNS.
// It uses Copy-on-Write semantics to ensure thread-safe writes
// without blocking high-throughput concurrent readers.
type Tree struct {
	state atomic.Pointer[state]
	mu    sync.Mutex
}

// New initializes and returns an empty radix tree with an active root node.
func New() *Tree {
	t := &Tree{}
	t.state.Store(&state{root: &Node{}, size: 0})
	return t
}

// Len returns the total number of active domains currently stored in the tree.
func (t *Tree) Len() int {
	s := t.state.Load()
	if s == nil {
		return 0
	}
	return int(s.size)
}
