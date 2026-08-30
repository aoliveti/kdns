// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package state provides the in-memory Radix tree state and LRU query resolution view.
//
// Concurrency Model:
//   - Data Plane (DNS Resolution): Lock-free lookups against the sharded LRU-TTL cache.
//     Cache misses fall back to the atomic Radix Tree snapshot and populate the cache.
//   - Control Plane (Read Views): Lock-free traversal and point lookups over the in-memory Radix Tree.
//   - State Synchronization: Atomic tree swaps (Swap) and copy-on-write tree updates (Update).
package state

import (
	"sync"
	"sync/atomic"

	"github.com/aoliveti/kdns/internal/cache"
	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/radix"
)

const defaultCacheCapacity = 10000

type metricsCollector interface {
	IncCacheHit()
	IncCacheMiss()
	SetDomains(count int)
	SetCacheEntries(count int)
}

type nopCollector struct{}

func (nopCollector) IncCacheHit()        {}
func (nopCollector) IncCacheMiss()       {}
func (nopCollector) SetDomains(int)      {}
func (nopCollector) SetCacheEntries(int) {}

// Option configures functional parameters for State.
type Option func(*options)

type options struct {
	metrics metricsCollector
}

// WithMetrics attaches a telemetry metrics collector.
func WithMetrics(m metricsCollector) Option {
	return func(o *options) {
		if m != nil {
			o.metrics = m
		}
	}
}

// State manages the authoritative in-memory Radix tree and LRU query resolution cache.
type State struct {
	tree    atomic.Pointer[radix.Tree]
	cache   *cache.Cache
	metrics metricsCollector
	mu      sync.Mutex
}

// New initializes an in-memory State instance with the configured cache capacity.
func New(cacheCapacity int, opts ...Option) *State {
	if cacheCapacity <= 0 {
		cacheCapacity = defaultCacheCapacity
	}

	cfg := &options{
		metrics: nopCollector{},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	s := &State{
		cache:   cache.New(cacheCapacity),
		metrics: cfg.metrics,
	}
	s.tree.Store(radix.New())
	return s
}

// Len returns the total number of active domain nodes in the radix tree.
func (s *State) Len() int {
	return s.tree.Load().Len()
}

// Swap atomically replaces the entire in-memory Radix Tree and flushes the LRU cache.
func (s *State) Swap(newTree *radix.Tree) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tree.Store(newTree)
	s.cache.Clear()
	s.metrics.SetDomains(newTree.Len())
}

// Update executes a mutation function on the Radix Tree under write lock and clears the cache.
func (s *State) Update(fn func(target *radix.Tree)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fn(s.tree.Load())
	s.cache.Clear()
	s.metrics.SetDomains(s.tree.Load().Len())
}

// ClearCache flushes all entries stored in the LRU query resolution cache.
func (s *State) ClearCache() {
	s.cache.Clear()
}

// SnapshotTree returns a point-in-time reference of the in-memory Radix Tree under read lock.
func (s *State) SnapshotTree() *radix.Tree {
	return s.tree.Load()
}

var (
	_ dns.Getter = (*State)(nil)
	_ dns.Viewer = (*State)(nil)
)
