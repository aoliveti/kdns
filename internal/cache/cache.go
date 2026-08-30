// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cache provides a highly concurrent, sharded LRU-TTL memory store
// optimized for high-throughput authoritative DNS query resolution.
//
// To sustain multi-million QPS workloads without GC latency degradation or lock
// bottlenecking, the cache enforces:
//   - Lock striping across 256 contiguous shards with CPU cache-line padding to
//     eliminate false sharing during concurrent LRU list mutations.
//   - Zero-allocation steady-state insertions via in-place recycling of evicted
//     tail entries, preventing heap churn and GC pauses under capacity saturation.
//   - Hot-key fast-path bypass on lookups for Zipfian traffic distributions,
//     skipping doubly linked list pointer updates when the entry is already at the head.
//   - Accelerated ASM hashing using maphash.Comparable for O(1) shard routing.
//   - Precise TTL enforcement via non-blocking lazy eviction on read access.
package cache

import (
	"hash/maphash"
	"sync"
	"time"

	"golang.org/x/sys/cpu"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	// shardCount dictates the concurrency partition level of the cache.
	// It is fixed to a power of 2 (256) to enable fast bitwise indexing.
	shardCount = 256

	// shardMask is the bitmask used for fast modulo shard routing.
	shardMask = shardCount - 1
)

// Key strictly identifies a unique cache entry by combining a canonical lower-case
// domain FQDN and query type (dns.Type).
//
// DNS protocol lookups are case-insensitive (RFC 1035), whereas Go map lookups evaluate
// binary equality. Callers must supply canonicalized lower-case domain names in Key.Name
// to prevent cache fragmentation and missed lookups across mixed-case resolver queries.
type Key struct {
	Name string
	Type dns.Type
}

// entry represents an intrusive doubly linked list node.
// Spatial pointers (prev, next), lookup key, cached payload, and expiration timestamp
// are stored contiguously to maximize CPU L1/L2 cache locality.
type entry struct {
	prev      *entry
	next      *entry
	key       Key
	value     dns.RRSet
	expiresAt int64
}

// shard isolates an independent partition of the cache behind a dedicated fast mutex.
//
// In an LRU cache, every read operation (Get) must acquire an exclusive lock to update
// the access ordering pointers. To prevent multi-core cache-line bouncing (false sharing)
// when adjacent shards are locked simultaneously, each shard struct is padded with
// cpu.CacheLinePad.
//
// Pointer fields are ordered first to minimize GC pointer scanning ranges.
type shard struct {
	items    map[Key]*entry
	head     *entry
	tail     *entry
	capacity int
	mu       sync.Mutex
	_        cpu.CacheLinePad
}

// remove unlinks an entry from the doubly linked list in O(1) time.
// It clears internal pointers to prevent dangling references.
func (s *shard) remove(e *entry) {
	e.prev.next = e.next
	e.next.prev = e.prev

	e.prev = nil
	e.next = nil
}

// pushFront inserts an entry immediately after the head sentinel in O(1) time,
// marking it as the most recently used element in the shard.
func (s *shard) pushFront(e *entry) {
	e.next = s.head.next
	e.prev = s.head

	s.head.next.prev = e
	s.head.next = e
}

// Cache coordinates partitioned LRU-TTL memory shards to serve low-latency DNS records.
// Shards are allocated as a single contiguous array inside the Cache struct to minimize
// heap indirections and constructor allocation overhead.
type Cache struct {
	shards [shardCount]shard
	seed   maphash.Seed
}

// New initializes a sharded DNS cache.
//
// The totalCapacity parameter is evenly distributed across all internal shards,
// with a minimum capacity floor of 1 entry per shard.
func New(totalCapacity int) *Cache {
	shardCap := max(totalCapacity/shardCount, 1)

	c := &Cache{
		seed: maphash.MakeSeed(),
	}

	for i := range shardCount {
		s := &c.shards[i]
		s.items = make(map[Key]*entry, shardCap)
		s.capacity = shardCap
		s.head = &entry{}
		s.tail = &entry{}
		s.head.next = s.tail
		s.tail.prev = s.head
	}

	return c
}

// getShard deterministically routes a Key to its designated memory shard.
// It utilizes maphash.Comparable to compute an ASM-accelerated 64-bit hash
// followed by a bitwise mask, operating completely allocation-free (0 B/op).
func (c *Cache) getShard(key Key) *shard {
	idx := maphash.Comparable(c.seed, key) & shardMask
	return &c.shards[idx]
}

// Set inserts or updates a DNS record with a specific Time-To-Live duration.
//
// Operational behavior:
//   - Overwrites: If the key already exists, its value and TTL expiration are updated.
//     If the entry is not already at the head of the list, it is promoted to the front.
//   - Steady-State Eviction (Zero Allocation): When shard capacity is reached, the least
//     recently used node at the tail is recycled in-place. Its key, value, and expiration
//     are overwritten and moved to the head without releasing memory to the GC or
//     allocating a new struct.
//   - Fresh Insertions: Under capacity, a new entry node is allocated and linked.
func (c *Cache) Set(key Key, value dns.RRSet, ttl time.Duration) {
	if ttl <= 0 {
		c.Delete(key)
		return
	}

	s := c.getShard(key)
	expiresAt := time.Now().Add(ttl).UnixNano()

	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.items[key]; ok {
		e.value = value
		e.expiresAt = expiresAt
		if s.head.next != e {
			s.remove(e)
			s.pushFront(e)
		}
		return
	}

	if len(s.items) >= s.capacity {
		e := s.tail.prev
		s.remove(e)
		delete(s.items, e.key)

		e.key = key
		e.value = value
		e.expiresAt = expiresAt

		s.items[key] = e
		s.pushFront(e)
		return
	}

	e := &entry{
		key:       key,
		value:     value,
		expiresAt: expiresAt,
	}

	s.items[key] = e
	s.pushFront(e)
}

// Get retrieves a DNS record from the cache and enforces TTL validity.
//
// Operational behavior:
//   - Lazy Eviction: If the current time exceeds the record expiration timestamp,
//     the expired entry is immediately unlinked from the list, deleted from the map,
//     and the method returns false without allocating memory.
//   - Hot-Key Fast-Path: If the accessed entry is already at the head of the list
//     (typical for high-traffic apex and NS records), list mutation is bypassed,
//     eliminating redundant memory writes.
//   - LRU Promotion: If the entry resides deeper in the list, it is unlinked and
//     promoted to the head as the most recently used item.
//
// WARNING: The returned dns.RRSet and its underlying RData slices are zero-copy references
// to the internal cache state. Callers MUST NOT mutate the returned structures.
func (c *Cache) Get(key Key) (dns.RRSet, bool) {
	s := c.getShard(key)
	now := time.Now().UnixNano()

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.items[key]
	if !ok {
		return dns.RRSet{}, false
	}

	if now >= e.expiresAt {
		s.remove(e)
		delete(s.items, e.key)
		return dns.RRSet{}, false
	}

	if s.head.next != e {
		s.remove(e)
		s.pushFront(e)
	}

	return e.value, true
}

// Delete explicitly removes a record from both the hash map and the LRU linked list.
// If the key does not exist in the shard, the operation safely no-ops.
func (c *Cache) Delete(key Key) {
	s := c.getShard(key)

	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.items[key]; ok {
		s.remove(e)
		delete(s.items, e.key)
	}
}

// Clear purges all entries across all 256 memory shards and resets internal head/tail
// sentinel pointers, restoring the cache to a clean, empty state ready for immediate reuse.
func (c *Cache) Clear() {
	for i := range shardCount {
		s := &c.shards[i]
		s.mu.Lock()
		clear(s.items)
		s.head.next = s.tail
		s.tail.prev = s.head
		s.mu.Unlock()
	}
}

// Len returns the aggregate count of entries currently held across all shards.
func (c *Cache) Len() int {
	var total int
	for i := range shardCount {
		s := &c.shards[i]
		s.mu.Lock()
		total += len(s.items)
		s.mu.Unlock()
	}
	return total
}
