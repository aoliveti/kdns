// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rrl implements high-performance, zero-allocation Response Rate Limiting (RRL)
// for authoritative DNS servers in accordance with BCP 140 specifications.
//
// DNS over UDP is inherently susceptible to source IP spoofing, enabling Distributed
// Reflection and Amplification Denial of Service attacks against third-party victims,
// as well as Pseudo-Random Subdomain (PRSD / Water Torture) floods targeting authoritative
// zones. RRL protects both the DNS infrastructure and reflection victims by enforcing
// token bucket rate limits per client subnet prefix, response classification, and FQDN.
package rrl

import (
	"math/bits"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/cpu"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	// DefaultResponsesPerSecond defines the token bucket capacity for successful (NOERROR) responses
	// allocated per second per client subnet prefix.
	DefaultResponsesPerSecond = 50

	// DefaultErrorsPerSecond defines the token bucket capacity for error and NXDOMAIN responses.
	// Error budgets are intentionally smaller to rapidly suppress PRSD attacks.
	DefaultErrorsPerSecond = 10

	// DefaultSlipRate defines the cadence at which rate-limited responses are returned with the
	// DNS TC (Truncated) bit set to prompt legitimate recursive resolvers to retry over TCP.
	DefaultSlipRate = 2

	// DefaultTableSize defines the total pre-allocated slot capacity across all memory shards.
	DefaultTableSize = 65536

	// DefaultIPv4Prefix defines the standard CIDR prefix length for IPv4 source aggregation (/24).
	DefaultIPv4Prefix = 24

	// DefaultIPv6Prefix defines the standard CIDR prefix length for IPv6 source aggregation (/56).
	DefaultIPv6Prefix = 56

	numShards = 64
)

// responseClass categorizes DNS response types to isolate rate limits across distinct traffic profiles.
type responseClass uint8

const (
	// classPositive tracks NOERROR responses containing positive answer records.
	classPositive responseClass = iota

	// classNXDomain tracks NXDOMAIN responses to mitigate PRSD and random subdomain floods.
	classNXDomain

	// classError tracks server failures, format errors, and administrative refusals.
	classError
)

// Action defines the enforcement decision returned by the RRL engine per BCP 140.
type Action uint8

const (
	// ActionAllow transmits the response normally to the client.
	ActionAllow Action = iota

	// ActionDrop drops the response silently to eliminate amplification bandwidth toward spoofed targets.
	ActionDrop

	// ActionSlip returns a response with the TC (Truncated) bit set, prompting legitimate resolvers
	// to retry over stateful TCP while dropping spoofed attacker traffic.
	ActionSlip
)

// String returns the canonical BCP 140 string representation of the action.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionDrop:
		return "DROP"
	case ActionSlip:
		return "SLIP"
	default:
		return "UNKNOWN"
	}
}

// Config defines the operational parameters for rate evaluation and subnet grouping.
type Config struct {
	ResponsesPerSecond int
	ErrorsPerSecond    int
	SlipRate           int
	TableSize          int
	IPv4Prefix         int
	IPv6Prefix         int
}

// DefaultConfig returns the standard BCP 140 recommended configuration parameters.
func DefaultConfig() Config {
	return Config{
		ResponsesPerSecond: DefaultResponsesPerSecond,
		ErrorsPerSecond:    DefaultErrorsPerSecond,
		SlipRate:           DefaultSlipRate,
		TableSize:          DefaultTableSize,
		IPv4Prefix:         DefaultIPv4Prefix,
		IPv6Prefix:         DefaultIPv6Prefix,
	}
}

// slot represents a 16-byte rate-tracking record aligned to avoid cache-line splitting.
type slot struct {
	keyHash   uint64
	timestamp uint32
	tokens    uint16
	slipCount uint16
}

// shard isolates a slot partition behind an independent mutex.
// CacheLinePad prevents false sharing when adjacent shards are locked simultaneously across CPU cores.
type shard struct {
	slots []slot
	mu    sync.Mutex
	_     cpu.CacheLinePad
}

// Limiter coordinates partitioned token buckets to mitigate DNS reflection and PRSD water-torture attacks.
// All operations are lock-striped across memory shards and execute with zero heap allocations.
type Limiter struct {
	shards    [numShards]shard
	cfg       Config
	shardMask uint64
	slotMask  uint64
}

// New initializes an RRL Limiter with pre-allocated memory shards and validated configuration limits.
func New(cfg Config) *Limiter {
	if cfg.ResponsesPerSecond <= 0 {
		cfg.ResponsesPerSecond = DefaultResponsesPerSecond
	}
	if cfg.ErrorsPerSecond <= 0 {
		cfg.ErrorsPerSecond = DefaultErrorsPerSecond
	}
	if cfg.SlipRate < 0 {
		cfg.SlipRate = DefaultSlipRate
	}
	if cfg.TableSize <= 0 {
		cfg.TableSize = DefaultTableSize
	}
	if cfg.IPv4Prefix <= 0 || cfg.IPv4Prefix > 32 {
		cfg.IPv4Prefix = DefaultIPv4Prefix
	}
	if cfg.IPv6Prefix <= 0 || cfg.IPv6Prefix > 128 {
		cfg.IPv6Prefix = DefaultIPv6Prefix
	}

	tableSize := roundUpPowerOfTwo(cfg.TableSize)
	slotsPerShard := max(1, tableSize/numShards)
	slotsPerShard = roundUpPowerOfTwo(slotsPerShard)
	cfg.TableSize = slotsPerShard * numShards

	l := &Limiter{
		cfg:       cfg,
		shardMask: numShards - 1,
		// #nosec G115
		slotMask: uint64(slotsPerShard - 1),
	}

	for i := range numShards {
		l.shards[i].slots = make([]slot, slotsPerShard)
	}

	return l
}

// Check evaluates an outbound DNS response against rate policies without heap allocations.
func (l *Limiter) Check(clientIP netip.Addr, domain string, rCode dns.RCode) Action {
	// #nosec G115
	now := uint32(time.Now().Unix())
	return l.checkAt(clientIP, domain, rCode, now)
}

// checkAt evaluates rate limits at an explicit epoch timestamp for deterministic execution and testing.
func (l *Limiter) checkAt(clientIP netip.Addr, domain string, rCode dns.RCode, now uint32) Action {
	if !clientIP.IsValid() {
		return ActionAllow
	}

	class := classifyRCode(rCode)
	hash := l.hashKey(clientIP, class, domain)

	shardIndex := (hash >> 58) & l.shardMask
	slotIndex := hash & l.slotMask

	s := &l.shards[shardIndex]
	s.mu.Lock()
	defer s.mu.Unlock()

	sl := &s.slots[slotIndex]

	limit := l.cfg.ResponsesPerSecond
	if class != classPositive {
		limit = l.cfg.ErrorsPerSecond
	}

	// Slot collision or uninitialized slot: evict previous occupant and start new accounting stream.
	if sl.keyHash != hash {
		sl.keyHash = hash
		sl.timestamp = now
		sl.tokens = 1
		sl.slipCount = 0
		return ActionAllow
	}

	// Protect against backward clock drift.
	if now < sl.timestamp {
		sl.timestamp = now
	}

	// Decay accumulated tokens and reset slip cadence across second boundaries.
	if elapsed := now - sl.timestamp; elapsed > 0 {
		// #nosec G115
		decay := elapsed * uint32(limit)
		current := uint32(sl.tokens)
		sl.tokens = 0
		if decay < current {
			// #nosec G115
			sl.tokens = uint16(current - decay)
		}
		sl.timestamp = now
		sl.slipCount = 0
	}

	if int(sl.tokens) < limit {
		sl.tokens++
		return ActionAllow
	}

	// #nosec G115
	sl.tokens = uint16(limit)

	// Emit truncated response (TC=1) every SlipRate occurrences to trigger TCP fallback.
	if l.cfg.SlipRate > 0 {
		sl.slipCount++
		if int(sl.slipCount) >= l.cfg.SlipRate {
			sl.slipCount = 0
			return ActionSlip
		}
	}

	return ActionDrop
}

// hashKey computes a 64-bit non-cryptographic mixer hash over subnet, response class, and case-folded domain.
// Non-positive responses omit the domain name to aggregate NXDOMAIN and PRSD floods per subnet.
func (l *Limiter) hashKey(ip netip.Addr, class responseClass, domain string) uint64 {
	h := 0x517cc1b727220a95 ^ l.hashSubnet(ip)
	h = (h ^ uint64(class)) * 0xbf58476d1ce4e5b9

	if class == classPositive {
		for i := range len(domain) {
			c := domain[i]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			h = (h ^ uint64(c)) * 0x94d049bb133111eb
		}
	}

	return h ^ (h >> 32)
}

// hashSubnet extracts the network prefix in network byte order based on configured prefix lengths.
// IPv4-mapped IPv6 addresses are unmapped to ensure consistent classification with native IPv4 queries.
func (l *Limiter) hashSubnet(ip netip.Addr) uint64 {
	if ip.Is4() || ip.Is4In6() {
		octets4 := ip.Unmap().As4()
		mask := ^uint32(0) << (32 - l.cfg.IPv4Prefix)
		subnet := (uint32(octets4[0])<<24 | uint32(octets4[1])<<16 | uint32(octets4[2])<<8 | uint32(octets4[3])) & mask
		return uint64(subnet)
	}

	octets16 := ip.As16()
	var hi, lo uint64
	for i := range 8 {
		hi = (hi << 8) | uint64(octets16[i])
		lo = (lo << 8) | uint64(octets16[i+8])
	}

	if l.cfg.IPv6Prefix <= 64 {
		mask := ^uint64(0) << (64 - l.cfg.IPv6Prefix)
		return hi & mask
	}

	mask := ^uint64(0) << (128 - l.cfg.IPv6Prefix)
	return hi ^ (lo & mask)
}

// classifyRCode maps DNS response codes to coarse-grained rate-limiting categories.
func classifyRCode(rCode dns.RCode) responseClass {
	switch rCode {
	case dns.RCodeSuccess:
		return classPositive
	case dns.RCodeNameError:
		return classNXDomain
	default:
		return classError
	}
}

// roundUpPowerOfTwo calculates the nearest power of two greater than or equal to v.
func roundUpPowerOfTwo(v int) int {
	if v <= 1 {
		return 1
	}
	// #nosec G115
	return 1 << bits.Len(uint(v-1))
}
