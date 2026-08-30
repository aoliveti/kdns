// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package state

import (
	"time"

	"github.com/aoliveti/kdns/internal/cache"
	"github.com/aoliveti/kdns/internal/dns"
)

// Resolve resolves a DNS data-plane query, backed by the LRU cache.
// Positive answer hits are cached; negative responses traverse the Radix tree.
func (s *State) Resolve(domain string, qType dns.Type) dns.Result {
	cacheKey := cache.Key{
		Name: toLowerASCII(domain),
		Type: qType,
	}

	if record, found := s.cache.Get(cacheKey); found {
		s.metrics.IncCacheHit()
		return dns.Result{
			RCode:  dns.RCodeSuccess,
			Answer: record,
		}
	}

	s.metrics.IncCacheMiss()

	res := s.tree.Load().Resolve(domain, qType)
	if res.RCode == dns.RCodeSuccess && res.HasAnswer() {
		ttlDuration := time.Duration(res.Answer.TTL) * time.Second
		s.cache.Set(cacheKey, res.Answer, ttlDuration)
	}

	return res
}

func toLowerASCII(s string) string {
	hasUpper := false
	for i := range len(s) {
		if s[i] >= 'A' && s[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}

	out := make([]byte, len(s))
	for i := range len(s) {
		b := s[i]
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		out[i] = b
	}
	return string(out)
}
