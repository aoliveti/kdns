// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rrl

import (
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestLimiter_AllowUnderLimit(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ResponsesPerSecond: 5,
		ErrorsPerSecond:    2,
		SlipRate:           2,
		TableSize:          1024,
		IPv4Prefix:         24,
		IPv6Prefix:         56,
	}
	limiter := New(cfg)
	ip := netip.MustParseAddr("192.0.2.1")
	domain := "example.com"
	now := uint32(1000)

	for i := range 5 {
		action := limiter.checkAt(ip, domain, dns.RCodeSuccess, now)
		assert.Equal(t, ActionAllow, action, "request %d should be allowed", i+1)
	}

	action6 := limiter.checkAt(ip, domain, dns.RCodeSuccess, now)
	assert.Equal(t, ActionDrop, action6)

	action7 := limiter.checkAt(ip, domain, dns.RCodeSuccess, now)
	assert.Equal(t, ActionSlip, action7)

	action8 := limiter.checkAt(ip, domain, dns.RCodeSuccess, now)
	assert.Equal(t, ActionDrop, action8)
}

func TestLimiter_ErrorsLimit(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ResponsesPerSecond: 10,
		ErrorsPerSecond:    3,
		SlipRate:           0,
		TableSize:          1024,
		IPv4Prefix:         24,
		IPv6Prefix:         56,
	}
	limiter := New(cfg)
	ip := netip.MustParseAddr("198.51.100.10")
	domain := "missing.example.com"
	now := uint32(2000)

	for i := range 3 {
		action := limiter.checkAt(ip, domain, dns.RCodeNameError, now)
		assert.Equal(t, ActionAllow, action, "error %d should be allowed", i+1)
	}

	action4 := limiter.checkAt(ip, domain, dns.RCodeNameError, now)
	assert.Equal(t, ActionDrop, action4)
}

func TestLimiter_CaseInsensitivity(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ResponsesPerSecond: 2,
		ErrorsPerSecond:    1,
		SlipRate:           0,
		TableSize:          1024,
		IPv4Prefix:         24,
		IPv6Prefix:         56,
	}
	limiter := New(cfg)
	ip := netip.MustParseAddr("192.0.2.15")
	now := uint32(3000)

	assert.Equal(t, ActionAllow, limiter.checkAt(ip, "ExAmPlE.CoM", dns.RCodeSuccess, now))
	assert.Equal(t, ActionAllow, limiter.checkAt(ip, "example.com", dns.RCodeSuccess, now))
	assert.Equal(t, ActionDrop, limiter.checkAt(ip, "EXAMPLE.COM", dns.RCodeSuccess, now))
}

func TestLimiter_SlotEvictionOnCollision(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ResponsesPerSecond: 1,
		ErrorsPerSecond:    1,
		SlipRate:           0,
		TableSize:          1,
		IPv4Prefix:         24,
		IPv6Prefix:         56,
	}
	limiter := New(cfg)
	ip1 := netip.MustParseAddr("192.0.2.1")
	ip2 := netip.MustParseAddr("198.51.100.1")
	now := uint32(5000)

	assert.Equal(t, ActionAllow, limiter.checkAt(ip1, "domain1.com", dns.RCodeSuccess, now))
	assert.Equal(t, ActionDrop, limiter.checkAt(ip1, "domain1.com", dns.RCodeSuccess, now))

	assert.Equal(t, ActionAllow, limiter.checkAt(ip2, "domain2.com", dns.RCodeSuccess, now))
}

func TestLimiter_ClockStepBackward(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ResponsesPerSecond: 2,
		ErrorsPerSecond:    1,
		SlipRate:           0,
		TableSize:          1024,
		IPv4Prefix:         24,
		IPv6Prefix:         56,
	}
	limiter := New(cfg)
	ip := netip.MustParseAddr("192.0.2.50")
	domain := "clock.test"

	assert.Equal(t, ActionAllow, limiter.checkAt(ip, domain, dns.RCodeSuccess, 2000))
	assert.Equal(t, ActionAllow, limiter.checkAt(ip, domain, dns.RCodeSuccess, 2000))
	assert.Equal(t, ActionDrop, limiter.checkAt(ip, domain, dns.RCodeSuccess, 2000))

	assert.Equal(t, ActionDrop, limiter.checkAt(ip, domain, dns.RCodeSuccess, 1950))
	assert.Equal(t, ActionAllow, limiter.checkAt(ip, domain, dns.RCodeSuccess, 1952))
}

func TestLimiter_PRSDWaterTorture(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ResponsesPerSecond: 10,
		ErrorsPerSecond:    2,
		SlipRate:           0,
		TableSize:          1024,
		IPv4Prefix:         24,
		IPv6Prefix:         56,
	}
	limiter := New(cfg)
	ip := netip.MustParseAddr("203.0.113.1")
	now := uint32(6000)

	assert.Equal(t, ActionAllow, limiter.checkAt(ip, "rand1.victim.com", dns.RCodeNameError, now))
	assert.Equal(t, ActionAllow, limiter.checkAt(ip, "rand2.victim.com", dns.RCodeNameError, now))
	assert.Equal(t, ActionDrop, limiter.checkAt(ip, "rand3.victim.com", dns.RCodeNameError, now))

	assert.Equal(t, ActionAllow, limiter.checkAt(ip, "legit.example.com", dns.RCodeSuccess, now))
}

func TestLimiter_TimeDecay(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ResponsesPerSecond: 2,
		ErrorsPerSecond:    1,
		SlipRate:           2,
		TableSize:          1024,
		IPv4Prefix:         24,
		IPv6Prefix:         56,
	}
	limiter := New(cfg)
	ip := netip.MustParseAddr("203.0.113.5")
	domain := "decay.test"

	assert.Equal(t, ActionAllow, limiter.checkAt(ip, domain, dns.RCodeSuccess, 100))
	assert.Equal(t, ActionAllow, limiter.checkAt(ip, domain, dns.RCodeSuccess, 100))
	assert.Equal(t, ActionDrop, limiter.checkAt(ip, domain, dns.RCodeSuccess, 100))

	assert.Equal(t, ActionAllow, limiter.checkAt(ip, domain, dns.RCodeSuccess, 101))
	assert.Equal(t, ActionAllow, limiter.checkAt(ip, domain, dns.RCodeSuccess, 101))
	assert.Equal(t, ActionDrop, limiter.checkAt(ip, domain, dns.RCodeSuccess, 101))

	assert.Equal(t, ActionAllow, limiter.checkAt(ip, domain, dns.RCodeSuccess, 110))
}

func TestLimiter_Subnets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		domain string
		ip1    string
		ip2    string
		ipDiff string
	}{
		{
			name:   "IPv4_Subnet24",
			domain: "subnet.test",
			ip1:    "192.0.2.1",
			ip2:    "192.0.2.200",
			ipDiff: "192.0.3.1",
		},
		{
			name:   "IPv4MappedIPv6",
			domain: "mapped.test",
			ip1:    "192.0.2.1",
			ip2:    "::ffff:192.0.2.100",
			ipDiff: "198.51.100.1",
		},
		{
			name:   "IPv6_Subnet56",
			domain: "ipv6.test",
			ip1:    "2001:db8:abcd:1234::1",
			ip2:    "2001:db8:abcd:12ff::99",
			ipDiff: "2001:db8:abcd:3400::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := Config{
				ResponsesPerSecond: 2,
				ErrorsPerSecond:    1,
				SlipRate:           0,
				TableSize:          1024,
				IPv4Prefix:         24,
				IPv6Prefix:         56,
			}
			limiter := New(cfg)
			ip1 := netip.MustParseAddr(tc.ip1)
			ip2 := netip.MustParseAddr(tc.ip2)
			ipDiff := netip.MustParseAddr(tc.ipDiff)
			now := uint32(500)

			assert.Equal(t, ActionAllow, limiter.checkAt(ip1, tc.domain, dns.RCodeSuccess, now))
			assert.Equal(t, ActionAllow, limiter.checkAt(ip2, tc.domain, dns.RCodeSuccess, now))
			assert.Equal(t, ActionDrop, limiter.checkAt(ip1, tc.domain, dns.RCodeSuccess, now))

			assert.Equal(t, ActionAllow, limiter.checkAt(ipDiff, tc.domain, dns.RCodeSuccess, now))
		})
	}
}

func TestLimiter_InvalidIP(t *testing.T) {
	t.Parallel()

	limiter := New(DefaultConfig())
	action := limiter.Check(netip.Addr{}, "example.com", dns.RCodeSuccess)
	assert.Equal(t, ActionAllow, action)
}

func TestLimiter_Concurrent(t *testing.T) {
	t.Parallel()

	limiter := New(DefaultConfig())
	var wg sync.WaitGroup

	numWorkers := 16
	requestsPerWorker := 1000

	for i := range numWorkers {
		wg.Go(func() {
			workerID := i
			ip := netip.MustParseAddr("10.0.0.1")
			if workerID%2 == 0 {
				ip = netip.MustParseAddr("10.0.1.1")
			}
			for range requestsPerWorker {
				action := limiter.Check(ip, "concurrent.test", dns.RCodeSuccess)
				require.Contains(t, []Action{ActionAllow, ActionDrop, ActionSlip}, action)
			}
		})
	}

	wg.Wait()
}

func TestAction_String(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "ALLOW", ActionAllow.String())
	assert.Equal(t, "DROP", ActionDrop.String())
	assert.Equal(t, "SLIP", ActionSlip.String())
	assert.Equal(t, "UNKNOWN", Action(99).String())
}

func TestLimiter_SynctestTimeDecay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := Config{
			ResponsesPerSecond: 2,
			ErrorsPerSecond:    1,
			SlipRate:           2,
			TableSize:          1024,
			IPv4Prefix:         24,
			IPv6Prefix:         56,
		}
		limiter := New(cfg)
		ip := netip.MustParseAddr("198.51.100.77")
		domain := "synctest.example.com"

		// Initial bucket capacity = 2
		assert.Equal(t, ActionAllow, limiter.Check(ip, domain, dns.RCodeSuccess))
		assert.Equal(t, ActionAllow, limiter.Check(ip, domain, dns.RCodeSuccess))
		assert.Equal(t, ActionDrop, limiter.Check(ip, domain, dns.RCodeSuccess))

		// Advance virtual time by 1 second instantly without wall-clock delay
		time.Sleep(1 * time.Second)

		// Bucket replenished by 2 tokens
		assert.Equal(t, ActionAllow, limiter.Check(ip, domain, dns.RCodeSuccess))
		assert.Equal(t, ActionAllow, limiter.Check(ip, domain, dns.RCodeSuccess))
		assert.Equal(t, ActionDrop, limiter.Check(ip, domain, dns.RCodeSuccess))
	})
}
