// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rfc2136

import (
	"encoding/binary"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

type memoryGetter struct {
	records map[string]dns.RRSets
	mu      sync.RWMutex
}

func newMemoryGetter() *memoryGetter {
	return &memoryGetter{records: make(map[string]dns.RRSets)}
}

func (m *memoryGetter) Get(domain string) (dns.RRSets, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sets, ok := m.records[canonicalName(domain)]
	return sets, ok
}

func (m *memoryGetter) set(domain string, records dns.RRSets) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[canonicalName(domain)] = records
}

type memoryUpsertDeleter struct {
	records map[string]dns.RRSets
	mu      sync.RWMutex
}

func newMemoryUpsertDeleter() *memoryUpsertDeleter {
	return &memoryUpsertDeleter{records: make(map[string]dns.RRSets)}
}

func (m *memoryUpsertDeleter) Upsert(domain string, records dns.RRSets) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[canonicalName(domain)] = records
	return nil
}

func (m *memoryUpsertDeleter) DeleteDomain(domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, canonicalName(domain))
	return nil
}

func (m *memoryUpsertDeleter) Get(domain string) (dns.RRSets, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	records, ok := m.records[canonicalName(domain)]
	return records, ok
}

func mustWire(qType dns.Type, text string) []byte {
	wire, err := dns.PackRData(qType, text)
	if err != nil {
		panic(err)
	}
	return wire
}

type packetBuilder struct {
	buf []byte
}

func newUpdateBuilder(zone string) *packetBuilder {
	b := &packetBuilder{buf: make([]byte, 12)}
	binary.BigEndian.PutUint16(b.buf[0:2], 0x1234)
	binary.BigEndian.PutUint16(b.buf[2:4], 0x2800) // OpcodeUpdate (0x2800)
	binary.BigEndian.PutUint16(b.buf[4:6], 1)      // QDCOUNT=1

	// Zone section: zname, ztype=SOA, zclass=IN
	b.buf = append(b.buf, dns.EncodeDomainName(zone)...)
	var zTypeClass [4]byte
	binary.BigEndian.PutUint16(zTypeClass[0:2], uint16(dns.TypeSOA))
	binary.BigEndian.PutUint16(zTypeClass[2:4], uint16(dns.ClassIN))
	b.buf = append(b.buf, zTypeClass[:]...)
	return b
}

func (b *packetBuilder) addPrereq(name string, qType dns.Type, class dns.Class, rData []byte) {
	b.buf = append(b.buf, dns.EncodeDomainName(name)...)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(qType))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(class))
	binary.BigEndian.PutUint32(hdr[4:8], 0)
	rDataLen := min(len(rData), 65535)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(rDataLen))
	b.buf = append(b.buf, hdr[:]...)
	if rDataLen > 0 {
		b.buf = append(b.buf, rData[:rDataLen]...)
	}
	anCount := binary.BigEndian.Uint16(b.buf[6:8])
	binary.BigEndian.PutUint16(b.buf[6:8], anCount+1)
}

func (b *packetBuilder) addUpdate(name string, qType dns.Type, class dns.Class, ttl uint32, rData []byte) {
	b.buf = append(b.buf, dns.EncodeDomainName(name)...)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(qType))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(class))
	binary.BigEndian.PutUint32(hdr[4:8], ttl)
	rDataLen := min(len(rData), 65535)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(rDataLen))
	b.buf = append(b.buf, hdr[:]...)
	if rDataLen > 0 {
		b.buf = append(b.buf, rData[:rDataLen]...)
	}
	nsCount := binary.BigEndian.Uint16(b.buf[8:10])
	binary.BigEndian.PutUint16(b.buf[8:10], nsCount+1)
}

func TestRFC2136_Prerequisites(t *testing.T) {
	t.Parallel()

	getter := newMemoryGetter()
	ud := newMemoryUpsertDeleter()

	soaWire := mustWire(dns.TypeSOA, "ns1.example.com. admin.example.com. 2026010101 7200 3600 1209600 300")
	getter.set("example.com.", dns.RRSets{
		{Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{soaWire}},
	})
	getter.set("host.example.com.", dns.RRSets{
		{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{mustWire(dns.TypeA, "1.2.3.4")}},
	})

	t.Run("Rule1_RRSetExistsValueIndependent_Pass", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("host.example.com.", dns.TypeA, dns.ClassANY, nil)
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)
	})

	t.Run("Rule1_RRSetExistsValueIndependent_Fail", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("host.example.com.", dns.TypeTXT, dns.ClassANY, nil)
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNXRRSet, rCode)
	})

	t.Run("Rule2_RRSetExistsValueDependent_Pass", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("host.example.com.", dns.TypeA, dns.ClassIN, mustWire(dns.TypeA, "1.2.3.4"))
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)
	})

	t.Run("Rule2_RRSetExistsValueDependent_Fail", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("host.example.com.", dns.TypeA, dns.ClassIN, mustWire(dns.TypeA, "9.9.9.9"))
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNXRRSet, rCode)
	})

	t.Run("Rule3_RRSetDoesNotExist_Pass", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("host.example.com.", dns.TypeAAAA, dns.ClassNONE, nil)
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)
	})

	t.Run("Rule3_RRSetDoesNotExist_Fail", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("host.example.com.", dns.TypeA, dns.ClassNONE, nil)
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeYXRRSet, rCode)
	})

	t.Run("Rule4_NameIsInUse_Pass", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("host.example.com.", dns.TypeANY, dns.ClassANY, nil)
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)
	})

	t.Run("Rule4_NameIsInUse_Fail", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("absent.example.com.", dns.TypeANY, dns.ClassANY, nil)
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNameError, rCode)
	})

	t.Run("Rule5_NameIsNotInUse_Pass", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("brandnew.example.com.", dns.TypeANY, dns.ClassNONE, nil)
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)
	})

	t.Run("Rule5_NameIsNotInUse_Fail", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("host.example.com.", dns.TypeANY, dns.ClassNONE, nil)
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeYXDomain, rCode)
	})

	t.Run("NotInZoneReturnsNotZone", func(t *testing.T) {
		t.Parallel()
		b := newUpdateBuilder("example.com.")
		b.addPrereq("otherdomain.org.", dns.TypeANY, dns.ClassANY, nil)
		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNotZone, rCode)
	})
}

func TestRFC2136_UpdateOperations(t *testing.T) {
	t.Parallel()

	soaWire := mustWire(dns.TypeSOA, "ns1.example.com. admin.example.com. 2026010101 7200 3600 1209600 300")

	t.Run("Case1_AddRecordsToRRSet", func(t *testing.T) {
		t.Parallel()
		getter := newMemoryGetter()
		ud := newMemoryUpsertDeleter()
		getter.set("example.com.", dns.RRSets{
			{Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{soaWire}},
		})

		b := newUpdateBuilder("example.com.")
		b.addUpdate("newhost.example.com.", dns.TypeA, dns.ClassIN, 300, mustWire(dns.TypeA, "10.0.0.1"))
		b.addUpdate("newhost.example.com.", dns.TypeA, dns.ClassIN, 300, mustWire(dns.TypeA, "10.0.0.2"))

		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		rrs, ok := ud.Get("newhost.example.com.")
		require.True(t, ok)
		aSet, ok := rrs.Get(dns.TypeA)
		require.True(t, ok)
		assert.Len(t, aSet.RData, 2)
	})

	t.Run("Case4_DeleteSingleRRFromRRSet", func(t *testing.T) {
		t.Parallel()
		getter := newMemoryGetter()
		ud := newMemoryUpsertDeleter()
		getter.set("example.com.", dns.RRSets{
			{Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{soaWire}},
		})
		initialRRs := dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{mustWire(dns.TypeA, "10.0.0.1"), mustWire(dns.TypeA, "10.0.0.2")}},
		}
		getter.set("newhost.example.com.", initialRRs)
		_ = ud.Upsert("newhost.example.com.", initialRRs)

		b := newUpdateBuilder("example.com.")
		b.addUpdate("newhost.example.com.", dns.TypeA, dns.ClassNONE, 0, mustWire(dns.TypeA, "10.0.0.1"))

		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		rrs, ok := ud.Get("newhost.example.com.")
		require.True(t, ok)
		aSet, ok := rrs.Get(dns.TypeA)
		require.True(t, ok)
		require.Len(t, aSet.RData, 1)
		assert.Equal(t, mustWire(dns.TypeA, "10.0.0.2"), aSet.RData[0])
	})

	t.Run("Case2_DeleteRRSet", func(t *testing.T) {
		t.Parallel()
		getter := newMemoryGetter()
		ud := newMemoryUpsertDeleter()
		getter.set("example.com.", dns.RRSets{
			{Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{soaWire}},
		})
		initialRRs := dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{mustWire(dns.TypeA, "10.0.0.2")}},
		}
		getter.set("newhost.example.com.", initialRRs)
		_ = ud.Upsert("newhost.example.com.", initialRRs)

		b := newUpdateBuilder("example.com.")
		b.addUpdate("newhost.example.com.", dns.TypeA, dns.ClassANY, 0, nil)

		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		_, ok := ud.Get("newhost.example.com.")
		assert.False(t, ok)
	})

	t.Run("Case3_DeleteAllRRSetsFromName", func(t *testing.T) {
		t.Parallel()
		getter := newMemoryGetter()
		ud := newMemoryUpsertDeleter()
		getter.set("example.com.", dns.RRSets{
			{Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{soaWire}},
		})
		initialRRs := dns.RRSets{
			{Type: dns.TypeA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{mustWire(dns.TypeA, "1.1.1.1")}},
			{Type: dns.TypeTXT, Class: dns.ClassIN, TTL: 300, RData: [][]byte{mustWire(dns.TypeTXT, "sample")}},
		}
		getter.set("multi.example.com.", initialRRs)
		_ = ud.Upsert("multi.example.com.", initialRRs)

		b := newUpdateBuilder("example.com.")
		b.addUpdate("multi.example.com.", dns.TypeANY, dns.ClassANY, 0, nil)

		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		_, ok := ud.Get("multi.example.com.")
		assert.False(t, ok)
	})

	t.Run("SubzoneUpdate", func(t *testing.T) {
		t.Parallel()
		getter := newMemoryGetter()
		ud := newMemoryUpsertDeleter()
		getter.set("sub.example.org.", dns.RRSets{
			{Type: dns.TypeSOA, Class: dns.ClassIN, TTL: 300, RData: [][]byte{soaWire}},
		})
		b := newUpdateBuilder("sub.example.org.")
		b.addUpdate("api.sub.example.org.", dns.TypeA, dns.ClassIN, 300, mustWire(dns.TypeA, "5.6.7.8"))

		rCode, err := Process(b.buf, getter, ud)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		rrs, ok := ud.Get("api.sub.example.org.")
		require.True(t, ok)
		assert.NotEmpty(t, rrs)
	})
}
