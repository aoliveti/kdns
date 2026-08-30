// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnssec

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestKey_ECDSA_Creation(t *testing.T) {
	t.Parallel()

	key, err := NewECDSAKey("example.com.", FlagZSK)
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, ECDSAP256, key.Algorithm)
	assert.NotZero(t, key.KeyTag)
	assert.Equal(t, "example.com.", key.Zone)
}

func TestKey_Ed25519_Creation(t *testing.T) {
	t.Parallel()

	key, err := NewEd25519Key("example.com.", FlagKSK)
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, ED25519, key.Algorithm)
	assert.NotZero(t, key.KeyTag)
	assert.Equal(t, "example.com.", key.Zone)
}

func TestManager_DNSKEYAndDS(t *testing.T) {
	t.Parallel()

	ksk, err := NewECDSAKey("example.com.", FlagKSK)
	require.NoError(t, err)

	mgr := NewManager()
	mgr.Add(ksk)
	assert.True(t, mgr.HasKeys("example.com."))

	dnskey, ok := mgr.DNSKEY("example.com.", 3600)
	require.True(t, ok)
	assert.Equal(t, dns.TypeDNSKEY, dnskey.Type)
	assert.Equal(t, uint32(3600), dnskey.TTL)
	assert.Len(t, dnskey.RData, 1)

	ds, err := mgr.DS("example.com.", ksk)
	require.NoError(t, err)
	assert.Equal(t, dns.TypeDS, ds.Type)
	assert.Equal(t, uint32(300), ds.TTL)
	assert.Len(t, ds.RData, 1)

	assert.Equal(t, ksk.KeyTag, ksk.Tag())
	assert.Error(t, ErrNoKeysFound)
	assert.Error(t, ErrUnsupportedAlgorithm)
}

func TestManager_SignResult_ApexDNSKEY(t *testing.T) {
	t.Parallel()

	key, err := NewECDSAKey("example.com.", FlagKSK|FlagZSK)
	require.NoError(t, err)

	mgr := NewManager()
	mgr.Add(key)

	var res dns.Result
	now := time.Now()
	mgr.SignResult("example.com.", dns.TypeDNSKEY, &res, now)

	assert.Equal(t, dns.RCodeSuccess, res.RCode)
	require.True(t, res.HasAnswer())
	assert.Equal(t, dns.TypeDNSKEY, res.Answer.Type)
	assert.True(t, res.HasAnswerRRSIG())
	assert.Equal(t, dns.TypeRRSIG, res.AnswerRRSIG.Type)
}

func TestManager_SignResult_PositiveAnswer(t *testing.T) {
	t.Parallel()

	key, err := NewECDSAKey("example.com.", FlagZSK)
	require.NoError(t, err)

	mgr := NewManager()
	mgr.Add(key)

	res := dns.Result{
		RCode: dns.RCodeSuccess,
		Answer: dns.RRSet{
			Type: dns.TypeA,
			TTL:  300,
			RData: [][]byte{
				{192, 0, 2, 1},
			},
		},
	}
	now := time.Now()
	mgr.SignResult("sub.example.com.", dns.TypeA, &res, now)

	assert.Equal(t, dns.RCodeSuccess, res.RCode)
	require.True(t, res.HasAnswerRRSIG())
	assert.Equal(t, dns.TypeRRSIG, res.AnswerRRSIG.Type)
}

func TestManager_SignResult_NXDOMAIN_And_NODATA(t *testing.T) {
	t.Parallel()

	key, err := NewECDSAKey("example.com.", FlagZSK)
	require.NoError(t, err)

	mgr := NewManager()
	mgr.Add(key)

	now := time.Now()

	// NXDOMAIN denial
	nxRes := dns.Result{RCode: dns.RCodeNameError}
	mgr.SignResult("nonexistent.example.com.", dns.TypeA, &nxRes, now)

	assert.Equal(t, dns.RCodeNameError, nxRes.RCode)
	require.True(t, nxRes.HasAuthority())
	assert.Equal(t, dns.TypeNSEC, nxRes.Authority.Type)
	require.True(t, nxRes.HasAuthorityRRSIG())
	assert.Equal(t, dns.TypeRRSIG, nxRes.AuthorityRRSIG.Type)

	// NODATA denial
	noDataRes := dns.Result{RCode: dns.RCodeSuccess}
	mgr.SignResult("example.com.", dns.TypeAAAA, &noDataRes, now)

	assert.Equal(t, dns.RCodeSuccess, noDataRes.RCode)
	require.True(t, noDataRes.HasAuthority())
	assert.Equal(t, dns.TypeNSEC, noDataRes.Authority.Type)
	require.True(t, noDataRes.HasAuthorityRRSIG())
}

func TestManager_SignResult_NilGuards(t *testing.T) {
	t.Parallel()

	var mgr *Manager
	res := dns.Result{RCode: dns.RCodeSuccess}
	mgr.SignResult("example.com.", dns.TypeA, &res, time.Now())
	mgr.SignResult("example.com.", dns.TypeA, nil, time.Now())

	realMgr := NewManager()
	realMgr.SignResult("example.com.", dns.TypeA, nil, time.Now())
}

func TestKey_DS_MethodAndKeysForZone(t *testing.T) {
	t.Parallel()

	key, err := NewECDSAKey("sub.example.com.", FlagKSK)
	require.NoError(t, err)

	dsBytes := key.DS()
	require.NotEmpty(t, dsBytes)
	assert.Len(t, dsBytes, 4+32)

	mgr := NewManager()
	mgr.Add(key)
	rootKey, err := NewECDSAKey(".", FlagZSK)
	require.NoError(t, err)
	mgr.Add(rootKey)

	// KeysForZone exact match
	k1 := mgr.KeysForZone("sub.example.com.")
	require.NotEmpty(t, k1)
	assert.Equal(t, "sub.example.com.", k1[0].Zone)

	// KeysForZone fallback to root
	k2 := mgr.KeysForZone("other.domain.com.")
	require.NotEmpty(t, k2)
	assert.Equal(t, ".", k2[0].Zone)

	// KeysForZone on empty manager
	emptyMgr := NewManager()
	assert.Nil(t, emptyMgr.KeysForZone("test.com."))
	assert.False(t, emptyMgr.HasKeys("test.com."))
	mgr.Add(nil) // nil guard
}
