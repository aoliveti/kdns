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

func TestECDSA_SigningAndVerification(t *testing.T) {
	t.Parallel()

	key, err := NewECDSAKey("example.com.", FlagZSK)
	require.NoError(t, err)
	require.NotNil(t, key)

	record := dns.NewRRSet(dns.TypeA, 300, "1.2.3.4", "5.6.7.8")

	now := time.Now()
	inception := now.Add(-1 * time.Hour)
	expiration := now.Add(24 * time.Hour)

	sig, err := Sign("host.example.com.", record, key, inception, expiration)
	require.NoError(t, err)
	require.Len(t, sig.RData, 1)

	rrsigWire := sig.RData[0]
	err = Verify("host.example.com.", record, rrsigWire, key.PublicKey, key.Algorithm)
	require.NoError(t, err)

	tamperedRecord := dns.NewRRSet(dns.TypeA, 300, "9.9.9.9", "5.6.7.8")
	err = Verify("host.example.com.", tamperedRecord, rrsigWire, key.PublicKey, key.Algorithm)
	require.ErrorIs(t, err, ErrInvalidSignature)
}

func TestEd25519_SigningAndVerification(t *testing.T) {
	t.Parallel()

	key, err := NewEd25519Key("example.com.", FlagZSK)
	require.NoError(t, err)
	require.NotNil(t, key)

	record := dns.NewRRSet(dns.TypeTXT, 300, "v=spf1 ~all")

	now := time.Now()
	inception := now.Add(-1 * time.Hour)
	expiration := now.Add(24 * time.Hour)

	sig, err := Sign("txt.example.com.", record, key, inception, expiration)
	require.NoError(t, err)
	require.Len(t, sig.RData, 1)

	rrsigWire := sig.RData[0]
	err = Verify("txt.example.com.", record, rrsigWire, key.PublicKey, key.Algorithm)
	require.NoError(t, err)
}

func TestNSEC_Build(t *testing.T) {
	t.Parallel()

	types := []dns.Type{dns.TypeA, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC}
	nsecRecord, err := NSEC("host.example.com.", "example.com.", types, 300)
	require.NoError(t, err)

	assert.Equal(t, dns.TypeNSEC, nsecRecord.Type)
	assert.Equal(t, uint32(300), nsecRecord.TTL)
	require.Len(t, nsecRecord.RData, 1)
	assert.NotEmpty(t, nsecRecord.RData[0])
}

func TestManager_SignResult(t *testing.T) {
	t.Parallel()

	zsk, err := NewECDSAKey("example.com.", FlagZSK)
	require.NoError(t, err)
	ksk, err := NewECDSAKey("example.com.", FlagKSK)
	require.NoError(t, err)

	mgr := NewManager()
	mgr.Add(zsk)
	mgr.Add(ksk)

	record := dns.NewRRSet(dns.TypeA, 300, "1.2.3.4")

	result := dns.Result{
		RCode:  dns.RCodeSuccess,
		Answer: record,
	}

	now := time.Now()
	mgr.SignResult("host.example.com.", dns.TypeA, &result, now)
	assert.NotEmpty(t, result.AnswerRRSIG.RData)

	// Test NXDOMAIN signing (NSEC + RRSIG in authority)
	nxResult := dns.Result{
		RCode: dns.RCodeNameError,
	}
	mgr.SignResult("nonexistent.example.com.", dns.TypeA, &nxResult, now)
	assert.Equal(t, dns.TypeNSEC, nxResult.Authority.Type)
	assert.NotEmpty(t, nxResult.AuthorityRRSIG.RData)
}
