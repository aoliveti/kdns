// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsig

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func buildSignedQuery(t *testing.T, domain string, qType dns.Type, key Key, now time.Time) []byte {
	t.Helper()
	var buf [4096]byte

	binary.BigEndian.PutUint16(buf[0:2], 0x1234)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 1)

	offset := 12
	qWire := dns.EncodeDomainName(domain)
	copy(buf[offset:], qWire)
	offset += len(qWire)

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(qType))
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(dns.ClassIN))
	offset += 2

	signedLen, err := Sign(buf[:], offset, nil, key, 0, now)
	require.NoError(t, err)

	out := make([]byte, signedLen)
	copy(out, buf[:signedLen])
	return out
}

func TestTSIG_RoundTripVerification(t *testing.T) {
	t.Parallel()

	algorithms := []struct {
		name  string
		algo  string
		qType dns.Type
	}{
		{name: "HMAC-SHA256", algo: "hmac-sha256", qType: dns.TypeA},
		{name: "HMAC-SHA512", algo: "hmac-sha512", qType: dns.TypeAAAA},
		{name: "HMAC-SHA1", algo: "hmac-sha1", qType: dns.TypeTXT},
		{name: "HMAC-MD5", algo: "hmac-md5", qType: dns.TypeMX},
	}

	for _, tt := range algorithms {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key := Key{
				Name:      "test-key.example.com.",
				Algorithm: tt.algo,
				Secret:    []byte("super-secret-key-material"),
			}

			now := time.Now()
			wireMsg := buildSignedQuery(t, "host.example.com", tt.qType, key, now)

			rec, unsignedPayload, err := Extract(wireMsg)
			require.NoError(t, err)
			require.NotNil(t, rec)
			assert.Equal(t, "test-key.example.com.", rec.Name)
			assert.Equal(t, uint16(0x1234), rec.OriginalID)

			tsigErr, err := Verify(unsignedPayload, rec, key, now)
			require.NoError(t, err)
			assert.Zero(t, tsigErr)
		})
	}
}

func TestTSIG_VerificationErrors(t *testing.T) {
	t.Parallel()

	keyValid := Key{
		Name:      "valid-key.",
		Algorithm: HMACSHA256,
		Secret:    []byte("valid-secret"),
	}

	t.Run("BadKey", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		wireMsg := buildSignedQuery(t, "host.example.com", dns.TypeA, keyValid, now)
		rec, unsignedPayload, err := Extract(wireMsg)
		require.NoError(t, err)

		keyWrongName := Key{
			Name:      "other-key.",
			Algorithm: HMACSHA256,
			Secret:    []byte("valid-secret"),
		}
		tsigErr, err := Verify(unsignedPayload, rec, keyWrongName, now)
		require.ErrorIs(t, err, ErrBadKey)
		assert.Equal(t, dns.TSIGErrBadKey, tsigErr)
	})

	t.Run("BadSignature", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		wireMsg := buildSignedQuery(t, "host.example.com", dns.TypeA, keyValid, now)
		rec, unsignedPayload, err := Extract(wireMsg)
		require.NoError(t, err)

		keyWrongSecret := Key{
			Name:      "valid-key.",
			Algorithm: HMACSHA256,
			Secret:    []byte("wrong-secret"),
		}
		tsigErr, err := Verify(unsignedPayload, rec, keyWrongSecret, now)
		require.ErrorIs(t, err, ErrBadSignature)
		assert.Equal(t, dns.TSIGErrBadSig, tsigErr)
	})

	t.Run("BadTime", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		wireMsg := buildSignedQuery(t, "host.example.com", dns.TypeA, keyValid, now)
		rec, unsignedPayload, err := Extract(wireMsg)
		require.NoError(t, err)

		futureTime := now.Add(10 * time.Minute)
		tsigErr, err := Verify(unsignedPayload, rec, keyValid, futureTime)
		require.ErrorIs(t, err, ErrBadTime)
		assert.Equal(t, dns.TSIGErrBadTime, tsigErr)
	})

	t.Run("BadAlgorithm", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		wireMsg := buildSignedQuery(t, "host.example.com", dns.TypeA, keyValid, now)
		rec, unsignedPayload, err := Extract(wireMsg)
		require.NoError(t, err)

		keyWrongAlgo := Key{
			Name:      "valid-key.",
			Algorithm: HMACSHA512,
			Secret:    []byte("valid-secret"),
		}
		tsigErr, err := Verify(unsignedPayload, rec, keyWrongAlgo, now)
		require.ErrorIs(t, err, ErrBadAlgorithm)
		assert.Equal(t, dns.TSIGErrBadAlg, tsigErr)
	})

	t.Run("VerifyWithOriginalIDAndOtherData", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		rec := &Record{
			Name:       "valid-key.",
			Algorithm:  HMACSHA256,
			TimeSigned: uint64(now.Unix()), //nolint:gosec // Unix() is always non-negative in practice
			Fudge:      300,
			OriginalID: 0x9999,
			OtherData:  []byte{1, 2, 3, 4},
		}
		var unsignedPayload [20]byte
		binary.BigEndian.PutUint16(unsignedPayload[0:2], 0x1111) // Different ID
		tsigErr, err := Verify(unsignedPayload[:], rec, keyValid, now)
		require.ErrorIs(t, err, ErrBadSignature) // Signature fails because MAC is empty, but path executes
		assert.Equal(t, dns.TSIGErrBadSig, tsigErr)
	})
}

func TestTSIG_ExtractEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("NilOrShortPayload", func(t *testing.T) {
		t.Parallel()
		rec, payload, err := Extract([]byte{1, 2, 3})
		require.NoError(t, err)
		assert.Nil(t, rec)
		assert.Equal(t, []byte{1, 2, 3}, payload)
	})

	t.Run("NoAdditionalRecords", func(t *testing.T) {
		t.Parallel()
		var hdr [12]byte
		binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCount = 1
		qWire := dns.EncodeDomainName("example.com")
		msg := append(hdr[:], qWire...)
		msg = append(msg, 0, 1, 0, 1) // Type A, Class IN

		rec, payload, err := Extract(msg)
		require.NoError(t, err)
		assert.Nil(t, rec)
		assert.Equal(t, msg, payload)
	})

	t.Run("NonTSIGAdditionalRecord_Ignored", func(t *testing.T) {
		t.Parallel()
		var hdr [12]byte
		binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCount = 1
		optRecord := []byte{
			0,     // root name
			0, 41, // Type OPT (41)
			16, 0, // Class (UDP size)
			0, 0, 0, 0, // TTL
			0, 0, // RDLen 0
		}
		msg := append(hdr[:], optRecord...)

		rec, payload, err := Extract(msg)
		require.NoError(t, err)
		assert.Nil(t, rec)
		assert.Equal(t, msg, payload)
	})

	t.Run("MalformedSections_ReturnsErrMalformedTSIG", func(t *testing.T) {
		t.Parallel()
		var hdr [12]byte
		binary.BigEndian.PutUint16(hdr[4:6], 1)   // QDCount = 1
		binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCount = 1
		// Broken domain name in question section
		brokenMsg := append(hdr[:], 50, 'a', 'b')

		_, _, err := Extract(brokenMsg)
		require.Error(t, err)
	})
}

func TestVerify_FudgeWindowSuccess(t *testing.T) {
	t.Parallel()

	now := time.Now()
	keyValid := Key{
		Name:      "valid-key.",
		Algorithm: HMACSHA256,
		Secret:    []byte("valid-secret"),
	}

	wireMsg := buildSignedQuery(t, "host.example.com", dns.TypeA, keyValid, now.Add(100*time.Second))
	rec, unsignedPayload, err := Extract(wireMsg)
	require.NoError(t, err)

	tsigErr, err := Verify(unsignedPayload, rec, keyValid, now)
	require.NoError(t, err)
	assert.Zero(t, tsigErr)
}
