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

func TestTSIG_ResponseSigningWithRequestMAC(t *testing.T) {
	t.Parallel()

	key := Key{
		Name:      "kdns-key.",
		Algorithm: HMACSHA256,
		Secret:    []byte("shared-secret"),
	}

	now := time.Now()
	queryWire := buildSignedQuery(t, "example.com", dns.TypeA, key, now)

	reqRec, _, err := Extract(queryWire)
	require.NoError(t, err)

	// Create a dummy DNS response packet
	var respBuf [4096]byte
	binary.BigEndian.PutUint16(respBuf[0:2], 0x1234)
	binary.BigEndian.PutUint16(respBuf[2:4], 0x8180) // QR=1, AA=1, NOERROR
	binary.BigEndian.PutUint16(respBuf[4:6], 1)      // QDCOUNT=1
	binary.BigEndian.PutUint16(respBuf[6:8], 0)      // ANCOUNT=0
	binary.BigEndian.PutUint16(respBuf[8:10], 0)     // NSCOUNT=0
	binary.BigEndian.PutUint16(respBuf[10:12], 0)    // ARCOUNT=0

	offset := 12
	qWire := dns.EncodeDomainName("example.com")
	copy(respBuf[offset:], qWire)
	offset += len(qWire)
	binary.BigEndian.PutUint16(respBuf[offset:offset+2], uint16(dns.TypeA))
	offset += 2
	binary.BigEndian.PutUint16(respBuf[offset:offset+2], uint16(dns.ClassIN))
	offset += 2

	// Sign the response with Request MAC prefix
	signedLen, err := Sign(respBuf[:], offset, reqRec.MAC, key, 0, now)
	require.NoError(t, err)

	// Verify the response contains TSIG in Additional section
	respRec, unsignedResp, err := Extract(respBuf[:signedLen])
	require.NoError(t, err)
	require.NotNil(t, respRec)
	assert.Equal(t, "kdns-key.", respRec.Name)
	assert.Equal(t, uint16(0), binary.BigEndian.Uint16(unsignedResp[10:12])) // ARCount was 0 before TSIG, now 0 in unsigned
}
