// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestRecords_FormatDomain(t *testing.T) {
	t.Parallel()

	wireA, err := dns.PackRData(dns.TypeA, "192.0.2.1")
	require.NoError(t, err)

	wireTXT, err := dns.PackRData(dns.TypeTXT, "v=spf1 -all")
	require.NoError(t, err)

	records := dns.RRSets{
		{Type: dns.TypeA, TTL: 300, RData: [][]byte{wireA}},
		{Type: dns.TypeTXT, TTL: 3600, RData: [][]byte{wireTXT}},
	}

	formatted := formatDomain("example.com", records)
	assert.Equal(t, "example.com", formatted.Domain)
	require.Len(t, formatted.Records, 2)
	assert.Equal(t, "A", formatted.Records[0].Type)
	assert.Equal(t, uint32(300), formatted.Records[0].TTL)
	assert.Equal(t, []string{"192.0.2.1"}, formatted.Records[0].RData)

	assert.Equal(t, "TXT", formatted.Records[1].Type)
	assert.Equal(t, uint32(3600), formatted.Records[1].TTL)
	assert.Equal(t, []string{"v=spf1 -all"}, formatted.Records[1].RData)
}

func TestRecords_UpsertRequest_Validation(t *testing.T) {
	t.Parallel()

	t.Run("ValidRequest", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "A", TTL: 300, RData: []string{"192.0.2.1", "192.0.2.2"}},
				{Type: "TXT", TTL: 600, RData: []string{"sample-txt"}},
			},
		}

		sets, err := req.RRSets()
		require.NoError(t, err)
		assert.Len(t, sets, 2)
		assert.Equal(t, dns.TypeA, sets[0].Type)
		assert.Len(t, sets[0].RData, 2)
	})

	t.Run("EmptyRecords", func(t *testing.T) {
		req := UpsertRequest{Records: nil}
		_, err := req.RRSets()
		require.ErrorIs(t, err, ErrEmptyRecords)
	})

	t.Run("InvalidType", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "UNKNOWN_TYPE", TTL: 300, RData: []string{"1.2.3.4"}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, dns.ErrUnknownType)
	})

	t.Run("ANYTypeRejected", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "ANY", TTL: 300, RData: []string{"1.2.3.4"}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, ErrPseudoTypeNotAllowed)
	})

	t.Run("OPTTypeRejected", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "OPT", TTL: 300, RData: []string{"1.2.3.4"}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, ErrPseudoTypeNotAllowed)
	})

	t.Run("DuplicateType", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "A", TTL: 300, RData: []string{"1.2.3.4"}},
				{Type: "A", TTL: 300, RData: []string{"5.6.7.8"}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, ErrDuplicateRecordType)
	})

	t.Run("CNAMECoexistenceClash", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "CNAME", TTL: 300, RData: []string{"target.com."}},
				{Type: "A", TTL: 300, RData: []string{"1.2.3.4"}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, ErrCNAMECoexistence)
	})

	t.Run("MultipleCNAMETargets", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "CNAME", TTL: 300, RData: []string{"target1.com.", "target2.com."}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, ErrCNAMEMultipleTargets)
	})

	t.Run("MultipleSOARecords", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "SOA", TTL: 300, RData: []string{
					"ns1.example.com admin.example.com 1 7200 3600 1209600 300",
					"ns2.example.com admin.example.com 2 7200 3600 1209600 300",
				}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, ErrMultipleSOA)
	})

	t.Run("EmptyRData", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "A", TTL: 300, RData: []string{}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, ErrEmptyRData)
	})

	t.Run("TTLExceeded", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "A", TTL: 3_000_000_000, RData: []string{"1.2.3.4"}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, ErrTTLExceeded)
	})

	t.Run("InvalidRDataPayload", func(t *testing.T) {
		req := UpsertRequest{
			Records: []Record{
				{Type: "A", TTL: 300, RData: []string{"not-an-ip"}},
			},
		}
		_, err := req.RRSets()
		require.ErrorIs(t, err, dns.ErrInvalidIPAddress)
	})
}
