// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zone

import (
	"bytes"
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestFormat_RoundTrip(t *testing.T) {
	t.Parallel()

	records := map[string]dns.RRSets{
		"example.com": {
			dns.NewRRSet(dns.TypeSOA, 3600, "ns1.example.com. hostmaster.example.com. 2026082701 7200 3600 1209600 300"),
			dns.NewRRSet(dns.TypeNS, 3600, "ns1.example.com.", "ns2.example.com."),
			dns.NewRRSet(dns.TypeA, 3600, "192.0.2.1"),
			dns.NewRRSet(dns.TypeTXT, 3600, "v=spf1 include:_spf.example.com ~all"),
			dns.NewRRSet(dns.TypeCAA, 3600, `0 issue "letsencrypt.org"`),
		},
		"www.example.com": {
			dns.NewRRSet(dns.TypeA, 300, "192.0.2.10"),
			dns.NewRRSet(dns.TypeAAAA, 300, "2001:db8::10"),
		},
		"mail.example.com": {
			dns.NewRRSet(dns.TypeA, 3600, "192.0.2.25"),
			dns.NewRRSet(dns.TypeMX, 3600, "10 mail.example.com."),
		},
		"cdn.example.com": {
			dns.NewRRSet(dns.TypeCNAME, 1800, "www.example.com."),
		},
		"_sip._tcp.example.com": {
			dns.NewRRSet(dns.TypeSRV, 3600, "10 60 5060 sip.example.com."),
		},
		"*.wildcard.example.com": {
			dns.NewRRSet(dns.TypeA, 600, "192.0.2.200"),
		},
	}

	var buf bytes.Buffer
	err := FormatZone(&buf, "example.com", maps.All(records))
	require.NoError(t, err)

	formatted := buf.String()
	assert.Contains(t, formatted, "$ORIGIN example.com.")
	assert.Contains(t, formatted, "$TTL 3600")
	assert.Contains(t, formatted, "SOA")
	assert.Contains(t, formatted, "192.0.2.1")
	assert.Contains(t, formatted, "2001:db8::10")
	assert.Contains(t, formatted, "v=spf1 include:_spf.example.com ~all")

	// Parse back formatted zone
	parsed := make(map[string]dns.RRSets)
	parseErr := Parse(strings.NewReader(formatted), func(domain string, domainRecords dns.RRSets) {
		parsed[domain] = domainRecords
	})
	require.NoError(t, parseErr)

	// Verify all domains and record types survived round-trip
	for domain, expectedRecords := range records {
		actualRecords, exists := parsed[domain]
		require.Truef(t, exists, "domain %s should exist in parsed zone", domain)
		for _, record := range expectedRecords {
			actualRecord, ok := actualRecords.Get(record.Type)
			require.Truef(t, ok, "type %v should exist for %s", record.Type, domain)
			assert.Equalf(t, len(record.RData), len(actualRecord.RData), "RData count should match for %s %v", domain, record.Type)
		}
	}
}

func TestFormat_ZoneFilter(t *testing.T) {
	t.Parallel()

	records := map[string]dns.RRSets{
		"example.com": {
			dns.NewRRSet(dns.TypeA, 3600, "192.0.2.1"),
		},
		"www.example.com": {
			dns.NewRRSet(dns.TypeA, 3600, "192.0.2.10"),
		},
		"othercorp.com": {
			dns.NewRRSet(dns.TypeA, 3600, "198.51.100.1"),
		},
		"api.othercorp.com": {
			dns.NewRRSet(dns.TypeA, 3600, "198.51.100.2"),
		},
	}

	tests := []struct {
		name            string
		filterZone      string
		expectedDomains []string
		excludedDomains []string
	}{
		{
			name:            "filter example.com",
			filterZone:      "example.com",
			expectedDomains: []string{"example.com.", "www.example.com."},
			excludedDomains: []string{"othercorp.com.", "api.othercorp.com."},
		},
		{
			name:            "filter othercorp.com",
			filterZone:      "othercorp.com",
			expectedDomains: []string{"othercorp.com.", "api.othercorp.com."},
			excludedDomains: []string{"example.com.", "www.example.com."},
		},
		{
			name:            "export all zones",
			filterZone:      "",
			expectedDomains: []string{"example.com.", "www.example.com.", "othercorp.com.", "api.othercorp.com."},
			excludedDomains: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			err := FormatZone(&buf, tc.filterZone, maps.All(records))
			require.NoError(t, err)

			output := buf.String()
			for _, exp := range tc.expectedDomains {
				assert.Contains(t, output, exp)
			}
			for _, excl := range tc.excludedDomains {
				assert.NotContains(t, output, excl)
			}
		})
	}
}

func TestFormat_Empty(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	emptyMap := make(map[string]dns.RRSets)
	err := Format(&buf, maps.All(emptyMap))
	require.NoError(t, err)
	assert.Empty(t, buf.String())
}
