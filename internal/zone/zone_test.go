// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zone

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/aoliveti/kdns/internal/radix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestParse_Success(t *testing.T) {
	t.Parallel()

	zoneData := `
	$TTL 86400
	$ORIGIN example.com.

	; Multiline SOA record with internal comments
	@       IN  SOA     ns1.example.com. admin.example.com. (
	        2026010101 ; Serial
	        7200       ; Refresh
	        3600       ; Retry
	        1209600    ; Expire
	        3600 )     ; Minimum TTL

	; Apex records
	@       IN  NS      ns1.example.com.
	@       IN  NS      ns2.example.com.
	@       IN  MX      10 mail.example.com.
	@       IN  MX      20 mail2.example.com.

	; Name servers and hosts
	ns1     IN  A       192.0.2.1
	ns1     IN  AAAA    2001:db8::1
	ns2     IN  A       192.0.2.2

	; Web and services with quoted semicolons
	www     IN  A       192.0.2.10
	www     IN  AAAA    2001:db8::10
	www     IN  TXT     "v=spf1; include:_spf.example.com; ~all"
	www     IN  TXT     "additional-txt-record"

	mail    IN  A       192.0.2.20
	alias   IN  CNAME   www

	; Changing origin test
	$ORIGIN sub.example.com.
	server1 IN  A       192.0.2.100
	service._tcp IN SRV 0 5 5060 sipserver.example.com.
	caa-record IN CAA   0 issue "letsencrypt.org"
	dnskey-rec IN DNSKEY 256 3 8 AwEAAag=
	ds-rec IN DS 60999 8 2 2BB1832F
	rrsig-rec IN RRSIG A 8 2 300 20260901000000 20260801000000 60999 example.com. AwEAAag=
	nsec-rec IN NSEC next.example.com. A AAAA RRSIG NSEC
	nsec3-rec IN NSEC3 1 0 10 AABBCCDD 09BE1F9856A15F431C8B9A2E12345678 A AAAA RRSIG NSEC3
	zonemd-rec IN ZONEMD 2026081201 1 1 09BE1F9856A15F431C8B9A2E12345678
	`

	parsedRecords := make(map[string]dns.RRSets)
	err := Parse(strings.NewReader(zoneData), func(domain string, records dns.RRSets) {
		parsedRecords[domain] = records
	})
	require.NoError(t, err)

	expectedDomains := []struct {
		expected map[dns.Type][]string
		domain   string
	}{
		{
			domain: "example.com",
			expected: map[dns.Type][]string{
				dns.TypeSOA: {"ns1.example.com. admin.example.com. 2026010101 7200 3600 1209600 3600"},
				dns.TypeNS:  {"ns1.example.com.", "ns2.example.com."},
				dns.TypeMX:  {"10 mail.example.com.", "20 mail2.example.com."},
			},
		},
		{
			domain: "ns1.example.com",
			expected: map[dns.Type][]string{
				dns.TypeA:    {"192.0.2.1"},
				dns.TypeAAAA: {"2001:db8::1"},
			},
		},
		{
			domain: "ns2.example.com",
			expected: map[dns.Type][]string{
				dns.TypeA: {"192.0.2.2"},
			},
		},
		{
			domain: "www.example.com",
			expected: map[dns.Type][]string{
				dns.TypeA:    {"192.0.2.10"},
				dns.TypeAAAA: {"2001:db8::10"},
				dns.TypeTXT:  {`"v=spf1; include:_spf.example.com; ~all"`, `"additional-txt-record"`},
			},
		},
		{
			domain: "mail.example.com",
			expected: map[dns.Type][]string{
				dns.TypeA: {"192.0.2.20"},
			},
		},
		{
			domain: "alias.example.com",
			expected: map[dns.Type][]string{
				dns.TypeCNAME: {"www"},
			},
		},
		{
			domain: "server1.sub.example.com",
			expected: map[dns.Type][]string{
				dns.TypeA: {"192.0.2.100"},
			},
		},
		{
			domain: "service._tcp.sub.example.com",
			expected: map[dns.Type][]string{
				dns.TypeSRV: {"0 5 5060 sipserver.example.com."},
			},
		},
		{
			domain: "caa-record.sub.example.com",
			expected: map[dns.Type][]string{
				dns.TypeCAA: {`0 issue "letsencrypt.org"`},
			},
		},
		{
			domain: "dnskey-rec.sub.example.com",
			expected: map[dns.Type][]string{
				dns.TypeDNSKEY: {"256 3 8 AwEAAag="},
			},
		},
		{
			domain: "ds-rec.sub.example.com",
			expected: map[dns.Type][]string{
				dns.TypeDS: {"60999 8 2 2BB1832F"},
			},
		},
		{
			domain: "rrsig-rec.sub.example.com",
			expected: map[dns.Type][]string{
				dns.TypeRRSIG: {"A 8 2 300 20260901000000 20260801000000 60999 example.com. AwEAAag="},
			},
		},
		{
			domain: "nsec-rec.sub.example.com",
			expected: map[dns.Type][]string{
				dns.TypeNSEC: {"next.example.com. A AAAA RRSIG NSEC"},
			},
		},
		{
			domain: "nsec3-rec.sub.example.com",
			expected: map[dns.Type][]string{
				dns.TypeNSEC3: {"1 0 10 AABBCCDD 09BE1F9856A15F431C8B9A2E12345678 A AAAA RRSIG NSEC3"},
			},
		},
		{
			domain: "zonemd-rec.sub.example.com",
			expected: map[dns.Type][]string{
				dns.TypeZONEMD: {"2026081201 1 1 09BE1F9856A15F431C8B9A2E12345678"},
			},
		},
	}

	for _, tt := range expectedDomains {
		t.Run(tt.domain, func(t *testing.T) {
			t.Parallel()

			actual, exists := parsedRecords[tt.domain]
			require.True(t, exists, "domain %q should exist in parsed zone map", tt.domain)
			require.Len(t, actual, len(tt.expected))

			for _, record := range actual {
				expectedStrings, ok := tt.expected[record.Type]
				require.True(t, ok, "unexpected Type %v for domain %q", record.Type, tt.domain)
				var expectedBytes [][]byte
				for _, str := range expectedStrings {
					w, err := dns.PackRData(record.Type, str)
					require.NoError(t, err)
					expectedBytes = append(expectedBytes, w)
				}
				assert.Equal(t, expectedBytes, record.RData)
				assert.Equal(t, uint32(86400), record.TTL)
			}
		})
	}
}

func TestParse_OmittedOwnerInheritance(t *testing.T) {
	t.Parallel()

	zoneData := `
	$TTL 1h
	$ORIGIN example.com.
	@       IN  SOA     ns1.example.com. admin.example.com. 2026010101 7200 3600 1209600 3600
	            NS      ns1.example.com.
	            NS      ns2.example.com.
	            MX  10  mail.example.com.
	www         A       192.0.2.1
	            AAAA    2001:db8::1
	`

	parsedRecords := make(map[string]dns.RRSets)
	err := Parse(strings.NewReader(zoneData), func(domain string, records dns.RRSets) {
		parsedRecords[domain] = records
	})
	require.NoError(t, err)

	require.Contains(t, parsedRecords, "example.com")
	apexSets := parsedRecords["example.com"]
	assert.Len(t, apexSets, 3)

	require.Contains(t, parsedRecords, "www.example.com")
	wwwSets := parsedRecords["www.example.com"]
	assert.Len(t, wwwSets, 2)
}

func TestParse_TTLUnitsAndClassPermutations(t *testing.T) {
	t.Parallel()

	zoneData := `
	$TTL 2h
	$ORIGIN example.com.
	host1   1d      IN  A       1.1.1.1
	host2   IN      30m A       2.2.2.2
	host3   45s         A       3.3.3.3
	host4   IN          A       4.4.4.4
	host5               A       5.5.5.5
	`

	parsedRecords := make(map[string]dns.RRSets)
	err := Parse(strings.NewReader(zoneData), func(domain string, records dns.RRSets) {
		parsedRecords[domain] = records
	})
	require.NoError(t, err)

	assert.Equal(t, uint32(86400), parsedRecords["host1.example.com"][0].TTL)
	assert.Equal(t, uint32(1800), parsedRecords["host2.example.com"][0].TTL)
	assert.Equal(t, uint32(45), parsedRecords["host3.example.com"][0].TTL)
	assert.Equal(t, uint32(7200), parsedRecords["host4.example.com"][0].TTL)
	assert.Equal(t, uint32(7200), parsedRecords["host5.example.com"][0].TTL)
}

func TestParse_Errors(t *testing.T) {
	t.Parallel()

	longName := strings.Repeat("a", 52) + "." +
		strings.Repeat("b", 52) + "." +
		strings.Repeat("c", 52) + "." +
		strings.Repeat("d", 52) + "." +
		strings.Repeat("e", 50) + ".com"

	tests := []struct {
		wantErr error
		name    string
		zone    string
	}{
		{
			name:    "malformed TTL directive",
			zone:    "$TTL invalid\n",
			wantErr: ErrMalformedTTL,
		},
		{
			name:    "malformed ORIGIN directive",
			zone:    "$ORIGIN \n",
			wantErr: ErrMalformedOrigin,
		},
		{
			name:    "label too long",
			zone:    strings.Repeat("a", 64) + " IN A 192.0.2.1\n",
			wantErr: dns.ErrLabelTooLong,
		},
		{
			name:    "name too long",
			zone:    longName + " IN A 192.0.2.1\n",
			wantErr: dns.ErrNameTooLong,
		},
		{
			name:    "unknown query type",
			zone:    "www IN UNKNOWN 192.0.2.1\n",
			wantErr: ErrUnknownQueryType,
		},
		{
			name:    "malformed record line missing fields",
			zone:    "www IN\n",
			wantErr: ErrMalformedLine,
		},
		{
			name:    "unclosed parenthesis",
			zone:    "@ IN SOA ns1.example.com. admin.example.com. (\n2026010101\n",
			wantErr: ErrUnclosedParenthesis,
		},
		{
			name:    "unmatched closing parenthesis",
			zone:    "@ IN SOA ns1.example.com. admin.example.com. )\n",
			wantErr: ErrUnmatchedParenthesis,
		},
		{
			name:    "unclosed quote",
			zone:    `www IN TXT "unclosed text literal` + "\n",
			wantErr: ErrUnclosedQuote,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := Parse(strings.NewReader(tt.zone), func(string, dns.RRSets) {})
			require.ErrorIs(t, err, ErrInvalidZoneFile)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestParse_RootZone(t *testing.T) {
	t.Parallel()

	testdataRoot, err := os.OpenRoot("testdata")
	require.NoError(t, err)
	defer func() { _ = testdataRoot.Close() }()

	data, err := testdataRoot.ReadFile("root.zone")
	require.NoError(t, err, "root.zone testdata file must exist")

	parsedRecords := make(map[string]dns.RRSets)
	totalRecords := 0

	err = Parse(bytes.NewReader(data), func(domain string, records dns.RRSets) {
		parsedRecords[domain] = records
		totalRecords += len(records)
	})
	require.NoError(t, err, "parsing root zone should produce zero errors")
	assert.Positive(t, totalRecords)

	tree := radix.New()
	for domain, records := range parsedRecords {
		tree.Upsert(domain, records)
	}

	t.Run("ApexSOA", func(t *testing.T) {
		t.Parallel()
		resSOA := tree.Resolve(".", dns.TypeSOA)
		require.Equal(t, dns.RCodeSuccess, resSOA.RCode)
		require.Len(t, resSOA.Answer.RData, 1)
	})

	t.Run("ApexNS", func(t *testing.T) {
		t.Parallel()
		resNS := tree.Resolve(".", dns.TypeNS)
		require.Equal(t, dns.RCodeSuccess, resNS.RCode)
		assert.NotEmpty(t, resNS.Answer.RData)
	})

	t.Run("ComDelegationNS", func(t *testing.T) {
		t.Parallel()
		resComNS := tree.Resolve("com.", dns.TypeNS)
		require.Equal(t, dns.RCodeSuccess, resComNS.RCode)
		assert.NotEmpty(t, resComNS.Authority.RData)
	})

	t.Run("ComDS", func(t *testing.T) {
		t.Parallel()
		resComDS := tree.Resolve("com.", dns.TypeDS)
		require.Equal(t, dns.RCodeSuccess, resComDS.RCode)
		assert.NotEmpty(t, resComDS.Answer.RData)
	})
}

func TestParse_EnterpriseAndWildcardsFiles(t *testing.T) {
	t.Parallel()

	for _, filename := range []string{"enterprise.zone", "wildcards.zone"} {
		t.Run(filename, func(t *testing.T) {
			t.Parallel()

			testdataRoot, err := os.OpenRoot("testdata")
			require.NoError(t, err)
			defer func() { _ = testdataRoot.Close() }()

			data, readErr := testdataRoot.ReadFile(filename)
			require.NoError(t, readErr)

			count := 0
			parseErr := Parse(bytes.NewReader(data), func(string, dns.RRSets) {
				count++
			})
			require.NoError(t, parseErr)
			assert.Positive(t, count)
		})
	}
}

func TestParse_MultilineQuoteStateLoss(t *testing.T) {
	t.Parallel()

	input := `$ORIGIN test.com.
@ IN TXT ( "part1
part2" )`
	var rdata string
	err := Parse(strings.NewReader(input), func(_ string, records dns.RRSets) {
		rdata = string(records[0].RData[0])
	})
	require.NoError(t, err)
	assert.Contains(t, rdata, "part1")
}
