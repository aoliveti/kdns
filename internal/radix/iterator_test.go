// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDomainIterator validates right-to-left label extraction across standard
// DNS domains, RFC 1035 size limits, and malformed edge cases.
func TestDomainIterator(t *testing.T) {
	t.Parallel()

	t.Run("StandardDomains", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name     string
			domain   string
			expected []string
		}{
			{
				name:     "StandardDomain",
				domain:   "www.example.com",
				expected: []string{"com", "example", "www"},
			},
			{
				name:     "FQDNWithTrailingDot",
				domain:   "example.com.",
				expected: []string{"com", "example"},
			},
			{
				name:     "SingleLabel",
				domain:   "localhost",
				expected: []string{"localhost"},
			},
			{
				name:     "WildcardRecord",
				domain:   "*.example.com",
				expected: []string{"com", "example", "*"},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				assertIteratorResults(t, tc.domain, tc.expected)
			})
		}
	})

	t.Run("RFC1035Limits", func(t *testing.T) {
		t.Parallel()

		maxLabel := strings.Repeat("a", 63)
		maxDomain := maxLabel + "." + maxLabel + "." + maxLabel + "." + maxLabel

		tests := []struct {
			name     string
			domain   string
			expected []string
		}{
			{
				name:     "ExactMaxLabelLength",
				domain:   maxLabel + ".com",
				expected: []string{"com", maxLabel},
			},
			{
				name:     "ExactMaxDomainLength",
				domain:   maxDomain,
				expected: []string{maxLabel, maxLabel, maxLabel, maxLabel},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				assertIteratorResults(t, tc.domain, tc.expected)
			})
		}
	})

	t.Run("EdgeCasesAndMalformed", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name     string
			domain   string
			expected []string
		}{
			{
				name:     "EmptyString",
				domain:   "",
				expected: []string{},
			},
			{
				name:     "RootDomainOnly",
				domain:   ".",
				expected: []string{},
			},
			{
				name:     "ConsecutiveDotsOnly",
				domain:   ".....",
				expected: []string{},
			},
			{
				name:     "MixedTrailingAndLeadingDots",
				domain:   ".example..com.",
				expected: []string{"com", "example"},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				assertIteratorResults(t, tc.domain, tc.expected)
			})
		}
	})
}

// assertIteratorResults drains the DomainIterator and compares the extracted
// right-to-left labels against the expected slice.
func assertIteratorResults(t *testing.T, domain string, expected []string) {
	t.Helper()

	iter := NewDomainIterator(domain)
	var results []string

	for {
		label, hasNext := iter.Next()
		if !hasNext {
			break
		}
		results = append(results, label)
	}

	if results == nil {
		results = []string{}
	}

	assert.Equal(t, expected, results)
}

func TestDomainIterator_NextLower(t *testing.T) {
	t.Parallel()

	t.Run("NextLower_UppercaseWithStackBuffer", func(t *testing.T) {
		t.Parallel()
		iter := NewDomainIterator("WwW.EXAMPLE.COM.")
		var buf [64]byte

		l1, ok := iter.NextLower(buf[:])
		require.True(t, ok)
		assert.Equal(t, "com", l1)

		l2, ok := iter.NextLower(buf[:])
		require.True(t, ok)
		assert.Equal(t, "example", l2)

		l3, ok := iter.NextLower(buf[:])
		require.True(t, ok)
		assert.Equal(t, "www", l3)

		_, ok = iter.NextLower(buf[:])
		assert.False(t, ok)
	})

	t.Run("NextLower_AlreadyLower", func(t *testing.T) {
		t.Parallel()
		iter := NewDomainIterator("already.lower.")
		var buf [64]byte

		l1, ok := iter.NextLower(buf[:])
		require.True(t, ok)
		assert.Equal(t, "lower", l1)
	})

	t.Run("NextLower_BufferTooSmall_AllocatesFallback", func(t *testing.T) {
		t.Parallel()
		iter := NewDomainIterator("LONGUPPERCASELABEL.COM")
		smallBuf := make([]byte, 2) // Buffer smaller than label length (18 bytes)

		l1, ok := iter.NextLower(smallBuf)
		require.True(t, ok)
		assert.Equal(t, "com", l1)

		l2, ok := iter.NextLower(smallBuf)
		require.True(t, ok)
		assert.Equal(t, "longuppercaselabel", l2)
	})
}
