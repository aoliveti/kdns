// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDomain_Valid(t *testing.T) {
	t.Parallel()

	// Construct an exact 253-character domain: 3 labels of 63 chars (189 chars + 2 dots = 191) + 1 label of 57 chars (248) + ".com" (252) + "." (253) -> trimmed to 252
	maxLabel := strings.Repeat("a", 63)
	exact253 := maxLabel + "." + maxLabel + "." + maxLabel + "." + strings.Repeat("b", 57)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "SimpleDomain",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "SingleLetterLabels",
			input:    "a.b.c.com",
			expected: "a.b.c.com",
		},
		{
			name:     "NumericOnlyLabelsRFC1123",
			input:    "123.456.789.com",
			expected: "123.456.789.com",
		},
		{
			name:     "Exact63CharMaxLabelLength",
			input:    maxLabel + ".com",
			expected: maxLabel + ".com",
		},
		{
			name:     "Exact253CharTotalLength",
			input:    exact253,
			expected: exact253,
		},
		{
			name:     "FQDNWithTrailingDot",
			input:    "example.com.",
			expected: "example.com",
		},
		{
			name:     "UppercaseNormalizationToLowercase",
			input:    "WWW.EXAMPLE.COM.",
			expected: "www.example.com",
		},
		{
			name:     "RootZoneDot",
			input:    ".",
			expected: ".",
		},
		{
			name:     "RootZoneAtSignAlias",
			input:    "@",
			expected: ".",
		},
		{
			name:     "SubdomainWithHyphenAndUnderscore",
			input:    "_dmarc.sub-domain.example.com",
			expected: "_dmarc.sub-domain.example.com",
		},
		{
			name:     "WildcardPrefixRFC4592",
			input:    "*.example.com",
			expected: "*.example.com",
		},
		{
			name:     "LeadingAndTrailingWhitespaceStripped",
			input:    "   example.com.   ",
			expected: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ValidateDomain(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateDomain_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expectedErr error
		name        string
		input       string
	}{
		{
			name:        "EmptyString",
			input:       "",
			expectedErr: ErrEmptyDomain,
		},
		{
			name:        "WhitespaceOnly",
			input:       "   ",
			expectedErr: ErrEmptyDomain,
		},
		{
			name:        "ConsecutiveDotsEmptyLabel",
			input:       "foo..example.com",
			expectedErr: ErrEmptyLabel,
		},
		{
			name:        "LeadingDotEmptyLabel",
			input:       ".example.com",
			expectedErr: ErrEmptyLabel,
		},
		{
			name:        "LabelExceeds63Bytes",
			input:       strings.Repeat("a", 64) + ".com",
			expectedErr: ErrLabelTooLong,
		},
		{
			name:        "TotalLengthExceeds253Bytes",
			input:       strings.Repeat("a.", 128) + "com",
			expectedErr: ErrNameTooLong,
		},
		{
			name:        "InvalidCharacterSpace",
			input:       "foo bar.com",
			expectedErr: ErrInvalidLabelChar,
		},
		{
			name:        "InvalidCharacterSlash",
			input:       "foo/bar.com",
			expectedErr: ErrInvalidLabelChar,
		},
		{
			name:        "WildcardInNonLeftmostPosition",
			input:       "foo.*.example.com",
			expectedErr: ErrInvalidLabelChar,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ValidateDomain(tt.input)
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.expectedErr)
			assert.Empty(t, result)
		})
	}
}

func TestEncodeDomainName_Valid(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []byte{0}, EncodeDomainName("."))
	assert.Equal(t, []byte{0}, EncodeDomainName(""))
	assert.Equal(t, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, EncodeDomainName("example.com"))
	assert.Equal(t, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, EncodeDomainName("EXAMPLE.COM."))
}
