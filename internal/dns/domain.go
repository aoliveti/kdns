// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrEmptyDomain indicates an empty domain name string.
	ErrEmptyDomain = errors.New("dns: domain name cannot be empty")

	// ErrEmptyLabel indicates consecutive dots or an empty label in the domain path.
	ErrEmptyLabel = errors.New("dns: domain contains empty label")

	// ErrInvalidLabelChar indicates a character outside allowed RFC 1035 / RFC 1123 / RFC 2782 sets.
	ErrInvalidLabelChar = errors.New("dns: domain label contains invalid character")
)

// ValidateDomain validates and normalizes a domain name according to RFC 1035 §2.3.1, RFC 1123 §2.1, and RFC 2782.
//
// Normalization rules:
//  1. Trims leading and trailing whitespace.
//  2. Translates "@" (zone apex shortcut) to "." (root/origin).
//  3. Strips trailing dots (returning "." for root).
//  4. Enforces the RFC 1035 maximum length of 253 characters for uncompressed presentation names.
//  5. Enforces label boundaries: each label must be 1-63 bytes long.
//  6. Allows valid hostname characters (a-z, 0-9, '-', '_', and leading '*' for wildcard apexes).
//  7. Normalizes all ASCII letters to lowercase.
func ValidateDomain(name string) (string, error) {
	trimmedName := strings.TrimSpace(name)
	if trimmedName == "" {
		return "", ErrEmptyDomain
	}

	if trimmedName == "@" {
		return ".", nil
	}

	trimmedName = strings.TrimSuffix(trimmedName, ".")
	if trimmedName == "" {
		return ".", nil
	}

	if len(trimmedName) > 253 {
		return "", ErrNameTooLong
	}

	var labelIndex int
	for label := range strings.SplitSeq(trimmedName, ".") {
		if label == "" {
			return "", ErrEmptyLabel
		}
		if len(label) > MaxLabelLen {
			return "", ErrLabelTooLong
		}
		// Allow wildcard prefix only as the first label (RFC 4592)
		if label == "*" && labelIndex == 0 {
			labelIndex++
			continue
		}
		for charIndex := range len(label) {
			char := label[charIndex]
			isValid := (char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				char == '-' ||
				char == '_'
			if !isValid {
				return "", fmt.Errorf("%w: %q in label %q", ErrInvalidLabelChar, char, label)
			}
		}
		labelIndex++
	}

	return strings.ToLower(trimmedName), nil
}

// EncodeDomainName encodes a domain name into uncompressed DNS wire format (RFC 1035 §3.1).
// It returns a byte slice representing length-prefixed labels terminated with a null byte (0x00).
func EncodeDomainName(name string) []byte {
	canonical := strings.ToLower(strings.TrimSpace(name))
	if canonical == "" || canonical == "." {
		return []byte{0}
	}
	trimmed := strings.TrimSuffix(canonical, ".")
	var buf []byte
	for label := range strings.SplitSeq(trimmed, ".") {
		labelLen := min(len(label), MaxLabelLen)
		buf = append(buf, byte(labelLen))
		buf = append(buf, label[:labelLen]...)
	}
	buf = append(buf, 0)
	return buf
}
