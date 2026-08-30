// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package radix implements an O(k) radix tree optimized for DNS domain lookups.
package radix

import "strings"

// DomainIterator provides a heap-allocation free, lock-free mechanism to traverse
// a domain name from right to left, extracting individual labels.
type DomainIterator struct {
	domain string
	cursor int
}

// NewDomainIterator initializes and returns a DomainIterator pointing
// to the end of the provided domain string.
func NewDomainIterator(domain string) DomainIterator {
	return DomainIterator{
		domain: domain,
		cursor: len(domain),
	}
}

// Next extracts the next label from right to left.
// It skips empty labels caused by consecutive dots and returns a boolean
// indicating whether a valid label was found.
func (it *DomainIterator) Next() (string, bool) {
	for it.cursor > 0 {
		end := it.cursor
		dotIdx := strings.LastIndexByte(it.domain[:it.cursor], '.')
		if dotIdx == -1 {
			it.cursor = 0
			return it.domain[:end], true
		}
		it.cursor = dotIdx
		label := it.domain[dotIdx+1 : end]
		if label != "" {
			return label, true
		}
	}
	return "", false
}

// NextLower extracts the next label from right to left, case-folding ASCII uppercase
// characters to lowercase. It uses the provided stack buffer when case conversion is needed
// to prevent heap allocations.
func (it *DomainIterator) NextLower(buf []byte) (string, bool) {
	label, ok := it.Next()
	if !ok {
		return "", false
	}
	hasUpper := false
	for i := range len(label) {
		if label[i] >= 'A' && label[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return label, true
	}
	if len(label) > len(buf) {
		out := make([]byte, len(label))
		for i := range len(label) {
			b := label[i]
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			out[i] = b
		}
		return string(out), true
	}
	for i := range len(label) {
		b := label[i]
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		buf[i] = b
	}
	return string(buf[:len(label)]), true
}
