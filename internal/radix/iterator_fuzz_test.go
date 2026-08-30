// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package radix

import (
	"strings"
	"testing"
)

// FuzzDomainIterator exposes the iterator to randomized inputs to ensure
// memory safety, preventing panics and infinite loops.
func FuzzDomainIterator(f *testing.F) {
	f.Add("www.example.com")
	f.Add("localhost.")
	f.Add("..multiple...dots..")
	f.Add("")
	f.Add("*.wildcard.com")
	f.Add(strings.Repeat("a", 300))

	f.Fuzz(func(t *testing.T, orig string) {
		iter := NewDomainIterator(orig)

		iterations := 0
		maxPossibleLabels := len(orig) + 1

		for {
			label, hasNext := iter.Next()
			if !hasNext {
				break
			}

			if label == "" {
				t.Errorf("Iterator returned an empty label for input %q", orig)
			}

			iterations++

			if iterations > maxPossibleLabels {
				t.Fatalf("Infinite loop detected for input %q running %d iterations", orig, iterations)
			}
		}
	})
}
