// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "iter"

// Getter handles point lookups of domain record sets.
type Getter interface {
	Get(domain string) (RRSets, bool)
}

// Seeker handles cursor-based pagination starting after a specific domain.
type Seeker interface {
	Seek(afterDomain string) iter.Seq2[string, RRSets]
}

// Walker handles sequential traversal over all stored domain records.
type Walker interface {
	Walk() iter.Seq2[string, RRSets]
}

// Searcher handles substring searching over stored domain records.
type Searcher interface {
	Search(query string) iter.Seq2[string, RRSets]
}

// Viewer aggregates all read-only query and traversal operations over in-memory state.
type Viewer interface {
	Getter
	Seeker
	Walker
	Searcher
}

// Upserter handles inserting or updating domain record sets.
type Upserter interface {
	Upsert(domain string, records RRSets) error
}

// Deleter handles domain deletion.
type Deleter interface {
	DeleteDomain(domain string) error
}

// UpsertDeleter aggregates domain mutation operations (analogous to io.ReadWriter).
type UpsertDeleter interface {
	Upserter
	Deleter
}
