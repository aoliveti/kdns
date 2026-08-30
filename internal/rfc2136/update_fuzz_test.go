// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rfc2136

import (
	"testing"

	"github.com/aoliveti/kdns/internal/dns"
)

type noopGetter struct{}

func (noopGetter) Get(_ string) (dns.RRSets, bool) {
	return dns.RRSets{}, false
}

type noopUpsertDeleter struct{}

func (noopUpsertDeleter) Upsert(_ string, _ dns.RRSets) error {
	return nil
}

func (noopUpsertDeleter) DeleteDomain(_ string) error {
	return nil
}

func FuzzRFC2136_Process(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x12, 0x34, 0x28, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x06, 0x00, 0x01})

	getter := noopGetter{}
	ud := noopUpsertDeleter{}

	f.Fuzz(func(_ *testing.T, payload []byte) {
		_, _ = Process(payload, getter, ud)
	})
}
