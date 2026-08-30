// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsig

import (
	"testing"
)

func FuzzTSIG_Extract(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xfa, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(_ *testing.T, payload []byte) {
		_, _, _ = Extract(payload)
	})
}
