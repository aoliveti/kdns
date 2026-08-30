// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "testing"

// FuzzMessage_Unpack stresses the wire deserializer with randomized payloads to guarantee zero panics.
func FuzzMessage_Unpack(f *testing.F) {
	f.Add(validQuery())

	f.Add([]byte{0x12, 0x34, 0x01, 0x00})

	f.Add([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
	})

	edns0Payload := validQuery()
	edns0Payload[11] = 1
	edns0Payload = append(edns0Payload, []byte{0x00, 0x00, 41, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	f.Add(edns0Payload)

	f.Fuzz(func(_ *testing.T, payload []byte) {
		var m Message

		_ = m.Unpack(payload)
		_ = m.Unpack(payload)
	})
}
