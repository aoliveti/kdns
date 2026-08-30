// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTSIG_KeyRing(t *testing.T) {
	t.Parallel()

	kr := NewKeyRing()
	kr.Add(Key{
		Name:      "kdns-key.example.com",
		Algorithm: "hmac-sha256",
		Secret:    []byte("secret123"),
	})

	k, ok := kr.Get("KDNS-KEY.EXAMPLE.COM.")
	require.True(t, ok)
	assert.Equal(t, "kdns-key.example.com.", k.Name)
	assert.Equal(t, HMACSHA256, k.Algorithm)
	assert.Equal(t, []byte("secret123"), k.Secret)

	_, ok = kr.Get("unknown.key.")
	assert.False(t, ok)
}
