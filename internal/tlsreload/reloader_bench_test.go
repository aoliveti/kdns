// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlsreload

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkReloader_GetCertificate(b *testing.B) {
	certPath, keyPath := generateTempCert(b)
	r, err := New(certPath, keyPath)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _ = r.GetCertificate(nil)
	}
}
