// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlsreload

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReloader_Lifecycle(t *testing.T) {
	t.Parallel()

	t.Run("ValidInitialization", func(t *testing.T) {
		t.Parallel()
		certPath, keyPath := generateTempCert(t)
		r, err := New(certPath, keyPath)
		require.NoError(t, err)

		cert, err := r.GetCertificate(nil)
		require.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("InvalidInitialization", func(t *testing.T) {
		t.Parallel()
		r, err := New("nonexistent.crt", "nonexistent.key")
		require.Error(t, err)
		assert.Nil(t, r)
	})

	t.Run("ReloadWithCorruptedFilesMaintainsOldState", func(t *testing.T) {
		t.Parallel()
		certPath, keyPath := generateTempCert(t)
		r, err := New(certPath, keyPath)
		require.NoError(t, err)

		originalCert, _ := r.GetCertificate(nil)

		corruptedPath := filepath.Join(t.TempDir(), "corrupt.crt")
		require.NoError(t, os.WriteFile(corruptedPath, []byte("invalid cert data"), 0o600))

		r.certPath = corruptedPath
		err = r.Reload()
		require.Error(t, err)

		currentCert, _ := r.GetCertificate(nil)
		assert.Same(t, originalCert, currentCert, "certificate must not change if reload fails")
	})
}

func generateTempCert(tb testing.TB) (certPath, keyPath string) {
	tb.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(tb, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"KDNS Test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(tb, err)

	dir := tb.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")

	certOut, err := os.Create(certPath) //nolint:gosec // intentional file creation in temporary test directory
	require.NoError(tb, err)
	defer func() { _ = certOut.Close() }()
	require.NoError(tb, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))

	keyOut, err := os.Create(keyPath) //nolint:gosec // intentional file creation in temporary test directory
	require.NoError(tb, err)
	defer func() { _ = keyOut.Close() }()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(tb, err)
	require.NoError(tb, pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}))

	return certPath, keyPath
}
