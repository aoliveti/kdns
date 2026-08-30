// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tlsreload provides lock-free hot-reloading capabilities for TLS certificates.
package tlsreload

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
)

// Reloader manages the safe, concurrent replacement of TLS certificates.
// It leverages an atomic pointer to ensure the hot path remains lock-free.
type Reloader struct {
	cert     atomic.Pointer[tls.Certificate]
	certPath string
	keyPath  string
}

// New initializes a new Reloader and performs the initial read of the certificate files.
func New(certPath, keyPath string) (*Reloader, error) {
	r := &Reloader{
		certPath: certPath,
		keyPath:  keyPath,
	}

	if err := r.Reload(); err != nil {
		return nil, fmt.Errorf("initialize tls reloader: %w", err)
	}

	return r, nil
}

// Reload reads the certificate files from disk and atomically swaps the active certificate.
// If the files are malformed or missing, it returns an error and keeps the existing certificate active.
func (r *Reloader) Reload() error {
	newCert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("load tls key pair (%s, %s): %w", r.certPath, r.keyPath, err)
	}

	r.cert.Store(&newCert)
	return nil
}

// GetCertificate is the callback function intended for tls.Config.GetCertificate.
// It returns the most recently loaded certificate without acquiring any locks.
func (r *Reloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cert.Load(), nil
}
