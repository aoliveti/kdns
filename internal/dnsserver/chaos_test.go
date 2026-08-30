// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func buildCHAOSQuery(tb testing.TB, name string, qType dns.Type) []byte {
	tb.Helper()
	buf := make([]byte, 0, headerSize+len(name)+8)

	var hdr [headerSize]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	buf = append(buf, hdr[:]...)

	buf = append(buf, encodeName(name)...)

	var qTypeClass [4]byte
	binary.BigEndian.PutUint16(qTypeClass[0:2], uint16(qType))
	binary.BigEndian.PutUint16(qTypeClass[2:4], uint16(dns.ClassCH))
	buf = append(buf, qTypeClass[:]...)

	return buf
}

func TestServer_CHAOSDiagnostics(t *testing.T) {
	t.Parallel()

	st := newPopulatedFakeResolver()
	s := New(
		st,
		WithLogger(newTestLogger()),
		WithVersion("kdns-v1.2.3"),
		WithIdentity("node-cluster-01"),
	)

	t.Run("VersionBind_ReturnsConfiguredVersion", func(t *testing.T) {
		query := buildCHAOSQuery(t, "version.bind", dns.TypeTXT)
		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(query, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("VersionBind_TypeANY_ReturnsConfiguredVersion", func(t *testing.T) {
		query := buildCHAOSQuery(t, "version.bind", dns.TypeANY)
		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(query, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("HostnameBind_ReturnsConfiguredIdentity", func(t *testing.T) {
		query := buildCHAOSQuery(t, "hostname.bind", dns.TypeTXT)
		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(query, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("IdServer_ReturnsConfiguredIdentity", func(t *testing.T) {
		query := buildCHAOSQuery(t, "id.server", dns.TypeTXT)
		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(query, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("AuthorsBind_ReturnsAuthor", func(t *testing.T) {
		query := buildCHAOSQuery(t, "authors.bind", dns.TypeTXT)
		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(query, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeSuccess, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("UnknownCHAOSQuery_ReturnsNXDOMAIN", func(t *testing.T) {
		query := buildCHAOSQuery(t, "unknown.bind", dns.TypeTXT)
		var respBuf [4096]byte
		written, _, rCode, err := s.resolve(query, respBuf[:], dns.MaxUDPSize)
		require.NoError(t, err)
		assert.Equal(t, dns.RCodeNameError, rCode)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf[:written]))
		assert.Equal(t, uint16(0), msg.Header.ANCount)
	})

	t.Run("KnownCHAOSQuery_NonTXT_ReturnsNODATA", func(t *testing.T) {
		for _, name := range []string{"version.bind", "hostname.bind", "authors.bind"} {
			query := buildCHAOSQuery(t, name, dns.TypeA)
			var respBuf [4096]byte
			written, _, rCode, err := s.resolve(query, respBuf[:], dns.MaxUDPSize)
			require.NoError(t, err)
			assert.Equal(t, dns.RCodeSuccess, rCode)

			var msg dns.Message
			require.NoError(t, msg.Unpack(respBuf[:written]))
			assert.Equal(t, uint16(0), msg.Header.ANCount)
		}
	})
}

func TestServer_ExplicitIdentityNone(t *testing.T) {
	t.Parallel()

	st := newPopulatedFakeResolver()
	s := New(
		st,
		WithLogger(newTestLogger()),
		WithIdentity("none"),
	)

	query := buildCHAOSQuery(t, "id.server", dns.TypeTXT)
	var respBuf [4096]byte
	written, _, rCode, err := s.resolve(query, respBuf[:], dns.MaxUDPSize)
	require.NoError(t, err)
	assert.Equal(t, dns.RCodeSuccess, rCode)

	var msg dns.Message
	require.NoError(t, msg.Unpack(respBuf[:written]))
	assert.Equal(t, uint16(1), msg.Header.ANCount)
	assert.Contains(t, string(respBuf[:written]), "none")
}
