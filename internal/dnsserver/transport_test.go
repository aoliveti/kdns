// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aoliveti/kdns/internal/dns"
)

func TestServer_UDPServer(t *testing.T) {
	t.Parallel()

	st := newPopulatedFakeResolver()

	rSub, _ := dns.PackRData(dns.TypeTXT, "sub-txt")
	st.Add("sub.example.com", dns.RRSet{
		Type:  dns.TypeTXT,
		Class: dns.ClassIN,
		TTL:   300,
		RData: [][]byte{rSub},
	})

	node := startTestServer(t, st, nil)

	t.Run("QueryA_ReturnsAnswer", func(t *testing.T) {
		t.Parallel()
		msg, err := sendUDPQuery(t, node.addr, "example.com", dns.TypeA)
		require.NoError(t, err)
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("QueryTXT_ReturnsAnswer", func(t *testing.T) {
		t.Parallel()
		msg, err := sendUDPQuery(t, node.addr, "sub.example.com", dns.TypeTXT)
		require.NoError(t, err)
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("MalformedPacket_NoResponseTimeout", func(t *testing.T) {
		t.Parallel()
		conn := dialContext(t, "udp", node.addr)
		defer func() { _ = conn.Close() }()

		_, err := conn.Write([]byte{0xFF, 0xFF, 0xFF})
		require.NoError(t, err)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
		resp := make([]byte, udpBufferSize)
		_, err = conn.Read(resp)

		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
		assert.True(t, netErr.Timeout())
	})
}

func TestServer_TCPServer(t *testing.T) {
	t.Parallel()

	st := newPopulatedFakeResolver()

	hugeTXT := strings.Repeat("A", 5000)
	rHuge, _ := dns.PackRData(dns.TypeTXT, hugeTXT)
	st.Add("huge.example.com", dns.RRSet{
		Type:  dns.TypeTXT,
		Class: dns.ClassIN,
		TTL:   300,
		RData: [][]byte{rHuge},
	})

	node := startTestServer(t, st, nil)

	t.Run("QueryA_ReturnsAnswer", func(t *testing.T) {
		t.Parallel()
		msg := sendTCPQuery(t, node.addr, "example.com", dns.TypeA)
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("QueryTXT_ReturnsAnswer", func(t *testing.T) {
		t.Parallel()
		msg := sendTCPQuery(t, node.addr, "example.com", dns.TypeTXT)
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("GiantPayload_UsesTCPPoolWithoutPanic", func(t *testing.T) {
		t.Parallel()
		msg := sendTCPQuery(t, node.addr, "huge.example.com", dns.TypeTXT)
		assert.Equal(t, uint16(1), msg.Header.ANCount)
	})

	t.Run("Pipelining_MalformedThenValidQueryKeepsConnOpen", func(t *testing.T) {
		t.Parallel()
		conn := dialContext(t, "tcp", node.addr)
		defer func() { _ = conn.Close() }()

		_, err := conn.Write(tcpLenPrefixed([]byte{0xAA, 0xBB, 0xCC}))
		require.NoError(t, err)

		query := buildQuery(t, "example.com", dns.TypeA)
		_, err = conn.Write(tcpLenPrefixed(query))
		require.NoError(t, err)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		var lenPrefix [2]byte
		_, err = io.ReadFull(conn, lenPrefix[:])
		require.NoError(t, err)

		respLen := binary.BigEndian.Uint16(lenPrefix[:])
		respBuf := make([]byte, respLen)
		_, err = io.ReadFull(conn, respBuf)
		require.NoError(t, err)

		var msg dns.Message
		require.NoError(t, msg.Unpack(respBuf))
	})

	t.Run("ZeroLengthPrefixClosesConn", func(t *testing.T) {
		t.Parallel()
		conn := dialContext(t, "tcp", node.addr)
		defer func() { _ = conn.Close() }()

		var lenPrefix [2]byte
		binary.BigEndian.PutUint16(lenPrefix[:], 0)
		_, err := conn.Write(lenPrefix[:])
		require.NoError(t, err)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(1*time.Second)))
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		require.Error(t, err)
	})
}

func TestServer_DoTServer(t *testing.T) {
	t.Parallel()

	st := newPopulatedFakeResolver()

	serverTLS, clientTLS := generateTestTLSConfig(t)
	node := startTestServer(t, st, serverTLS)

	t.Run("QueryA_OverDoT_ReturnsAnswer", func(t *testing.T) {
		t.Parallel()
		dialer := &tls.Dialer{
			Config: clientTLS,
		}
		conn, err := dialer.DialContext(t.Context(), "tcp", node.dotAddr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		query := buildQuery(t, "example.com", dns.TypeA)
		_, err = conn.Write(tcpLenPrefixed(query))
		require.NoError(t, err)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
		var lenBuf [2]byte
		_, err = io.ReadFull(conn, lenBuf[:])
		require.NoError(t, err)

		respBuf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		_, err = io.ReadFull(conn, respBuf)
		require.NoError(t, err)

		var resp dns.Message
		require.NoError(t, resp.Unpack(respBuf))
		assert.Equal(t, uint16(1), resp.Header.ANCount)
	})
}

type panickingResolver struct {
	shouldPanic atomic.Bool
}

func (p *panickingResolver) Resolve(_ string, _ dns.Type) dns.Result {
	if p.shouldPanic.Load() {
		panic("simulated resolver crash")
	}
	return dns.Result{
		RCode: dns.RCodeSuccess,
		Answer: dns.RRSet{
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   300,
			RData: [][]byte{dns.MustPackRData(dns.TypeA, "1.2.3.4")},
		},
	}
}

func TestServer_TCPHandler_PanicRecovery(t *testing.T) {
	t.Parallel()

	res := &panickingResolver{}
	res.shouldPanic.Store(true)
	node := startTestServer(t, res, nil)

	// 1. Send query to panicking resolver - should not crash server, connection will be closed
	conn := dialContext(t, "tcp", node.addr)

	query := buildQuery(t, "panic.example.com", dns.TypeA)
	_, err := conn.Write(tcpLenPrefixed(query))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(1*time.Second)))
	var lenBuf [2]byte
	_, err = io.ReadFull(conn, lenBuf[:])
	require.Error(t, err, "connection must be closed when handler panics")
	_ = conn.Close()

	// 2. Clear panic flag and verify server is still running and resolving queries cleanly
	res.shouldPanic.Store(false)
	conn2 := dialContext(t, "tcp", node.addr)
	defer func() { _ = conn2.Close() }()

	_, err = conn2.Write(tcpLenPrefixed(query))
	require.NoError(t, err)

	require.NoError(t, conn2.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = io.ReadFull(conn2, lenBuf[:])
	require.NoError(t, err)

	respBuf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	_, err = io.ReadFull(conn2, respBuf)
	require.NoError(t, err)

	var resp dns.Message
	require.NoError(t, resp.Unpack(respBuf))
	assert.Equal(t, dns.RCodeSuccess, dns.RCode(resp.Header.Flags&0x0F))
	assert.Equal(t, uint16(1), resp.Header.ANCount)
}

// generateTestTLSConfig builds an ephemeral self-signed cert for testing DoT.
func generateTestTLSConfig(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"KDNS Test"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(parsedCert)

	clientCfg := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	return serverCfg, clientCfg
}
