// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
	"github.com/aoliveti/kdns/internal/rrl"
)

// Start opens network sockets and begins accepting incoming DNS traffic on configured protocols.
func (s *Server) Start(ctx context.Context) error {
	if s.res == nil {
		return ErrNilResolver
	}

	s.mu.Lock()
	ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("bind UDP listener on %s: %w", s.addr, err)
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", s.addr)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("resolve TCP address: %w", err)
	}
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("bind TCP listener on %s: %w", s.addr, err)
	}

	var dotListener net.Listener
	if s.hasDoT() {
		dotListener, err = tls.Listen("tcp", s.dotAddr, s.tlsConfig)
		if err != nil {
			_ = udpConn.Close()
			_ = tcpListener.Close()
			return fmt.Errorf("bind DoT listener on %s: %w", s.dotAddr, err)
		}
	}

	logAttrs := []any{slog.String("addr", s.addr)}
	if dotListener != nil {
		logAttrs = append(logAttrs, slog.String("dot_addr", s.dotAddr))
	}
	s.logger.Info("dns server listening", logAttrs...)

	s.wg.Go(func() {
		defer func() { _ = udpConn.Close() }()
		s.serveUDP(ctx, udpConn)
	})

	s.wg.Go(func() {
		defer func() { _ = tcpListener.Close() }()
		s.serveTCP(ctx, tcpListener, "tcp")
	})

	if dotListener != nil {
		s.wg.Go(func() {
			defer func() { _ = dotListener.Close() }()
			s.serveTCP(ctx, dotListener, "dot")
		})
	}

	<-ctx.Done()
	_ = udpConn.Close()
	_ = tcpListener.Close()
	if dotListener != nil {
		_ = dotListener.Close()
	}
	s.wg.Wait()

	s.logger.Info("dns server stopped gracefully")
	return nil
}

func (s *Server) serveUDP(ctx context.Context, conn *net.UDPConn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buf := s.udpPool.Get().(*[]byte)
			reqBuf := *buf

			_ = conn.SetReadDeadline(time.Now().Add(udpReadTimeout))
			n, remoteAddr, err := conn.ReadFrom(reqBuf)

			if err != nil {
				s.udpPool.Put(buf)
				if errors.Is(err, os.ErrDeadlineExceeded) || isTimeout(err) {
					continue
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case <-ctx.Done():
					return
				default:
					s.logger.Error("failed to read UDP packet", slog.Any("error", err))
					continue
				}
			}

			if err := s.handleUDPQuery(ctx, conn, remoteAddr, reqBuf[:n]); err != nil {
				switch {
				case errors.Is(err, ErrSocketWrite):
					if s.logger.Enabled(ctx, slog.LevelDebug) {
						s.logger.Debug("failed to write UDP response", slog.String("remote", remoteAddr.String()), slog.Any("error", err))
					}
				case errors.Is(err, ErrSerialization):
					s.logger.Error("failed to serialize response", slog.String("remote", remoteAddr.String()), slog.Any("error", err))
				}
			}
			s.udpPool.Put(buf)
		}
	}
}

func (s *Server) handleUDPQuery(ctx context.Context, conn *net.UDPConn, remote net.Addr, queryBytes []byte) error {
	s.metrics.IncQueriesUDP()
	s.metrics.AddBytesInUDP(uint64(len(queryBytes)))

	buf := s.udpPool.Get().(*[]byte)
	defer s.udpPool.Put(buf)

	written, qName, rCode, err := s.resolve(queryBytes, *buf, dns.MaxUDPSize)
	if err != nil {
		if errors.Is(err, ErrResponsePacket) || errors.Is(err, ErrMalformedQuery) {
			return nil
		}
		return err
	}

	if s.hasRRL() {
		clientIP := extractIP(remote)
		action := s.rrl.Check(clientIP, qName, rCode)

		switch action {
		case rrl.ActionAllow:
		case rrl.ActionDrop, rrl.ActionSlip:
			if s.logger.Enabled(ctx, slog.LevelDebug) {
				s.logger.Debug("rrl rate limit exceeded",
					slog.String("remote", clientIP.String()),
					slog.String("qname", qName),
					slog.String("rcode", rCode.String()),
					slog.String("action", action.String()),
				)
			}
			if action == rrl.ActionDrop {
				s.metrics.IncRRLDrop()
				return nil
			}
			s.metrics.IncRRLSlip()
			written = dns.TruncateToSlip(*buf, written)
		}
	}

	if _, err := conn.WriteTo((*buf)[:written], remote); err != nil {
		return fmt.Errorf("%w: %w", ErrSocketWrite, err)
	}
	if written > 0 {
		// #nosec G115
		s.metrics.AddBytesOutUDP(uint64(written))
	}

	return nil
}

func (s *Server) serveTCP(ctx context.Context, listener net.Listener, proto string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Error("failed to accept connection", slog.String("proto", proto), slog.Any("error", err))
				continue
			}
		}

		s.wg.Go(func() {
			s.handleTCPConn(ctx, conn, proto)
		})
	}
}

func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn, proto string) {
	s.metrics.IncTCPConnection()
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("panic recovered in dns tcp worker",
				slog.String("proto", proto),
				slog.String("remote", conn.RemoteAddr().String()),
				slog.Any("panic", r),
			)
		}
		s.metrics.DecTCPConnection()
		_ = conn.Close()
	}()

	remoteAddr := conn.RemoteAddr().String()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(tcpReadWriteTimeout))

		var lenPrefix [2]byte
		if _, err := io.ReadFull(conn, lenPrefix[:]); err != nil {
			return
		}

		length := binary.BigEndian.Uint16(lenPrefix[:])
		if length == 0 {
			return
		}

		reqPtr := s.tcpPool.Get().(*[]byte)
		reqBuf := (*reqPtr)[:length]

		if _, err := io.ReadFull(conn, reqBuf); err != nil {
			s.tcpPool.Put(reqPtr)
			return
		}

		s.recordTCPIn(proto, length)

		respPtr := s.tcpPool.Get().(*[]byte)
		written, _, _, err := s.resolve(reqBuf, *respPtr, dns.MaxTCPSize)
		s.tcpPool.Put(reqPtr)

		if err != nil {
			s.tcpPool.Put(respPtr)
			if errors.Is(err, ErrSerialization) {
				s.logger.Error("failed to serialize response", slog.String("remote", remoteAddr), slog.Any("error", err))
			}
			continue
		}

		if written > math.MaxUint16 {
			s.tcpPool.Put(respPtr)
			s.logger.Error("response exceeds uint16 length prefix", slog.String("remote", remoteAddr), slog.Int("written", written))
			return
		}

		var outPrefix [2]byte
		// #nosec G115
		binary.BigEndian.PutUint16(outPrefix[:], uint16(written))

		bufs := net.Buffers{
			outPrefix[:],
			(*respPtr)[:written],
		}

		_ = conn.SetWriteDeadline(time.Now().Add(tcpReadWriteTimeout))
		_, err = bufs.WriteTo(conn)
		s.tcpPool.Put(respPtr)

		if err != nil {
			if s.logger.Enabled(ctx, slog.LevelDebug) {
				s.logger.Debug("failed to write response", slog.String("proto", proto), slog.String("remote", remoteAddr), slog.Any("error", err))
			}
			return
		}

		s.recordTCPOut(proto, written)
	}
}

// recordTCPIn tracks ingress query and byte telemetry for TCP and DoT connections.
func (s *Server) recordTCPIn(proto string, length uint16) {
	if proto == "dot" {
		s.metrics.IncQueriesDoT()
		s.metrics.AddBytesInDoT(uint64(length + 2))
		return
	}
	s.metrics.IncQueriesTCP()
	s.metrics.AddBytesInTCP(uint64(length + 2))
}

// recordTCPOut tracks egress byte telemetry for TCP and DoT responses.
func (s *Server) recordTCPOut(proto string, written int) {
	// #nosec G115
	bytes := uint64(written + 2)
	if proto == "dot" {
		s.metrics.AddBytesOutDoT(bytes)
		return
	}
	s.metrics.AddBytesOutTCP(bytes)
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func extractIP(addr net.Addr) netip.Addr {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.AddrPort().Addr()
	case *net.TCPAddr:
		return a.AddrPort().Addr()
	default:
		if ap, err := netip.ParseAddrPort(addr.String()); err == nil {
			return ap.Addr()
		}
		return netip.Addr{}
	}
}
