// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnssec implements cryptographic DNSSEC signing on-the-fly,
// NSEC denial of existence generation, and key management (RFC 4033, 4034, 4035, 5155, 6605, 8080).
package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aoliveti/kdns/internal/dns"
)

const (
	// ECDSAP256 represents ECDSA curve P-256 with SHA-256 (Algorithm 13, RFC 6605).
	ECDSAP256 byte = 13
	// ED25519 represents Edwards-curve Digital Signature Algorithm with SHA-512 (Algorithm 15, RFC 8080).
	ED25519 byte = 15

	// FlagZSK identifies a Zone Signing Key (RFC 4034 §2.1.1).
	FlagZSK uint16 = 256
	// FlagKSK identifies a Key Signing Key with Secure Entry Point set (RFC 3757 / RFC 4034 §2.1.1).
	FlagKSK uint16 = 257

	// DigestSHA256 specifies the SHA-256 digest algorithm for DS records (RFC 4509).
	DigestSHA256 byte = 2

	protocolDNSSEC byte = 3
)

var (
	// ErrUnsupportedAlgorithm indicates an unrecognized or unsupported DNSSEC cryptographic algorithm.
	ErrUnsupportedAlgorithm = errors.New("dnssec: unsupported algorithm")
	// ErrNoKeysFound indicates no signing keys are configured for the requested zone.
	ErrNoKeysFound = errors.New("dnssec: no signing keys found for zone")
)

// Key represents a cryptographic private/public key pair and its pre-rendered DNSKEY wire format.
type Key struct {
	Zone       string
	PrivateKey crypto.Signer
	PublicKey  []byte
	DNSKEYWire []byte
	Flags      uint16
	KeyTag     uint16
	Algorithm  byte
	Protocol   byte
}

// KeyTag computes the 16-bit checksum over a DNSKEY RDATA wire payload as specified in RFC 4034 Appendix B.
func KeyTag(rdata []byte) uint16 {
	var ac uint32
	for i, b := range rdata {
		if i&1 == 1 {
			ac += uint32(b)
			continue
		}
		ac += uint32(b) << 8
	}
	ac += (ac >> 16) & 0xFFFF
	return uint16(ac & 0xFFFF)
}

// NewECDSAKey generates an ECDSA P-256 key pair for the specified zone.
func NewECDSAKey(zone string, flags uint16) (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa p256 key: %w", err)
	}

	ecdhKey, ecdhErr := priv.PublicKey.ECDH()
	if ecdhErr != nil {
		return nil, fmt.Errorf("ecdh conversion: %w", ecdhErr)
	}
	pubBytes := slices.Clone(ecdhKey.Bytes()[1:]) // RFC 6605 raw 64-byte uncompressed (X || Y)

	return newKey(zone, flags, ECDSAP256, pubBytes, priv), nil
}

// NewEd25519Key generates an Ed25519 key pair for the specified zone.
func NewEd25519Key(zone string, flags uint16) (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	return newKey(zone, flags, ED25519, pub, priv), nil
}

func newKey(zone string, flags uint16, algo byte, pub []byte, priv crypto.Signer) *Key {
	wire := make([]byte, 4+len(pub))
	binary.BigEndian.PutUint16(wire[0:2], flags)
	wire[2] = protocolDNSSEC
	wire[3] = algo
	copy(wire[4:], pub)

	return &Key{
		Zone:       canonicalZone(zone),
		Flags:      flags,
		Protocol:   protocolDNSSEC,
		Algorithm:  algo,
		PublicKey:  pub,
		PrivateKey: priv,
		DNSKEYWire: wire,
		KeyTag:     KeyTag(wire),
	}
}

// DS generates a Delegation Signer (DS) record RData using SHA-256.
func (k *Key) DS() []byte {
	ownerWire := dns.EncodeDomainName(k.Zone)
	data := make([]byte, 0, len(ownerWire)+len(k.DNSKEYWire))
	data = append(data, ownerWire...)
	data = append(data, k.DNSKEYWire...)

	digest := sha256.Sum256(data)

	ds := make([]byte, 4+len(digest))
	binary.BigEndian.PutUint16(ds[0:2], k.KeyTag)
	ds[2] = k.Algorithm
	ds[3] = DigestSHA256
	copy(ds[4:], digest[:])
	return ds
}

// Tag calculates the 16-bit key tag checksum over the DNSKEY wire format (RFC 4034 Appendix B).
func (k *Key) Tag() uint16 {
	return k.KeyTag
}

// Sign computes the raw cryptographic signature over a canonical DNSSEC buffer.
func (k *Key) Sign(data []byte) ([]byte, error) {
	switch k.Algorithm {
	case ECDSAP256:
		priv, ok := k.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("dnssec: private key is not ECDSA")
		}
		digest := sha256.Sum256(data)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			return nil, fmt.Errorf("ecdsa sign: %w", err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil

	case ED25519:
		priv, ok := k.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("dnssec: private key is not Ed25519")
		}
		return ed25519.Sign(priv, data), nil

	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func canonicalZone(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || lower == "." {
		return "."
	}
	if !strings.HasSuffix(lower, ".") {
		lower += "."
	}
	return lower
}
