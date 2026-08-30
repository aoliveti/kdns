// Copyright (c) 2026 Andrea Oliveti All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsig

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/aoliveti/kdns/internal/dns"
)

// Sign appends an authenticated TSIG signature RR to a DNS response buffer and updates ARCount.
func Sign(respBuf []byte, respLen int, reqMAC []byte, key Key, tsigErr uint16, now time.Time) (int, error) {
	algo := CanonicalAlgorithm(key.Algorithm)
	h, err := newHasher(algo, key.Secret)
	if err != nil {
		return respLen, err
	}

	nowSec := max(now.Unix(), 0)
	timeSigned := uint64(nowSec)
	fudge := uint16(defaultFudge)

	// RFC 2845 §4.2: In responses, prepend the Request MAC to digest buffer.
	if len(reqMAC) > 0 {
		var reqMACLen [2]byte
		binary.BigEndian.PutUint16(reqMACLen[:], uint16(min(len(reqMAC), 65535)))
		h.Write(reqMACLen[:])
		h.Write(reqMAC)
	}

	h.Write(respBuf[:respLen])

	var otherData []byte
	if tsigErr == dns.TSIGErrBadTime {
		otherData = make([]byte, 6)
		binary.BigEndian.PutUint16(otherData[0:2], uint16((timeSigned>>32)&0xFFFF))
		binary.BigEndian.PutUint32(otherData[2:6], uint32(timeSigned&0xFFFFFFFF))
	}

	keyName := CanonicalName(key.Name)
	writeTSIGVariables(h, keyName, algo, timeSigned, fudge, tsigErr, otherData)

	mac := h.Sum(nil)

	offset := respLen
	keyWire := dns.EncodeDomainName(keyName)
	algoWire := dns.EncodeDomainName(algo)

	rdataLen := len(algoWire) + 6 + 2 + 2 + len(mac) + 2 + 2 + 2 + len(otherData)
	totalRRLen := len(keyWire) + 2 + 2 + 4 + 2 + rdataLen

	if offset+totalRRLen > cap(respBuf) && offset+totalRRLen > len(respBuf) {
		return respLen, fmt.Errorf("insufficient buffer space for TSIG response: needed %d", offset+totalRRLen)
	}

	copy(respBuf[offset:], keyWire)
	offset += len(keyWire)

	binary.BigEndian.PutUint16(respBuf[offset:offset+2], uint16(dns.TypeTSIG))
	offset += 2

	binary.BigEndian.PutUint16(respBuf[offset:offset+2], uint16(dns.ClassANY))
	offset += 2

	binary.BigEndian.PutUint32(respBuf[offset:offset+4], 0)
	offset += 4

	binary.BigEndian.PutUint16(respBuf[offset:offset+2], uint16(min(rdataLen, 65535)))
	offset += 2

	copy(respBuf[offset:], algoWire)
	offset += len(algoWire)

	binary.BigEndian.PutUint16(respBuf[offset:offset+2], uint16((timeSigned>>32)&0xFFFF))
	binary.BigEndian.PutUint32(respBuf[offset+2:offset+6], uint32(timeSigned&0xFFFFFFFF))
	offset += 6

	binary.BigEndian.PutUint16(respBuf[offset:offset+2], fudge)
	offset += 2

	binary.BigEndian.PutUint16(respBuf[offset:offset+2], uint16(min(len(mac), 65535)))
	offset += 2
	copy(respBuf[offset:], mac)
	offset += len(mac)

	origID := binary.BigEndian.Uint16(respBuf[0:2])
	binary.BigEndian.PutUint16(respBuf[offset:offset+2], origID)
	offset += 2

	binary.BigEndian.PutUint16(respBuf[offset:offset+2], tsigErr)
	offset += 2

	binary.BigEndian.PutUint16(respBuf[offset:offset+2], uint16(min(len(otherData), 65535)))
	offset += 2
	if len(otherData) > 0 {
		copy(respBuf[offset:], otherData)
		offset += len(otherData)
	}

	arCount := binary.BigEndian.Uint16(respBuf[10:12])
	binary.BigEndian.PutUint16(respBuf[10:12], arCount+1)

	return offset, nil
}
