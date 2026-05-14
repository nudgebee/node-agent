package l7

import (
	"encoding/binary"
	"errors"
)

// ParseSNI extracts the server_name (SNI) hostname from a TLS ClientHello
// record. The input must be a complete TLS handshake record starting with
// the 5-byte record header (type, version, length).
//
// Returns the hostname, or an empty string with an error if the record is
// malformed, not a ClientHello, or has no SNI extension. Errors are
// returned for diagnostics — callers typically treat any failure as
// "no SNI" and fall back to other detection.
func ParseSNI(record []byte) (string, error) {
	const (
		recordHeaderLen    = 5
		handshakeHeaderLen = 4
		clientRandomLen    = 32
		extServerName      = 0x0000
		nameTypeHostName   = 0x00
	)

	if len(record) < recordHeaderLen {
		return "", errors.New("record too short")
	}
	if record[0] != 0x16 {
		return "", errors.New("not a handshake record")
	}
	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLen+recordHeaderLen > len(record) {
		// We only have a prefix of the record. ClientHello is usually one
		// record; if it's fragmented across records the SNI parse below
		// will still work as long as the relevant fields fit in what we
		// have. Continue with the available bytes.
	}

	body := record[recordHeaderLen:]
	if len(body) < handshakeHeaderLen {
		return "", errors.New("handshake header truncated")
	}
	if body[0] != 0x01 {
		return "", errors.New("not a ClientHello")
	}
	// 3-byte handshake length follows; we don't enforce it here (a partial
	// payload is fine if the SNI extension still fits in what we have).
	body = body[handshakeHeaderLen:]

	// client_version (2) + random (32)
	if len(body) < 2+clientRandomLen {
		return "", errors.New("client random truncated")
	}
	body = body[2+clientRandomLen:]

	// session_id: 1-byte length + bytes
	if len(body) < 1 {
		return "", errors.New("session_id length truncated")
	}
	sessionIDLen := int(body[0])
	if 1+sessionIDLen > len(body) {
		return "", errors.New("session_id truncated")
	}
	body = body[1+sessionIDLen:]

	// cipher_suites: 2-byte length + bytes
	if len(body) < 2 {
		return "", errors.New("cipher_suites length truncated")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(body[0:2]))
	if 2+cipherSuitesLen > len(body) {
		return "", errors.New("cipher_suites truncated")
	}
	body = body[2+cipherSuitesLen:]

	// compression_methods: 1-byte length + bytes
	if len(body) < 1 {
		return "", errors.New("compression_methods length truncated")
	}
	compMethodsLen := int(body[0])
	if 1+compMethodsLen > len(body) {
		return "", errors.New("compression_methods truncated")
	}
	body = body[1+compMethodsLen:]

	// extensions: 2-byte length + bytes
	if len(body) < 2 {
		// No extensions present: TLS 1.0/1.1 may omit them. No SNI possible.
		return "", errors.New("no extensions")
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[0:2]))
	body = body[2:]
	if extensionsLen > len(body) {
		extensionsLen = len(body)
	}
	exts := body[:extensionsLen]

	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[0:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+extLen > len(exts) {
			return "", errors.New("extension data truncated")
		}
		extData := exts[4 : 4+extLen]
		exts = exts[4+extLen:]

		if extType != extServerName {
			continue
		}

		// server_name extension body: 2-byte list length, then list of
		// {nameType (1), nameLength (2), nameBytes (nameLength)}.
		if len(extData) < 2 {
			return "", errors.New("server_name list length truncated")
		}
		listLen := int(binary.BigEndian.Uint16(extData[0:2]))
		list := extData[2:]
		if listLen > len(list) {
			listLen = len(list)
		}
		list = list[:listLen]

		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:3]))
			if 3+nameLen > len(list) {
				return "", errors.New("server_name entry truncated")
			}
			if nameType == nameTypeHostName {
				return string(list[3 : 3+nameLen]), nil
			}
			list = list[3+nameLen:]
		}

		return "", errors.New("server_name list had no host_name entry")
	}

	return "", errors.New("server_name extension not found")
}
