package proc

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"

	"inet.af/netaddr"
)

const (
	stateEstablished = "01"
	stateListen      = "0A"
)

type Sock struct {
	Inode  string
	SAddr  netaddr.IPPort
	DAddr  netaddr.IPPort
	Listen bool
}

func GetSockets(pid uint32) ([]Sock, error) {
	var res []Sock
	var e error
	for _, f := range []string{"tcp", "tcp6"} {
		ss, err := readSockets(Path(pid, "net", f))
		if err != nil {
			e = err
		}
		res = append(res, ss...)
	}
	return res, e
}

func readSockets(src string) ([]Sock, error) {
	f, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var res []Sock
	scanner := bufio.NewScanner(f)
	header := true
	for scanner.Scan() {
		if header {
			header = false
			continue
		}
		b := scanner.Bytes()
		_, b = nextField(b)
		local, b := nextField(b)
		remote, b := nextField(b)
		st, b := nextField(b)
		state := string(st)
		if state != stateEstablished && state != stateListen {
			continue
		}
		_, b = nextField(b)
		_, b = nextField(b)
		_, b = nextField(b)
		_, b = nextField(b)
		_, b = nextField(b)
		inode, _ := nextField(b)
		res = append(res, Sock{SAddr: decodeAddr(local), DAddr: decodeAddr(remote), Listen: state == stateListen, Inode: string(inode)})
	}
	return res, nil
}

func nextField(s []byte) ([]byte, []byte) {
	for i, b := range s {
		if b != ' ' {
			s = s[i:]
			break
		}
	}
	for i, b := range s {
		if b == ' ' {
			return s[:i], s[i:]
		}
	}
	return nil, nil
}

func decodeAddr(src []byte) netaddr.IPPort {
	col := bytes.IndexByte(src, ':')
	if col == -1 || (col != 8 && col != 32) {
		return netaddr.IPPort{}
	}

	if len(src) < col+5 {
		return netaddr.IPPort{}
	}
	// Use stack-allocated buffer for port to avoid heap allocation.
	var portBuf [2]byte
	// Port is 4 hex characters.
	if _, err := hex.Decode(portBuf[:], src[col+1:col+5]); err != nil {
		return netaddr.IPPort{}
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	// IPv4 address in /proc/net/tcp is stored as a little-endian 32-bit hex number.
	// For example, 127.0.0.1 is 0100007F.
	// We decode the hex directly into a stack-allocated array and then reverse the bytes
	// to reconstruct the IP address in standard network order.
	if col == 8 {
		var ip [4]byte
		if _, err := hex.Decode(ip[:], src[:col]); err != nil {
			return netaddr.IPPort{}
		}
		ip[0], ip[1], ip[2], ip[3] = ip[3], ip[2], ip[1], ip[0]
		return netaddr.IPPortFrom(netaddr.IPv4(ip[0], ip[1], ip[2], ip[3]), port)
	}

	// IPv6 address is stored as 4 32-bit integers, each in little-endian hex format.
	var ip [16]byte
	if _, err := hex.Decode(ip[:], src[:col]); err != nil {
		return netaddr.IPPort{}
	}
	for i := 0; i < 16; i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = ip[i+3], ip[i+2], ip[i+1], ip[i]
	}
	return netaddr.IPPortFrom(netaddr.IPFrom16(ip), port)
}
