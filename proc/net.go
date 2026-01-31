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
	// Optimization: Use stack-allocated buffers to avoid heap allocations
	col := bytes.IndexByte(src, ':')
	if col == -1 {
		return netaddr.IPPort{}
	}
	var ip netaddr.IP
	var buf [16]byte
	switch col {
	case 8:
		if _, err := hex.Decode(buf[:4], src[:col]); err != nil {
			return netaddr.IPPort{}
		}
		v := binary.BigEndian.Uint32(buf[:4])
		binary.LittleEndian.PutUint32(buf[:4], v)
		ip = netaddr.IPv4(buf[0], buf[1], buf[2], buf[3])
	case 32:
		if _, err := hex.Decode(buf[:], src[:col]); err != nil {
			return netaddr.IPPort{}
		}
		for i := 0; i < 16; i += 4 {
			v := binary.BigEndian.Uint32(buf[i : i+4])
			binary.LittleEndian.PutUint32(buf[i:i+4], v)
		}
		ip = netaddr.IPFrom16(buf)
	default:
		return netaddr.IPPort{}
	}

	var portBuf [2]byte
	if _, err := hex.Decode(portBuf[:], src[col+1:]); err != nil {
		return netaddr.IPPort{}
	}
	return netaddr.IPPortFrom(ip, binary.BigEndian.Uint16(portBuf[:]))
}
