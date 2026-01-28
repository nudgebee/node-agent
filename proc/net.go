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
	if col == -1 {
		return netaddr.IPPort{}
	}

	var ip [16]byte
	var ipp netaddr.IP
	if col == 8 {
		if _, err := hex.Decode(ip[:4], src[:8]); err != nil {
			return netaddr.IPPort{}
		}
		v := binary.BigEndian.Uint32(ip[:4])
		binary.LittleEndian.PutUint32(ip[:4], v)
		ipp = netaddr.IPv4(ip[0], ip[1], ip[2], ip[3])
	} else if col == 32 {
		if _, err := hex.Decode(ip[:], src[:32]); err != nil {
			return netaddr.IPPort{}
		}
		for i := 0; i < 16; i += 4 {
			v := binary.BigEndian.Uint32(ip[i : i+4])
			binary.LittleEndian.PutUint32(ip[i:i+4], v)
		}
		ipp = netaddr.IPFrom16(ip)
	} else {
		return netaddr.IPPort{}
	}

	if len(src) < col+1+4 {
		return netaddr.IPPort{}
	}
	var port [2]byte
	if _, err := hex.Decode(port[:], src[col+1:col+1+4]); err != nil {
		return netaddr.IPPort{}
	}

	return netaddr.IPPortFrom(ipp, binary.BigEndian.Uint16(port[:]))
}
