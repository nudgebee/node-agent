package ebpftracer

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/coroot/coroot-node-agent/common"
	"golang.org/x/sys/unix"
)

const goTLSWalkChildEnv = "GO_TLS_WALK_SERVER"

// statConn wraps a connection after a field, as VictoriaMetrics' scrape
// connections do: the walk finds the *net.TCPConn one level down, at offset 8.
type statConn struct {
	closed int32
	net.Conn
}

// decoy, read as a net.netFD, has the Sysfd of another socket and nothing else.
type decoy struct {
	_  [2]uint64
	fd int64
	_  [8]uint64
}

// decoyConn's first word points to a decoy. Read as a net.TCPConn, it names
// the decoy's socket, which is live and belongs to the same process, but is
// not the connection this TLS session runs over.
type decoyConn struct {
	d *decoy
	net.Conn
}

func connFd(c net.Conn) int {
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		panic(err)
	}
	var fd int
	if err := rc.Control(func(f uintptr) { fd = int(f) }); err != nil {
		panic(err)
	}
	return fd
}

// goTLSWalkChild runs in the traced process. It opens TLS sessions over a
// plain connection, a wrapped one and a decoy, reports their fds, and on "go"
// sends one HTTP request over each.
func goTLSWalkChild(addr string) {
	dial := func() net.Conn {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			panic(err)
		}
		return c
	}
	handshake := func(c net.Conn) *tls.Conn {
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			panic(err)
		}
		return tc
	}
	plain := dial()
	wrapped := dial()
	decoyTarget := dial()
	decoyed := dial()
	sessions := []struct {
		name string
		conn *tls.Conn
	}{
		{"plain", handshake(plain)},
		{"wrapped", handshake(&statConn{Conn: wrapped})},
		{"decoy", handshake(&decoyConn{d: &decoy{fd: int64(connFd(decoyTarget))}, Conn: decoyed})},
	}
	fds, _ := json.Marshal(map[string]int{
		"plain": connFd(plain), "wrapped": connFd(wrapped), "decoy": connFd(decoyed), "decoyTarget": connFd(decoyTarget),
	})
	fmt.Printf("fds %s\n", fds)

	in := bufio.NewReader(os.Stdin)
	if line, _ := in.ReadString('\n'); line != "go\n" {
		os.Exit(1)
	}
	for _, s := range sessions {
		fmt.Fprintf(s.conn, "GET /%s HTTP/1.1\r\nHost: walk\r\n\r\n", s.name)
		resp, err := http.ReadResponse(bufio.NewReader(s.conn), nil)
		if err != nil {
			panic(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("done")
	_, _ = io.Copy(io.Discard, in)
}

// TestGoTLSFdWalk runs Go TLS through the uprobes and checks which socket
// each session's plaintext is attributed to. A wrapper whose first word
// leads to another live socket of the process must not take that socket's
// fd; before netFD's fields were checked, it did. Run as root in a VM:
//
//	go test -c -o ebpftracer.test ./ebpftracer
//	sudo VM=1 ./ebpftracer.test -test.run TestGoTLSFdWalk -test.v
//
// Run it again with /sys/kernel/btf hidden (unshare -m, then mount a tmpfs
// over it) to cover a kernel without BTF.
func TestGoTLSFdWalk(t *testing.T) {
	if addr := os.Getenv(goTLSWalkChildEnv); addr != "" {
		goTLSWalkChild(addr)
		return
	}
	if os.Getenv("VM") == "" {
		t.Skip("loads eBPF programs into the running kernel; set VM=1 and run as root")
	}
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		t.Fatal(err)
	}
	if err := common.SetKernelVersion(unix.ByteSliceToString(uname.Release[:])); err != nil {
		t.Fatal(err)
	}

	events := make(chan Event, 10000)
	tt := NewTracer(0, 0, false, false)
	if err := tt.Run(events); err != nil {
		t.Fatal(err)
	}
	defer tt.Close()
	var mu sync.Mutex
	var l7 []Event
	go func() {
		for e := range events {
			if e.Type == EventTypeL7Request {
				mu.Lock()
				l7 = append(l7, e)
				mu.Unlock()
			}
		}
	}()
	info, _ := tt.EBPFInfo()
	t.Logf("variant %s, btf %v, socket offsets %v", info.ProgramVariant, info.KernelBTF, info.SocketOffsets)
	heuristic := "shape"
	if info.SocketOffsets {
		heuristic = "socket"
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name string
		// withItab keeps the binary's *net.TCPConn itab in the offsets map;
		// without it the walk runs as it does for a stripped or PIE binary.
		withItab bool
		resolved map[string]uint64 // "method/depth" -> calls
	}{
		// Each session makes one Write and at least one Read call.
		{"itab", true, map[string]uint64{"itab/0": 2, "itab/1": 2}},
		{"no_itab", false, map[string]uint64{heuristic + "/0": 2, heuristic + "/1": 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestGoTLSFdWalk$")
			cmd.Env = append(os.Environ(), goTLSWalkChildEnv+"="+srv.Listener.Addr().String())
			stdin, _ := cmd.StdinPipe()
			stdout, _ := cmd.StdoutPipe()
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = stdin.Close()
				_ = cmd.Wait()
			}()
			out := bufio.NewReader(stdout)
			line, err := out.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "fds ") {
				t.Fatalf("child: %q %v", line, err)
			}
			var fds map[string]uint64
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "fds ")), &fds); err != nil {
				t.Fatal(err)
			}
			pid := uint32(cmd.Process.Pid)

			links, _, result := tt.AttachGoTlsUprobes(pid)
			defer func() {
				for _, l := range links {
					_ = l.Close()
				}
			}()
			if result != TLSAttached {
				t.Fatalf("attach: %s", result)
			}
			if !tc.withItab {
				m := tt.collection.Maps["go_tls_offsets_map"]
				var o GoTLSOffsetsC
				if err := m.Lookup(pid, &o); err != nil {
					t.Fatal(err)
				}
				o.NetTCPConnItab = 0
				var buf bytes.Buffer
				_ = binary.Write(&buf, binary.LittleEndian, o)
				if err := m.Update(pid, buf.Bytes(), ebpf.UpdateExist); err != nil {
					t.Fatal(err)
				}
			}

			resolvedBefore := resolvedCounts(tt)
			droppedBefore, _ := tt.TLSPlaintextDropped()
			mu.Lock()
			l7 = nil
			mu.Unlock()

			if _, err := io.WriteString(stdin, "go\n"); err != nil {
				t.Fatal(err)
			}
			if line, err := out.ReadString('\n'); err != nil || line != "done\n" {
				t.Fatalf("child: %q %v", line, err)
			}
			time.Sleep(time.Second)

			mu.Lock()
			got := map[string][]uint64{}
			for _, e := range l7 {
				if e.Pid != pid || e.L7Request == nil {
					continue
				}
				for _, name := range []string{"plain", "wrapped", "decoy"} {
					if bytes.Contains(e.L7Request.Payload, []byte("GET /"+name+" ")) {
						got[name] = append(got[name], e.Fd)
					}
				}
			}
			mu.Unlock()
			t.Logf("fds %v, events by session %v", fds, got)
			for _, name := range []string{"plain", "wrapped"} {
				if len(got[name]) == 0 {
					t.Errorf("%s: no event", name)
				}
				for _, fd := range got[name] {
					if fd != fds[name] {
						t.Errorf("%s: event on fd %d, want %d", name, fd, fds[name])
					}
				}
			}
			for _, fd := range got["decoy"] {
				if fd == fds["decoyTarget"] {
					t.Errorf("decoy: plaintext attributed to the decoy's socket (fd %d)", fd)
				} else if fd != fds["decoy"] {
					t.Errorf("decoy: event on fd %d, want %d or none", fd, fds["decoy"])
				}
			}

			resolved := resolvedCounts(tt)
			for k := range resolved {
				resolved[k] -= resolvedBefore[k]
			}
			dropped, _ := tt.TLSPlaintextDropped()
			t.Logf("resolved %v, go_fd_unknown +%d", nonZero(resolved), dropped["go_fd_unknown"]-droppedBefore["go_fd_unknown"])
			for k, want := range tc.resolved {
				if resolved[k] < want {
					t.Errorf("resolved %s = %d, want at least %d", k, resolved[k], want)
				}
			}
			if dropped["go_fd_unknown"] == droppedBefore["go_fd_unknown"] && len(got["decoy"]) == 0 {
				t.Error("decoy session neither captured nor counted as go_fd_unknown")
			}
		})
	}
}

func resolvedCounts(tt *Tracer) map[string]uint64 {
	res := map[string]uint64{}
	rs, _ := tt.GoTLSFdResolved()
	for _, r := range rs {
		res[fmt.Sprintf("%s/%d", r.Method, r.Depth)] = r.Count
	}
	return res
}

func nonZero(m map[string]uint64) map[string]uint64 {
	res := map[string]uint64{}
	for k, v := range m {
		if v != 0 {
			res[k] = v
		}
	}
	return res
}
