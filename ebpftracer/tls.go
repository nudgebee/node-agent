package ebpftracer

import (
	"bufio"
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

const (
	goTlsWriteSymbol = "crypto/tls.(*Conn).Write"
	goTlsReadSymbol  = "crypto/tls.(*Conn).Read"

	// S2A (Secure Session Agent) symbols for Google Cloud SDK connections
	// S2A implements its own TLS record layer that bypasses crypto/tls
	// https://github.com/google/s2a-go
	goS2AWriteSymbol = "github.com/google/s2a-go/internal/record.(*conn).Write"
	goS2AReadSymbol  = "github.com/google/s2a-go/internal/record.(*conn).Read"

	// ALTS (Application Layer Transport Security) symbols for Google Cloud
	// gRPC connections on GCP. ALTS provides mutual authentication and
	// transport encryption without TLS — uses its own record protocol.
	// On GCP with Private Google Access, Google API calls may use ALTS
	// instead of TLS, completely bypassing crypto/tls and S2A.
	// The conn struct embeds net.Conn at offset 0, same as tls.Conn.
	goALTSWriteSymbol = "google.golang.org/grpc/credentials/alts/internal/conn.(*conn).Write"
	goALTSReadSymbol  = "google.golang.org/grpc/credentials/alts/internal/conn.(*conn).Read"
)

var (
	goTlsWriteSymbols = []string{goTlsWriteSymbol, goS2AWriteSymbol, goALTSWriteSymbol}
	goTlsReadSymbols  = []string{goTlsReadSymbol, goS2AReadSymbol, goALTSReadSymbol}
	// Every symbol resolved in one pass over the ELF symbol table, so a cache
	// miss costs a single parse rather than one per symbol.
	goTlsProbeSymbols = append(append([]string{}, goTlsWriteSymbols...), goTlsReadSymbols...)
)

// Additional TLS symbols to hook for HTTP/2 and gRPC connections
// These may use different code paths that bypass the standard Write/Read methods
var (
	// Internal TLS write method - less likely to be inlined
	goTlsWriteRecordSymbol = "crypto/tls.(*Conn).writeRecordLocked"
	// HTTP/2 framer methods for capturing HTTP/2 traffic
	goHttp2WriteDataSymbol    = "golang.org/x/net/http2.(*Framer).WriteData"
	goHttp2WriteHeadersSymbol = "golang.org/x/net/http2.(*Framer).WriteHeaders"
	// net/http internal HTTP/2 symbols
	goNetHttpHttp2WriteSymbol = "net/http.(*http2Framer).WriteData"
)

var (
	opensslVersionRe = regexp.MustCompile(`OpenSSL\s(\d\.\d+\.\d+)`)
	// Regex to find libraries that look like libssl or libcrypto, even with version numbers.
	// e.g., libssl.so.3, libcrypto-74fbf0e0.so.3
	libSslRe    = regexp.MustCompile(`libssl\.so(\.\d+)*`)
	libCryptoRe = regexp.MustCompile(`libcrypto\.so(\.\d+)*`)
	// A more specific regex for psycopg2's bundled libs
	psycopg2LibRe = regexp.MustCompile(`lib(ssl|crypto)-[a-f0-9]+\.so\.\d+`)
)

// openSslProbes lists every OpenSSL function the probes use. The _ex variants
// exist from 1.1.1 on, so they are attached only for those versions.
type openSslProbe struct {
	symbol    string
	uprobe    string
	uretprobe string
	needs111  bool
}

var openSslProbes = []openSslProbe{
	{symbol: "SSL_write", uprobe: "openssl_SSL_write_enter"},
	{symbol: "SSL_read", uprobe: "openssl_SSL_read_enter"},
	{symbol: "SSL_read", uretprobe: "openssl_SSL_read_exit"},
	{symbol: "SSL_free", uprobe: "openssl_SSL_free_enter"},
	{symbol: "SSL_write_ex", uprobe: "openssl_SSL_write_enter", needs111: true},
	{symbol: "SSL_read_ex", uprobe: "openssl_SSL_read_ex_enter", needs111: true},
	{symbol: "SSL_read_ex", uretprobe: "openssl_SSL_read_exit", needs111: true},
}

var openSslSymbols = []string{"SSL_write", "SSL_read", "SSL_free", "SSL_write_ex", "SSL_read_ex"}

func (t *Tracer) AttachOpenSslUprobes(pid uint32) ([]link.Link, TLSAttachResult) {
	if t.disableL7Tracing {
		return nil, TLSAttachNotApplicable
	}
	libPath, version := getSslLibPathAndVersion(pid)
	if libPath == "" || version == "" {
		klog.V(3).Infof("pid=%d: no SSL libraries found (libPath='%s', version='%s')", pid, libPath, version)
		return nil, TLSAttachNoLibrary
	}
	bin, err := binaryKeyFor(libPath)
	if err != nil {
		return nil, failureResult(err)
	}
	fail := func(msg string, err error) ([]link.Link, TLSAttachResult) {
		result := failureResult(err)
		if result == TLSAttachProcessExited {
			klog.V(3).Infof("pid=%d libssl_version=%s: %s: %s", pid, version, msg, err)
		} else {
			logTLSAttachOnce(bin, "openssl", result, "TLS capture unavailable for %s (libssl %s, first seen in pid %d): %s: %s", libPath, version, pid, msg, err)
		}
		return nil, result
	}

	// The programs are the same for every OpenSSL release: they never read the
	// SSL/BIO structs, whose layout is what used to differ between versions.
	// The version only decides whether the _ex variants exist.
	v, err := common.VersionFromString(version)
	if err != nil {
		logTLSAttachOnce(bin, "openssl", TLSAttachUnsupported, "TLS capture unavailable for %s: cannot parse libssl version %q: %s", libPath, version, err)
		return nil, TLSAttachUnsupported
	}
	hasEx := v.GreaterOrEqual(common.NewVersion(1, 1, 1))

	// Resolved once per library file rather than once per pid — see LookupSymbols.
	targets, err := LookupSymbols(libPath, openSslSymbols)
	if err != nil {
		return fail("failed to read symbols", err)
	}
	exe, err := link.OpenExecutable(libPath)
	if err != nil {
		return fail("failed to open executable", err)
	}
	var links []link.Link
	closeLinks := func() {
		for _, l := range links {
			l.Close()
		}
	}
	for _, p := range openSslProbes {
		if p.needs111 && !hasEx {
			continue
		}
		target := targets[p.symbol]
		if !target.Found {
			closeLinks()
			logTLSAttachOnce(bin, "openssl", TLSAttachNoSymbols, "TLS capture unavailable for %s (libssl %s): symbol %s not found", libPath, version, p.symbol)
			return nil, TLSAttachNoSymbols
		}
		if p.uprobe != "" {
			l, err := attachUprobeAt(exe, t.uprobes[p.uprobe], pid, target.Address)
			if err != nil {
				closeLinks()
				return fail("failed to attach uprobe to "+p.symbol, err)
			}
			links = append(links, l)
		}
		if p.uretprobe != "" {
			ls, err := attachUretprobesAt(exe, t.uprobes[p.uretprobe], pid, target)
			links = append(links, ls...)
			if err != nil {
				closeLinks()
				return fail("failed to attach exit uprobe to "+p.symbol, err)
			}
		}
	}
	if !logTLSAttachOnce(bin, "openssl", TLSAttached, "libssl uprobes attached: %s (libssl %s, pid %d; later processes using this library are logged at -v=2)", libPath, version, pid) {
		klog.V(2).Infof("pid=%d libssl_version=%s: libssl uprobes attached", pid, version)
	}
	return links, TLSAttached
}

// AttachGoTlsUprobes attaches the crypto/tls (and S2A, ALTS) probes to a Go
// process. isGolangApp reports whether the executable is a Go binary at all,
// whatever the result.
func (t *Tracer) AttachGoTlsUprobes(pid uint32) (links []link.Link, isGolangApp bool, result TLSAttachResult) {
	if t.disableL7Tracing {
		return nil, false, TLSAttachNotApplicable
	}

	path := proc.Path(pid, "exe")
	bin, err := binaryKeyFor(path)
	if err != nil {
		klog.V(3).Infof("GO_TLS_ATTACH_ATTEMPT: pid=%d exe=<unreadable>: %v", pid, err)
		return nil, false, failureResult(err)
	}
	// Binaries that can never be probed are recognised by file identity and
	// skipped before any parsing. This matters for repeated short-lived
	// processes such as CLI invocations and exec probes.
	if skip, ok := goTLSSkipCache.Get(bin); ok {
		return nil, skip.isGo, skip.result
	}

	name, _ := os.Readlink(path)
	klog.V(2).Infof("GO_TLS_ATTACH_ATTEMPT: pid=%d exe=%s", pid, name)

	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		if strings.HasSuffix(err.Error(), "not a Go executable") {
			goTLSSkipCache.Add(bin, goTLSSkip{result: TLSAttachNotApplicable})
			return nil, false, TLSAttachNotApplicable
		}
		result := failureResult(err)
		if result != TLSAttachProcessExited {
			logTLSAttachOnce(bin, "go", result, "Go TLS capture unavailable for %s (pid %d): failed to read build info: %s", name, pid, err)
		}
		return nil, false, result
	}
	version := bi.GoVersion
	v, err := common.VersionFromString(strings.Replace(version, "go", "", 1))
	if err != nil || !v.GreaterOrEqual(common.NewVersion(1, 17, 0)) {
		goTLSSkipCache.Add(bin, goTLSSkip{result: TLSAttachUnsupported, isGo: true})
		logTLSAttachOnce(bin, "go", TLSAttachUnsupported, "Go TLS capture unavailable for %s: %s is not supported (1.17 or later is required)", name, version)
		return nil, true, TLSAttachUnsupported
	}

	fail := func(msg string, err error) ([]link.Link, bool, TLSAttachResult) {
		result := failureResult(err)
		if result == TLSAttachProcessExited {
			klog.V(3).Infof("pid=%d golang_app=%s golang_version=%s: %s: %s", pid, name, version, msg, err)
		} else {
			logTLSAttachOnce(bin, "go", result, "Go TLS capture unavailable for %s (%s, first seen in pid %d): %s: %s", name, version, pid, msg, err)
		}
		return nil, true, result
	}
	noSymbols := func(symbol string) ([]link.Link, bool, TLSAttachResult) {
		goTLSSkipCache.Add(bin, goTLSSkip{result: TLSAttachNoSymbols, isGo: true})
		logTLSAttachOnce(bin, "go", TLSAttachNoSymbols, "Go TLS capture unavailable for %s (%s): %s not found; the binary does not use crypto/tls, or its function table cannot be read", name, version, symbol)
		return nil, true, TLSAttachNoSymbols
	}

	// Resolved once per binary rather than once per pid — see LookupSymbols.
	targets, err := LookupSymbols(path, goTlsProbeSymbols)
	if err != nil {
		return fail("failed to open as elf binary", err)
	}
	if !targets[goTlsWriteSymbol].Found {
		return noSymbols(goTlsWriteSymbol)
	}
	if !targets[goTlsReadSymbol].Found {
		return noSymbols(goTlsReadSymbol)
	}

	// Discover Go TLS offsets and populate the BPF map. Only binaries that
	// have probe points get this far, so a Go binary without crypto/tls never
	// pays for the DWARF read.
	result = TLSAttached
	if err := t.populateGoTLSOffsets(pid, path, version); err != nil {
		result = TLSAttachedNoOffsets
		logTLSAttachOnce(bin, "go", TLSAttachedNoOffsets, "Go TLS probes for %s (pid %d) run without per-process offsets, gRPC connections may not be captured: %v", name, pid, err)
	}

	exe, err := link.OpenExecutable(path)
	if err != nil {
		return fail("failed to open executable", err)
	}
	closeLinks := func() {
		for _, l := range links {
			l.Close()
		}
	}

	// Attach Write uprobes (crypto/tls + S2A + ALTS). crypto/tls is checked
	// above; S2A and ALTS are optional.
	for _, writeSymbol := range goTlsWriteSymbols {
		ws := targets[writeSymbol]
		if !ws.Found {
			continue
		}
		l, err := attachUprobeAt(exe, t.uprobes["go_crypto_tls_write_enter"], pid, ws.Address)
		if err != nil {
			closeLinks()
			return fail(fmt.Sprintf("failed to attach write_enter uprobe for %s", writeSymbol), err)
		}
		links = append(links, l)
	}

	// Attach Read uprobes + return-offset exit probes (crypto/tls + S2A + ALTS)
	for _, readSymbol := range goTlsReadSymbols {
		rs := targets[readSymbol]
		if !rs.Found {
			continue
		}
		l, err := attachUprobeAt(exe, t.uprobes["go_crypto_tls_read_enter"], pid, rs.Address)
		if err != nil {
			closeLinks()
			return fail(fmt.Sprintf("failed to attach read_enter uprobe for %s", readSymbol), err)
		}
		links = append(links, l)

		ls, err := attachUretprobesAt(exe, t.uprobes["go_crypto_tls_read_exit"], pid, rs)
		links = append(links, ls...)
		if err != nil {
			closeLinks()
			return fail(fmt.Sprintf("failed to attach read_exit uprobe for %s", readSymbol), err)
		}
	}
	if !logTLSAttachOnce(bin, "go", TLSAttached, "GO_TLS_SUCCESS: exe=%s go_version=%s uprobes_attached=%d (first pid %d; later processes of this binary are logged at -v=2)", name, version, len(links), pid) {
		klog.V(2).Infof("GO_TLS_SUCCESS: pid=%d exe=%s go_version=%s uprobes_attached=%d", pid, name, version, len(links))
	}
	return links, true, result
}

func getSslLibPathAndVersion(pid uint32) (string, string) {
	f, err := os.Open(proc.Path(pid, "maps"))
	if err != nil {
		klog.V(4).Infof("pid=%d: failed to open maps file: %v", pid, err)
		return "", ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	var libsslPath, libcryptoPath string
	var bundledSslPath, bundledCryptoPath string
	klog.V(4).Infof("pid=%d: scanning process maps for SSL libraries...", pid)
	seen := map[string]bool{}
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) <= 5 {
			continue
		}
		libPath := parts[5]
		if seen[libPath] {
			continue
		}
		seen[libPath] = true

		isBundled := strings.Contains(libPath, "psycopg2") && psycopg2LibRe.MatchString(libPath)
		isSsl := libSslRe.MatchString(libPath) || (isBundled && strings.Contains(libPath, "libssl"))
		isCrypto := libCryptoRe.MatchString(libPath) || (isBundled && strings.Contains(libPath, "libcrypto"))

		if isSsl {
			fullPath := proc.Path(pid, "root", libPath)
			if _, err = os.Stat(fullPath); err == nil {
				if isBundled {
					if bundledSslPath == "" {
						bundledSslPath = fullPath
						klog.V(3).Infof("pid=%d: found bundled libssl at %s (will prefer system lib if available)", pid, fullPath)
					}
				} else if libsslPath == "" {
					libsslPath = fullPath
					klog.V(3).Infof("pid=%d: found system libssl at %s", pid, fullPath)
				}
			} else {
				klog.V(4).Infof("pid=%d: libssl candidate %s not accessible: %v", pid, fullPath, err)
			}
		}
		if isCrypto {
			fullPath := proc.Path(pid, "root", libPath)
			if _, err = os.Stat(fullPath); err == nil {
				if isBundled {
					if bundledCryptoPath == "" {
						bundledCryptoPath = fullPath
						klog.V(3).Infof("pid=%d: found bundled libcrypto at %s (will prefer system lib if available)", pid, fullPath)
					}
				} else if libcryptoPath == "" {
					libcryptoPath = fullPath
					klog.V(3).Infof("pid=%d: found system libcrypto at %s", pid, fullPath)
				}
			} else {
				klog.V(4).Infof("pid=%d: libcrypto candidate %s not accessible: %v", pid, fullPath, err)
			}
		}
	}
	// Fall back to bundled libs if no system libs found
	if libsslPath == "" {
		libsslPath = bundledSslPath
	}
	if libcryptoPath == "" {
		libcryptoPath = bundledCryptoPath
	}
	if libsslPath == "" || libcryptoPath == "" {
		klog.V(3).Infof("pid=%d: SSL libraries incomplete (libssl='%s', libcrypto='%s')", pid, libsslPath, libcryptoPath)
		return "", ""
	}

	ef, err := elf.Open(libcryptoPath)
	if err != nil {
		return "", ""
	}
	defer ef.Close()
	rodataSection := ef.Section(".rodata")
	if rodataSection == nil {
		return "", ""
	}
	rodataSectionData, err := rodataSection.Data()
	if err != nil {
		return "", ""
	}
	var version string
	for _, b := range bytes.Split(rodataSectionData, []byte("\x00")) {
		if len(b) == 0 {
			continue
		}
		s := string(b)
		if !strings.HasPrefix(s, "OpenSSL") {
			continue
		}
		if m := opensslVersionRe.FindStringSubmatch(s); len(m) > 1 {
			version = m[1]
		}
	}
	return libsslPath, "v" + version
}

// populateGoTLSOffsets discovers Go TLS offsets and populates the BPF map for a process.
// This allows the eBPF code to use dynamic offsets instead of hardcoded values.
func (t *Tracer) populateGoTLSOffsets(pid uint32, binaryPath string, goVersion string) error {
	offsetsMap := t.collection.Maps["go_tls_offsets_map"]
	if offsetsMap == nil {
		return fmt.Errorf("go_tls_offsets_map not found in BPF collection")
	}

	offsets, err := DiscoverGoTLSOffsets(binaryPath, goVersion)
	if err != nil {
		return fmt.Errorf("failed to discover offsets: %w", err)
	}

	offsetsC := offsets.ToC()

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, offsetsC); err != nil {
		return fmt.Errorf("failed to serialize offsets: %w", err)
	}

	if err := offsetsMap.Update(unsafe.Pointer(&pid), buf.Bytes(), 0); err != nil {
		return fmt.Errorf("failed to update BPF map: %w", err)
	}

	klog.V(2).Infof("pid=%d: populated Go TLS offsets: tls_conn=%d, conn_fd=%d, netfd_pfd=%d, fd_sysfd=%d, tcp_itab=0x%x, grpc_itab=0x%x",
		pid, offsets.TLSConnConnOffset, offsets.ConnFdOffset, offsets.NetFDPfdOffset, offsets.FDSysfdOffset,
		offsets.NetTCPConnItab, offsets.GRPCSyscallConnItab)

	return nil
}

// ReleaseGoTLSOffsets removes pid's entry from go_tls_offsets_map; call it
// when the process exits. Nothing in the kernel removes these entries, so
// without this every short-lived Go process leaves one behind. Once the
// map's 1024 slots are full, every later Go process is probed without its
// itab addresses. On a busy node the map filled within two hours.
func (t *Tracer) ReleaseGoTLSOffsets(pid uint32) {
	m := t.readyMap("go_tls_offsets_map")
	if m == nil {
		return
	}
	if err := m.Delete(pid); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		klog.V(3).Infof("pid=%d: failed to remove Go TLS offsets: %v", pid, err)
	}
}
