package ebpftracer

import (
	"bufio"
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	lru "github.com/hashicorp/golang-lru/v2"
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

	// strippedGoExeCache caches exe paths that are Go binaries but have no TLS symbols.
	// This avoids expensive ELF scanning for the same stripped binary across many
	// short-lived processes (e.g., kubectl invocations). Capped at 1000 entries to
	// prevent unbounded growth on CI/CD nodes with many unique Go binaries.
	strippedGoExeCache, _ = lru.New[string, struct{}](1000)
)

func (t *Tracer) AttachOpenSslUprobes(pid uint32) []link.Link {
	if t.disableL7Tracing {
		return nil
	}
	libPath, version := getSslLibPathAndVersion(pid)
	if libPath == "" || version == "" {
		klog.V(3).Infof("pid=%d: no SSL libraries found (libPath='%s', version='%s')", pid, libPath, version)
		return nil
	}

	log := func(msg string, err error) {
		if err != nil {
			for _, s := range []string{"no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					return
				}
			}
			klog.ErrorfDepth(1, "pid=%d libssl_version=%s: %s: %s", pid, version, msg, err)
			return
		}
		klog.InfofDepth(1, "pid=%d libssl_version=%s: %s", pid, version, msg)
	}

	exe, err := link.OpenExecutable(libPath)
	if err != nil {
		log("failed to open executable", err)
		return nil
	}
	var links []link.Link
	closeLinks := func() {
		for _, l := range links {
			l.Close()
		}
	}
	writeEnter := "openssl_SSL_write_enter"
	readEnter := "openssl_SSL_read_enter"
	readExEnter := "openssl_SSL_read_ex_enter"
	readExit := "openssl_SSL_read_exit"
	v, err := common.VersionFromString(version)
	if err != nil {
		log("failed to determine version", err)
		return nil
	}
	switch {
	case v.GreaterOrEqual(common.NewVersion(3, 0, 0)):
		writeEnter = "openssl_SSL_write_enter_v3_0"
		readEnter = "openssl_SSL_read_enter_v3_0"
		readExEnter = "openssl_SSL_read_ex_enter_v3_0"
	case v.GreaterOrEqual(common.NewVersion(1, 1, 1)):
		writeEnter = "openssl_SSL_write_enter_v1_1_1"
		readEnter = "openssl_SSL_read_enter_v1_1_1"
		readExEnter = "openssl_SSL_read_ex_enter_v1_1_1"
	}

	type prog struct {
		symbol    string
		uprobe    string
		uretprobe string
	}
	progs := []prog{
		{symbol: "SSL_write", uprobe: writeEnter},
		{symbol: "SSL_read", uprobe: readEnter},
		{symbol: "SSL_read", uretprobe: readExit},
	}
	if v.GreaterOrEqual(common.NewVersion(1, 1, 1)) {
		progs = append(progs, []prog{
			{symbol: "SSL_write_ex", uprobe: writeEnter},
			{symbol: "SSL_read_ex", uprobe: readExEnter},
			{symbol: "SSL_read_ex", uretprobe: readExit},
		}...)
	}

	ef, err := OpenELFFile(libPath)
	if err != nil {
		log("open elf", err)
		return nil
	}
	defer ef.Close()

	for _, p := range progs {
		s, err := ef.GetSymbol(p.symbol)
		if err != nil {
			log("failed to get symbol", err)
			closeLinks()
			return nil
		}
		if p.uprobe != "" {
			l, err := s.AttachUprobe(exe, t.uprobes[p.uprobe], pid)
			if err != nil {
				log("failed to attach uprobe", err)
				closeLinks()
				return nil
			}
			links = append(links, l)
		}
		if p.uretprobe != "" {
			ls, err := s.AttachUretprobes(exe, t.uprobes[p.uretprobe], pid)
			links = append(links, ls...)
			if err != nil {
				log("failed to attach exit uprobe", err)
				closeLinks()
				return nil
			}
		}
	}
	if len(links) > 0 {
		log("libssl uprobes attached", nil)
	}
	return links
}

func (t *Tracer) AttachGoTlsUprobes(pid uint32) ([]link.Link, bool) {
	isGolangApp := false
	if t.disableL7Tracing {
		return nil, isGolangApp
	}

	path := proc.Path(pid, "exe")

	exeName, _ := os.Readlink(path)
	klog.V(2).Infof("GO_TLS_ATTACH_ATTEMPT: pid=%d exe=%s", pid, exeName)

	// Skip binaries we already know are stripped (no TLS symbols).
	// This avoids expensive ELF scanning for repeated short-lived processes like kubectl.
	if strippedGoExeCache.Contains(exeName) {
		klog.V(3).Infof("GO_TLS_SKIP_STRIPPED: pid=%d exe=%s", pid, exeName)
		return nil, true // still a Go app, just stripped
	}

	var err error
	var name, version string
	log := func(msg string, err error) {
		if err != nil {
			for _, s := range []string{"not a Go executable", "no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					klog.V(3).Infof("GO_TLS_FILTERED: pid=%d exe=%s msg=%s err=%s", pid, exeName, msg, err.Error())
					return
				}
			}
			klog.ErrorfDepth(1, "pid=%d golang_app=%s golang_version=%s: %s: %s", pid, name, version, msg, err)
			return
		}
		klog.InfofDepth(1, "pid=%d golang_app=%s golang_version=%s: %s", pid, name, version, msg)
	}

	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		log("failed to read build info", err)
		return nil, isGolangApp
	}
	klog.V(2).Infof("GO_TLS_BUILD_INFO: pid=%d exe=%s go_version=%s", pid, exeName, bi.GoVersion)
	isGolangApp = true

	name, err = os.Readlink(path)
	if err != nil {
		log("failed to read name", err)
		return nil, isGolangApp
	}
	version = bi.GoVersion
	v, err := common.VersionFromString(strings.Replace(bi.GoVersion, "go", "", 1))
	if err != nil {
		log("failed to determine version", err)
	}
	if !v.GreaterOrEqual(common.NewVersion(1, 17, 0)) {
		log("versions below 1.17 are not supported", nil)
		return nil, isGolangApp
	}

	// Discover Go TLS offsets and populate the BPF map
	if err := t.populateGoTLSOffsets(pid, path, version); err != nil {
		klog.V(2).Infof("pid=%d: failed to populate Go TLS offsets (will use defaults): %v", pid, err)
	}

	ef, err := OpenELFFile(path)
	if err != nil {
		log("failed to open as elf binary", err)
		return nil, isGolangApp
	}
	defer ef.Close()

	exe, err := link.OpenExecutable(path)
	if err != nil {
		log("failed to open executable", err)
		return nil, isGolangApp
	}

	var links []link.Link
	closeLinks := func() {
		for _, l := range links {
			l.Close()
		}
	}

	// Attach Write uprobes (crypto/tls + S2A + ALTS)
	for _, writeSymbol := range []string{goTlsWriteSymbol, goS2AWriteSymbol, goALTSWriteSymbol} {
		ws, err := ef.GetSymbol(writeSymbol)
		if err != nil {
			if writeSymbol == goTlsWriteSymbol {
				log("failed to get write symbol", err)
				// Cache this exe as stripped to skip future attempts
				if exeName != "" {
					strippedGoExeCache.Add(exeName, struct{}{})
				}
				return nil, isGolangApp
			}
			continue // S2A symbol is optional
		}
		l, err := ws.AttachUprobe(exe, t.uprobes["go_crypto_tls_write_enter"], pid)
		if err != nil {
			log(fmt.Sprintf("failed to attach write_enter uprobe for %s", writeSymbol), err)
			closeLinks()
			return nil, isGolangApp
		}
		links = append(links, l)
	}

	// Attach Read uprobes + return-offset exit probes (crypto/tls + S2A + ALTS)
	for _, readSymbol := range []string{goTlsReadSymbol, goS2AReadSymbol, goALTSReadSymbol} {
		rs, err := ef.GetSymbol(readSymbol)
		if err != nil {
			if readSymbol == goTlsReadSymbol {
				log("failed to get read symbol", err)
				closeLinks()
				return nil, isGolangApp
			}
			continue // S2A symbol is optional
		}
		l, err := rs.AttachUprobe(exe, t.uprobes["go_crypto_tls_read_enter"], pid)
		if err != nil {
			log(fmt.Sprintf("failed to attach read_enter uprobe for %s", readSymbol), err)
			closeLinks()
			return nil, isGolangApp
		}
		links = append(links, l)

		ls, err := rs.AttachUretprobes(exe, t.uprobes["go_crypto_tls_read_exit"], pid)
		links = append(links, ls...)
		if err != nil {
			log(fmt.Sprintf("failed to attach read_exit uprobe for %s", readSymbol), err)
			closeLinks()
			return nil, isGolangApp
		}
	}
	if len(links) == 0 {
		klog.V(1).Infof("GO_TLS_NO_UPROBES: pid=%d exe=%s - no crypto/tls or S2A uprobes attached (symbols may not be functions)", pid, name)
		return nil, isGolangApp
	}
	klog.Infof("GO_TLS_SUCCESS: pid=%d exe=%s go_version=%s uprobes_attached=%d", pid, name, version, len(links))
	log("crypto/tls uprobes attached", nil)
	return links, isGolangApp
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
