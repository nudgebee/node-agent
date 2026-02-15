package ebpftracer

import (
	"bufio"
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
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
	for _, p := range progs {
		if p.uprobe != "" {
			l, err := exe.Uprobe(p.symbol, t.uprobes[p.uprobe], nil)
			if err != nil {
				log("failed to attach uprobe", err)
				return nil
			}
			links = append(links, l)
		}
		if p.uretprobe != "" {
			l, err := exe.Uretprobe(p.symbol, t.uprobes[p.uretprobe], nil)
			if err != nil {
				log("failed to attach uretprobe", err)
				return nil
			}
			links = append(links, l)
		}
	}

	log("libssl uprobes attached", nil)
	return links
}

func (t *Tracer) AttachGoTlsUprobes(pid uint32) ([]link.Link, bool) {
	isGolangApp := false
	if t.disableL7Tracing {
		return nil, isGolangApp
	}

	path := proc.Path(pid, "exe")

	// DEBUG: Log every attempt to attach Go TLS uprobes (at Info level for visibility)
	exeName, _ := os.Readlink(path)
	klog.Infof("GO_TLS_ATTACH_ATTEMPT: pid=%d exe=%s", pid, exeName)

	var err error
	var name, version string
	log := func(msg string, err error) {
		if err != nil {
			for _, s := range []string{"not a Go executable", "no such file or directory", "no such process", "permission denied"} {
				if strings.HasSuffix(err.Error(), s) {
					// DEBUG: Log filtered errors at Info level for visibility
					klog.Infof("GO_TLS_FILTERED: pid=%d exe=%s msg=%s err=%s", pid, exeName, msg, err.Error())
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
	klog.Infof("GO_TLS_BUILD_INFO: pid=%d exe=%s go_version=%s", pid, exeName, bi.GoVersion)
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

	ef, err := elf.Open(path)
	if err != nil {
		log("failed to open as elf binary", err)
		return nil, isGolangApp
	}
	defer ef.Close()

	symbols, err := ef.Symbols()
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			log("no symbol section", nil)
			return nil, isGolangApp
		}
		log("failed to read symbols", err)
		return nil, isGolangApp
	}

	textSection := ef.Section(".text")
	if textSection == nil {
		log("no text section", nil)
		return nil, isGolangApp
	}
	textReader := textSection.Open()

	exe, err := link.OpenExecutable(path)
	if err != nil {
		log("failed to open executable", err)
		return nil, isGolangApp
	}

	var links []link.Link
	// Log all crypto/tls, http2, and S2A symbols found for debugging
	foundS2A := false
	foundCryptoTLS := false
	for _, s := range symbols {
		if strings.Contains(s.Name, "crypto/tls") || strings.Contains(s.Name, "http2") || strings.Contains(s.Name, "s2a-go") {
			klog.V(3).Infof("pid=%d: found symbol %s (type=%d, size=%d, value=0x%x)",
				pid, s.Name, elf.ST_TYPE(s.Info), s.Size, s.Value)
			if s.Name == goS2AWriteSymbol || s.Name == goS2AReadSymbol {
				foundS2A = true
				klog.Infof("GO_TLS_S2A_SYMBOL: pid=%d exe=%s symbol=%s addr=0x%x", pid, name, s.Name, s.Value)
			}
			if s.Name == goTlsWriteSymbol || s.Name == goTlsReadSymbol {
				foundCryptoTLS = true
				klog.V(1).Infof("GO_TLS_CRYPTO_SYMBOL: pid=%d exe=%s symbol=%s addr=0x%x size=%d", pid, name, s.Name, s.Value, s.Size)
			}
		}
	}
	if !foundS2A {
		klog.V(2).Infof("GO_TLS_NO_S2A: pid=%d exe=%s", pid, name)
	}
	if !foundCryptoTLS {
		klog.V(1).Infof("GO_TLS_NO_CRYPTO_TLS: pid=%d exe=%s - no crypto/tls.(*Conn).Write/Read symbols found", pid, name)
	}

	for _, s := range symbols {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 {
			continue
		}
		switch s.Name {
		case goTlsWriteSymbol, goTlsReadSymbol, goS2AWriteSymbol, goS2AReadSymbol:
		default:
			continue
		}
		address := s.Value
		for _, p := range ef.Progs {
			if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
				continue
			}

			if p.Vaddr <= s.Value && s.Value < (p.Vaddr+p.Memsz) {
				address = s.Value - p.Vaddr + p.Off
				break
			}
		}
		switch s.Name {
		case goTlsWriteSymbol, goS2AWriteSymbol:
			l, err := exe.Uprobe(s.Name, t.uprobes["go_crypto_tls_write_enter"], &link.UprobeOptions{Address: address})
			if err != nil {
				log(fmt.Sprintf("failed to attach write_enter uprobe for %s", s.Name), err)
				return nil, isGolangApp
			}
			links = append(links, l)
			klog.V(1).Infof("GO_TLS_UPROBE_ATTACHED: pid=%d exe=%s symbol=%s type=write_enter addr=0x%x", pid, name, s.Name, address)
			if s.Name == goS2AWriteSymbol {
				klog.Infof("GO_TLS_S2A_WRITE_ATTACHED: pid=%d exe=%s addr=0x%x", pid, name, address)
			}
		case goTlsReadSymbol, goS2AReadSymbol:
			l, err := exe.Uprobe(s.Name, t.uprobes["go_crypto_tls_read_enter"], &link.UprobeOptions{Address: address})
			if err != nil {
				log(fmt.Sprintf("failed to attach read_enter uprobe for %s", s.Name), err)
				return nil, isGolangApp
			}
			links = append(links, l)
			klog.V(1).Infof("GO_TLS_UPROBE_ATTACHED: pid=%d exe=%s symbol=%s type=read_enter addr=0x%x", pid, name, s.Name, address)
			if s.Name == goS2AReadSymbol {
				klog.Infof("GO_TLS_S2A_READ_ATTACHED: pid=%d exe=%s addr=0x%x", pid, name, address)
			}
			sStart := s.Value - textSection.Addr
			_, err = textReader.Seek(int64(sStart), io.SeekStart)
			if err != nil {
				log("failed to seek", err)
				return nil, isGolangApp
			}
			sBytes := make([]byte, s.Size)
			_, err = textReader.Read(sBytes)
			if err != nil {
				log("failed to read", err)
				return nil, isGolangApp
			}
			returnOffsets := getReturnOffsets(ef.Machine, sBytes)
			if len(returnOffsets) == 0 {
				log("failed to attach read_exit uprobe", fmt.Errorf("no return offsets found"))
				return nil, isGolangApp
			}
			for _, offset := range returnOffsets {
				l, err := exe.Uprobe(s.Name, t.uprobes["go_crypto_tls_read_exit"], &link.UprobeOptions{Address: address, Offset: uint64(offset)})
				if err != nil {
					log("failed to attach read_exit uprobe", err)
					return nil, isGolangApp
				}
				links = append(links, l)
			}
			klog.V(1).Infof("GO_TLS_UPROBE_ATTACHED: pid=%d exe=%s symbol=%s type=read_exit return_offsets=%d", pid, name, s.Name, len(returnOffsets))
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

func getReturnOffsets(machine elf.Machine, instructions []byte) []int {
	var res []int
	switch machine {
	case elf.EM_X86_64:
		for i := 0; i < len(instructions); {
			ins, err := x86asm.Decode(instructions[i:], 64)
			if err == nil && ins.Op == x86asm.RET {
				res = append(res, i)
			}
			i += ins.Len
		}
	case elf.EM_AARCH64:
		for i := 0; i < len(instructions); {
			ins, err := arm64asm.Decode(instructions[i:])
			if err == nil && ins.Op == arm64asm.RET {
				res = append(res, i)
			}
			i += 4
		}
	}
	return res
}

// populateGoTLSOffsets discovers Go TLS offsets and populates the BPF map for a process.
// This allows the eBPF code to use dynamic offsets instead of hardcoded values.
func (t *Tracer) populateGoTLSOffsets(pid uint32, binaryPath string, goVersion string) error {
	// Get the BPF map
	offsetsMap := t.collection.Maps["go_tls_offsets_map"]
	if offsetsMap == nil {
		return fmt.Errorf("go_tls_offsets_map not found in BPF collection")
	}

	// Discover offsets from DWARF or use version-based fallbacks
	offsets, err := DiscoverGoTLSOffsets(binaryPath, goVersion)
	if err != nil {
		return fmt.Errorf("failed to discover offsets: %w", err)
	}

	// Convert to C struct format and write to BPF map
	offsetsC := offsets.ToC()

	// Serialize the struct to bytes (must match the BPF struct layout)
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, offsetsC); err != nil {
		return fmt.Errorf("failed to serialize offsets: %w", err)
	}

	// Update the BPF map with offsets for this process
	if err := offsetsMap.Update(unsafe.Pointer(&pid), buf.Bytes(), 0); err != nil {
		return fmt.Errorf("failed to update BPF map: %w", err)
	}

	klog.V(2).Infof("pid=%d: populated Go TLS offsets: tls_conn=%d, conn_fd=%d, netfd_pfd=%d, fd_sysfd=%d, tcp_itab=0x%x, grpc_itab=0x%x",
		pid, offsets.TLSConnConnOffset, offsets.ConnFdOffset, offsets.NetFDPfdOffset, offsets.FDSysfdOffset,
		offsets.NetTCPConnItab, offsets.GRPCSyscallConnItab)

	return nil
}
