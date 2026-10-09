package prom

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// InstanceID derives the `instance` label that tells one machine's series from
// another's in the metrics store.
//
// machine-id alone is not enough: VMs cloned from one image share it. The system
// UUID (SMBIOS product_uuid) usually differs per clone, so it is folded in. But
// when the hypervisor reports no UUID, or the same one for a copied disk, two
// clones collapse into one instance and their series overwrite each other. The
// extras (cloud instance id, hardware NIC addresses) are per-machine inputs that
// still differ in those cases.
//
// With no extras the result is byte-for-byte what earlier releases produced, so a
// host that has nothing extra to add keeps its existing series.
func InstanceID(machineID, systemUUID string, extras ...string) string {
	uuid := strings.ReplaceAll(systemUUID, "-", "")
	var parts []string
	if uuid != "" && uuid != machineID {
		parts = append(parts, uuid)
	}
	for _, e := range extras {
		if e != "" {
			// A separator keeps ("ab","c") and ("a","bc") from hashing alike.
			parts = append(parts, "\x00"+e)
		}
	}
	if len(parts) == 0 {
		return machineID
	}
	h := md5.New()
	h.Write([]byte(machineID))
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HostIdentityExtras collects the per-machine inputs InstanceID mixes in beyond
// machine-id and system UUID: the cloud instance id when running in a cloud, and
// the permanent hardware addresses of the host's NICs.
func HostIdentityExtras(cloudInstanceID, sysClassNet string) []string {
	var extras []string
	if cloudInstanceID != "" {
		extras = append(extras, "cloud:"+cloudInstanceID)
	}
	for _, mac := range hardwareMACs(sysClassNet) {
		extras = append(extras, "mac:"+mac)
	}
	return extras
}

// hardwareMACs lists the sorted, permanent MAC addresses of real NICs under
// /sys/class/net. Interfaces without a backing device (bridges, veth, docker0,
// tunnels) are skipped, as are addresses the kernel generated at boot
// (addr_assign_type 1, random): those would change identity on every restart.
func hardwareMACs(sysClassNet string) []string {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil
	}
	var macs []string
	for _, e := range entries {
		dir := filepath.Join(sysClassNet, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "device")); err != nil {
			continue
		}
		if t, err := os.ReadFile(filepath.Join(dir, "addr_assign_type")); err == nil && strings.TrimSpace(string(t)) == "1" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "address"))
		if err != nil {
			continue
		}
		mac := strings.ToLower(strings.TrimSpace(string(b)))
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	return macs
}
