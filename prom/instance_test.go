package prom

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// legacy is the derivation earlier releases used; InstanceID must reproduce it
// when there is nothing extra to add, so hosts keep their existing series.
func legacy(machineID, systemUUID string) string {
	instance := machineID
	if s := systemUUIDNoDashes(systemUUID); s != "" && s != machineID {
		h := md5.New()
		h.Write([]byte(machineID))
		h.Write([]byte(s))
		instance = hex.EncodeToString(h.Sum(nil))
	}
	return instance
}

func systemUUIDNoDashes(s string) string {
	out := ""
	for _, r := range s {
		if r != '-' {
			out += string(r)
		}
	}
	return out
}

func TestInstanceID_MatchesLegacyWithoutExtras(t *testing.T) {
	for _, c := range []struct{ machine, uuid string }{
		{"aaaa", "11111111-2222-3333-4444-555555555555"},
		{"aaaa", ""},
		{"aaaa", "aaaa"},
		{"", ""},
	} {
		if got, want := InstanceID(c.machine, c.uuid), legacy(c.machine, c.uuid); got != want {
			t.Errorf("InstanceID(%q,%q) = %q, legacy %q", c.machine, c.uuid, got, want)
		}
	}
}

// The failure this exists for: clones share machine-id and the hypervisor gives
// them the same (or no) system UUID, so the legacy derivation cannot tell them apart.
func TestInstanceID_ClonesWithSameMachineAndUUIDDiffer(t *testing.T) {
	const machine, uuid = "aaaa", "11111111-2222-3333-4444-555555555555"
	if legacy(machine, uuid) != legacy(machine, uuid) {
		t.Fatal("legacy must be deterministic")
	}
	a := InstanceID(machine, uuid, "mac:52:54:00:00:00:01")
	b := InstanceID(machine, uuid, "mac:52:54:00:00:00:02")
	if a == b {
		t.Fatal("clones with different NICs must get different instances")
	}
	c := InstanceID(machine, "", "cloud:i-0abc")
	d := InstanceID(machine, "", "cloud:i-0def")
	if c == d {
		t.Fatal("clones with different cloud instance ids must get different instances")
	}
}

func TestInstanceID_Stable(t *testing.T) {
	a := InstanceID("m", "u", "cloud:i-1", "mac:aa", "mac:bb")
	if b := InstanceID("m", "u", "cloud:i-1", "mac:aa", "mac:bb"); a != b {
		t.Fatalf("not stable: %q vs %q", a, b)
	}
}

func TestInstanceID_ExtrasAreDelimited(t *testing.T) {
	if InstanceID("m", "", "ab", "c") == InstanceID("m", "", "a", "bc") {
		t.Fatal("extras must not run together")
	}
}

func TestInstanceID_EmptyExtrasIgnored(t *testing.T) {
	if InstanceID("m", "u", "", "") != InstanceID("m", "u") {
		t.Fatal("empty extras must not change the instance")
	}
}

func writeNIC(t *testing.T, root, name string, device bool, address, assign string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if device {
		if err := os.Mkdir(filepath.Join(dir, "device"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "address"), []byte(address+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if assign != "" {
		if err := os.WriteFile(filepath.Join(dir, "addr_assign_type"), []byte(assign+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHardwareMACs(t *testing.T) {
	root := t.TempDir()
	writeNIC(t, root, "ens3", true, "52:54:00:AB:CD:02", "0") // real NIC, upper case
	writeNIC(t, root, "ens4", true, "52:54:00:ab:cd:01", "0")
	writeNIC(t, root, "docker0", false, "02:42:ac:11:00:01", "") // no backing device
	writeNIC(t, root, "veth1", false, "de:ad:be:ef:00:01", "1")  // virtual, random
	writeNIC(t, root, "ens5", true, "7a:00:00:00:00:09", "1")    // random at boot: unstable
	writeNIC(t, root, "ens6", true, "00:00:00:00:00:00", "0")    // unset
	writeNIC(t, root, "lo", false, "00:00:00:00:00:00", "")

	got := hardwareMACs(root)
	want := []string{"52:54:00:ab:cd:01", "52:54:00:ab:cd:02"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestHardwareMACs_MissingDir(t *testing.T) {
	if got := hardwareMACs(filepath.Join(t.TempDir(), "nope")); got != nil {
		t.Fatalf("got %v", got)
	}
}

func TestHostIdentityExtras(t *testing.T) {
	root := t.TempDir()
	writeNIC(t, root, "ens3", true, "52:54:00:00:00:01", "0")
	got := HostIdentityExtras("i-0abc", root)
	if len(got) != 2 || got[0] != "cloud:i-0abc" || got[1] != "mac:52:54:00:00:00:01" {
		t.Fatalf("got %v", got)
	}
	if got := HostIdentityExtras("", filepath.Join(root, "missing")); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}
