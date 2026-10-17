package flags

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/alecthomas/kingpin.v2"
)

// install.sh copies only the variables listed in ENV_VARS into the systemd env
// file. A flag missing from that list can be set on Kubernetes but is silently
// dropped on a standalone host, so every flag's env var must be listed.
func TestInstallScriptPassesEveryFlagEnvVar(t *testing.T) {
	script, err := os.ReadFile("../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ENV_VARS="\^\(([A-Z0-9_|]+)\)="$`).FindSubmatch(script)
	if m == nil {
		t.Fatal(`ENV_VARS="^(A|B|...)=" not found in install.sh`)
	}
	listed := map[string]bool{}
	for _, name := range strings.Split(string(m[1]), "|") {
		listed[name] = true
	}

	flags := kingpin.CommandLine.Model().Flags
	if len(flags) == 0 {
		t.Fatal("no flags registered")
	}
	for _, f := range flags {
		if f.Envar == "" {
			continue
		}
		if !listed[f.Envar] {
			t.Errorf("install.sh ENV_VARS is missing %s (flag --%s)", f.Envar, f.Name)
		}
	}
}
