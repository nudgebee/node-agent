package common

import (
	"os"
	"path/filepath"
	"testing"
)

const testKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://192.0.2.10:6443
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user:
    token: test
`

func TestKubernetesConfig(t *testing.T) {
	t.Run("standalone host", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		t.Setenv("KUBERNETES_SERVICE_PORT", "")
		t.Setenv("KUBECONFIG", "")
		// A kubeconfig at the default path must not switch a VM into
		// Kubernetes mode.
		home := t.TempDir()
		t.Setenv("HOME", home)
		if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".kube", "config"), []byte(testKubeconfig), 0o600); err != nil {
			t.Fatal(err)
		}

		config, err := KubernetesConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if config != nil {
			t.Fatalf("expected no kubernetes config on a standalone host, got %s", config.Host)
		}
	})

	t.Run("explicit KUBECONFIG", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		t.Setenv("KUBERNETES_SERVICE_PORT", "")
		path := filepath.Join(t.TempDir(), "config")
		if err := os.WriteFile(path, []byte(testKubeconfig), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KUBECONFIG", path)

		config, err := KubernetesConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if config == nil || config.Host != "https://192.0.2.10:6443" {
			t.Fatalf("expected config from KUBECONFIG, got %+v", config)
		}
	})

	t.Run("broken KUBECONFIG is an error, not standalone mode", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		t.Setenv("KUBERNETES_SERVICE_PORT", "")
		t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))

		if _, err := KubernetesConfig(); err == nil {
			t.Fatal("expected an error for a KUBECONFIG that does not exist")
		}
	})

	// In a pod the service env vars are always set. If the service account
	// token is missing, that is a misconfigured deployment and must fail
	// loudly instead of quietly running as a standalone host.
	t.Run("in cluster without token is an error", func(t *testing.T) {
		if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
			t.Skip("running inside a pod with a service account token")
		}
		t.Setenv("KUBERNETES_SERVICE_HOST", "192.0.2.1")
		t.Setenv("KUBERNETES_SERVICE_PORT", "443")
		t.Setenv("KUBECONFIG", "")

		if _, err := KubernetesConfig(); err == nil {
			t.Fatal("expected an error when in-cluster config is incomplete")
		}
	})
}
