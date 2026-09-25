package common

import (
	"errors"
	"os"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesConfig returns the API client config when the agent runs in a
// cluster, or outside one with KUBECONFIG set explicitly. It returns nil when
// neither holds, which means the agent is on a standalone host.
//
// A kubeconfig at the default path is deliberately not picked up: a VM used
// as an admin box often has /root/.kube/config, and silently resolving that
// VM's traffic against some unrelated cluster would mislabel all of it.
func KubernetesConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}
	if !errors.Is(err, rest.ErrNotInCluster) {
		return nil, err
	}
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return nil, nil
}
