package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	versionapi "github.com/containerd/containerd/api/services/version/v1"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/nudgebee/logparser"
	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"k8s.io/klog/v2"
)

const (
	containerdTimeout        = 30 * time.Second
	containerdConnectTimeout = time.Second
	containerdMaxMessageSize = 16 << 20

	// The namespace CRI keeps Kubernetes containers in, and the gRPC header
	// containerd reads it from.
	containerdNamespace       = "k8s.io"
	containerdNamespaceHeader = "containerd-namespace"
)

var (
	containerdClient containersapi.ContainersClient
)

func containerdConnect(socket string) (containersapi.ContainersClient, error) {
	conn, err := grpc.NewClient("unix://"+socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(containerdMaxMessageSize),
			grpc.MaxCallSendMsgSize(containerdMaxMessageSize),
		),
	)
	if err != nil {
		return nil, err
	}
	// grpc.NewClient connects lazily, so ask for the version to find out
	// whether anything is listening before settling on this socket.
	ctx, cancel := context.WithTimeout(context.Background(), containerdConnectTimeout)
	defer cancel()
	if _, err = versionapi.NewVersionClient(conn).Version(ctx, &emptypb.Empty{}); err != nil {
		conn.Close()
		return nil, err
	}
	return containersapi.NewContainersClient(conn), nil
}

func ContainerdInit() error {
	sockets := []string{
		"/var/snap/microk8s/common/run/containerd.sock",
		"/run/k0s/containerd.sock",
		"/run/k3s/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
	}
	var err error
	for _, socket := range sockets {
		containerdClient, err = containerdConnect(proc.HostPath(socket))
		if err == nil {
			klog.Infoln("using", socket)
			break
		}
	}
	if containerdClient == nil {
		return fmt.Errorf(
			"couldn't connect to containerd through the following UNIX sockets [%s]: %s",
			strings.Join(sockets, ","), err,
		)
	}
	return nil
}

func ContainerdInspect(containerID string) (*ContainerMetadata, error) {
	if containerdClient == nil {
		return nil, fmt.Errorf("containerd client not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), containerdTimeout)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, containerdNamespaceHeader, containerdNamespace)

	resp, err := containerdClient.Get(ctx, &containersapi.GetContainerRequest{ID: containerID})
	if err != nil {
		return nil, err
	}
	c := resp.GetContainer()

	res := &ContainerMetadata{
		labels:  c.Labels,
		image:   c.Image,
		volumes: map[string]string{},
	}

	var spec specs.Spec
	if err := json.Unmarshal(c.Spec.GetValue(), &spec); err != nil {
		klog.Warningln(err)
	} else {
		for _, m := range spec.Mounts {
			res.volumes[m.Destination] = common.ParseKubernetesVolumeSource(m.Source)
		}
	}

	if data, ok := c.Extensions["io.cri-containerd.container.metadata"]; ok {
		var md = struct { // from data.TypeUrl
			Metadata struct {
				LogPath string
			}
		}{}
		if err := json.Unmarshal(data.GetValue(), &md); err != nil {
			klog.Warningln(err)
		} else {
			res.logPath = md.Metadata.LogPath
			res.logDecoder = logparser.CriDecoder{}
		}
	}

	return res, nil
}
