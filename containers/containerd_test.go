package containers

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	versionapi "github.com/containerd/containerd/api/services/version/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

type fakeContainerd struct {
	containersapi.UnimplementedContainersServer
	versionapi.UnimplementedVersionServer
	namespaces []string
}

func (f *fakeContainerd) Version(context.Context, *emptypb.Empty) (*versionapi.VersionResponse, error) {
	return &versionapi.VersionResponse{Version: "test"}, nil
}

func (f *fakeContainerd) Get(ctx context.Context, req *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	f.namespaces = append(f.namespaces, md.Get(containerdNamespaceHeader)...)
	if req.GetID() != "abc" {
		return nil, status.Error(codes.NotFound, "no such container")
	}
	spec, err := json.Marshal(map[string]any{
		"mounts": []map[string]string{{"destination": "/data", "source": "/var/lib/kubelet/pods/ed56844b-2ad5-4858-9305-abea47bd39fc/volumes/kubernetes.io~csi/pvc-90af9c02-ec70-446a-a16a-3ce17d4f42b4/mount"}},
	})
	if err != nil {
		return nil, err
	}
	return &containersapi.GetContainerResponse{Container: &containersapi.Container{
		ID:     "abc",
		Image:  "example.com/app:1",
		Labels: map[string]string{"io.kubernetes.pod.name": "app-0"},
		Spec:   &anypb.Any{Value: spec},
		Extensions: map[string]*anypb.Any{
			"io.cri-containerd.container.metadata": {Value: []byte(`{"Metadata":{"LogPath":"/var/log/pods/app.log"}}`)},
		},
	}}, nil
}

func TestContainerdInspect(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "containerd.sock")
	l, err := net.Listen("unix", socket)
	require.NoError(t, err)
	fake := &fakeContainerd{}
	srv := grpc.NewServer()
	containersapi.RegisterContainersServer(srv, fake)
	versionapi.RegisterVersionServer(srv, fake)
	go srv.Serve(l)
	defer srv.Stop()

	client, err := containerdConnect(socket)
	require.NoError(t, err)
	containerdClient = client
	defer func() { containerdClient = nil }()

	md, err := ContainerdInspect("abc")
	require.NoError(t, err)
	assert.Equal(t, "example.com/app:1", md.image)
	assert.Equal(t, "app-0", md.labels["io.kubernetes.pod.name"])
	assert.Equal(t, "pvc-90af9c02-ec70-446a-a16a-3ce17d4f42b4", md.volumes["/data"])
	assert.Equal(t, "/var/log/pods/app.log", md.logPath)
	assert.NotNil(t, md.logDecoder)
	assert.Equal(t, []string{"k8s.io"}, fake.namespaces)

	_, err = ContainerdInspect("missing")
	assert.Error(t, err)
}

func TestContainerdConnectNoSocket(t *testing.T) {
	_, err := containerdConnect(filepath.Join(t.TempDir(), "containerd.sock"))
	assert.Error(t, err)
}
