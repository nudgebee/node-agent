package logs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	otel "github.com/agoda-com/opentelemetry-logs-go"
	sdk "github.com/agoda-com/opentelemetry-logs-go/sdk/logs"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/nudgebee/logparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

type memExporter struct{ records []sdk.ReadableLogRecord }

func (e *memExporter) Export(_ context.Context, records []sdk.ReadableLogRecord) error {
	e.records = append(e.records, records...)
	return nil
}

func (e *memExporter) Shutdown(context.Context) error { return nil }

func withMemExporter(t *testing.T, node string) *memExporter {
	t.Helper()
	exp := &memExporter{}
	provider := sdk.NewLoggerProvider(sdk.WithSyncer(exp))
	prevLogger, prevNode := otelLogger, nodeName
	otelLogger, nodeName = provider.Logger("test"), node
	t.Cleanup(func() { otelLogger, nodeName = prevLogger, prevNode })
	return exp
}

// A Kubernetes container's records carry the attributes log queries filter on, the
// line's own time, and its stream.
func TestOtelLogEmitterKubernetesRecord(t *testing.T) {
	exp := withMemExporter(t, "node-a")
	ownerCalls := 0
	k8s := &K8sContainer{
		Namespace: "shop", Pod: "checkout-7d9f8b6c4-x2x9q", Container: "app",
		Owner: func() common.Workload {
			ownerCalls++
			return common.Workload{Name: "checkout", Namespace: "shop", Kind: "Deployment"}
		},
	}
	emit := OtelLogEmitter("/k8s/shop/checkout-7d9f8b6c4-x2x9q/app", k8s, nil)
	require.NotNil(t, emit)

	lineTime := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	emit(lineTime, logparser.LevelError, "h1", "connection refused", map[string]string{"order": "1"}, "stderr", 0)
	require.Len(t, exp.records, 1)
	r := exp.records[0]

	require.NotNil(t, r.Timestamp())
	assert.Equal(t, lineTime, *r.Timestamp(), "the line's own time")
	assert.True(t, r.ObservedTimestamp().After(lineTime), "when the agent emitted it")

	res := attrMap(r.Resource().Attributes())
	assert.Equal(t, []string{"shop"}, res["k8s.namespace.name"])
	assert.Equal(t, []string{"checkout-7d9f8b6c4-x2x9q"}, res["k8s.pod.name"])
	assert.Equal(t, []string{"app"}, res["k8s.container.name"])
	assert.Equal(t, []string{"node-a"}, res["k8s.node.name"])
	assert.Equal(t, []string{"checkout"}, res["k8s.deployment.name"])
	assert.Equal(t, []string{"/k8s/shop/checkout"}, res["service.name"], "the agent's service name, as on its traces")
	assert.Equal(t, []string{"/k8s/shop/checkout-7d9f8b6c4-x2x9q/app"}, res["container.id"])

	attrs := attrMap(*r.Attributes())
	assert.Equal(t, []string{"stderr"}, attrs["log.iostream"])
	assert.Equal(t, []string{"1"}, attrs["order"])

	// A parsed field named log.iostream gives way to the runtime's stream.
	emit(lineTime, logparser.LevelInfo, "h2", "ok", map[string]string{"log.iostream": "app-value"}, "stdout", 0)
	require.Len(t, exp.records, 2)
	assert.Equal(t, []string{"stdout"}, attrMap(*exp.records[1].Attributes())["log.iostream"])
	assert.Equal(t, res, attrMap(exp.records[1].Resource().Attributes()), "the container's resource, reused")
	assert.Equal(t, 1, ownerCalls)
}

// Init's exporter gzips its requests, since every record carries a copy of its
// container's resource.
func TestInitGzipsRequests(t *testing.T) {
	encodings := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encodings <- r.Header.Get("Content-Encoding")
	}))
	defer srv.Close()
	endpoint, err := url.Parse(srv.URL + "/v1/logs")
	require.NoError(t, err)
	prevEndpoint, prevLogger, prevNode := *flags.LogsEndpoint, otelLogger, nodeName
	prevDlv, prevRetrying := dlv, retrying
	*flags.LogsEndpoint = endpoint
	t.Cleanup(func() {
		*flags.LogsEndpoint, otelLogger, nodeName = prevEndpoint, prevLogger, prevNode
		dlv, retrying = prevDlv, prevRetrying
	})

	Init("machine-id", "host-a", "test")
	provider, ok := otel.GetLoggerProvider().(*sdk.LoggerProvider)
	require.True(t, ok)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	OtelLogEmitter("/system.slice/k3s.service", nil, nil)(time.Now(), logparser.LevelInfo, "", "started", nil, "", 0)
	require.NoError(t, provider.ForceFlush(context.Background()))

	select {
	case encoding := <-encodings:
		assert.Equal(t, "gzip", encoding)
	case <-time.After(5 * time.Second):
		t.Fatal("no export request")
	}
}

// Containers outside Kubernetes keep the records they had, plus the stream.
func TestOtelLogEmitterOtherContainer(t *testing.T) {
	exp := withMemExporter(t, "node-a")
	emit := OtelLogEmitter("/system.slice/k3s.service", nil, nil)
	emit(time.Now(), logparser.LevelInfo, "", "started", nil, "", 0)
	emit(time.Now(), logparser.LevelInfo, "", "ready", nil, "", 0)
	require.Len(t, exp.records, 2)

	res := attrMap(exp.records[0].Resource().Attributes())
	assert.NotContains(t, res, "k8s.pod.name")
	assert.NotContains(t, res, "k8s.node.name")
	assert.Equal(t, []string{"/system.slice/k3s.service"}, res["service.name"])
	assert.Equal(t, []string{"/system.slice/k3s.service"}, res["container.id"])
	assert.NotContains(t, attrMap(*exp.records[0].Attributes()), "log.iostream")
	assert.Equal(t, res, attrMap(exp.records[1].Resource().Attributes()), "the same resource for every record")
}

// The owner is looked up again after ownerRefresh, so a pod first resolved as itself
// (not indexed yet, and the API-server lookup failed: kind pod) gets its Deployment
// instead of no workload for the container's lifetime. The resource is built once
// and again only when the owner changes. Kinds log queries can't read set none, nor
// does a Job, whose resolved name can be an aggregate.
func TestK8sContainerOwnerIsRefreshed(t *testing.T) {
	calls := 0
	owners := []common.Workload{
		{Name: "checkout-7d9f8b6c4-x2x9q", Namespace: "shop", Kind: "pod"},
		{Name: "checkout", Namespace: "shop", Kind: "Deployment"},
	}
	k := &K8sContainer{Namespace: "shop", Pod: "checkout-7d9f8b6c4-x2x9q", Container: "c", Owner: func() common.Workload {
		w := owners[min(calls, len(owners)-1)]
		calls++
		return w
	}}
	base := []attribute.KeyValue{attribute.String("container.id", "/k8s/shop/checkout-7d9f8b6c4-x2x9q/c")}
	t0 := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)

	first := k.resource(base, t0)
	assert.NotContains(t, attrMap(first.Attributes()), "k8s.deployment.name")
	assert.Same(t, first, k.resource(base, t0.Add(30*time.Second)), "still cached")
	assert.Equal(t, 1, calls)

	refreshed := k.resource(base, t0.Add(ownerRefresh))
	assert.Equal(t, 2, calls)
	assert.NotSame(t, first, refreshed, "rebuilt: the owner changed")
	res := attrMap(refreshed.Attributes())
	assert.Equal(t, []string{"checkout"}, res["k8s.deployment.name"])
	assert.Equal(t, []string{"checkout-7d9f8b6c4-x2x9q"}, res["k8s.pod.name"])
	assert.Equal(t, []string{"/k8s/shop/checkout-7d9f8b6c4-x2x9q/c"}, res["container.id"])

	assert.Same(t, refreshed, k.resource(base, t0.Add(2*ownerRefresh)), "the same owner: not rebuilt")
	assert.Equal(t, 3, calls)

	for kind, key := range map[string]string{
		"StatefulSet": "k8s.statefulset.name", "DaemonSet": "k8s.daemonset.name",
		"CronJob": "k8s.cronjob.name",
	} {
		k := &K8sContainer{Owner: func() common.Workload { return common.Workload{Name: "w", Kind: kind} }}
		assert.Equal(t, []string{"w"}, attrMap(k.resource(nil, t0).Attributes())[key], kind)
	}
	for _, kind := range []string{"Job", "Rollout", "pod", ""} {
		k := &K8sContainer{Owner: func() common.Workload { return common.Workload{Name: "w", Kind: kind} }}
		for key := range attrMap(k.resource(nil, t0).Attributes()) {
			assert.NotRegexp(t, `^k8s\.(deployment|statefulset|daemonset|cronjob|job|rollout|replicaset)\.name$`, key, kind)
		}
	}
}
