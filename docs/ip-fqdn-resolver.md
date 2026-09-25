# IP-to-FQDN resolver

The agent enriches outbound network flows with a human-readable
destination identity. Instead of a service map full of dotted-quad
IPs, you get pod names, Kubernetes service names, deployment names,
or DNS hostnames.

This feature is specific to the nudgebee fork and is not present in
upstream `coroot/coroot-node-agent`.

## What it does

For each destination IP observed via an eBPF `connect()` event, the
resolver returns a *Workload* record with:

| Field       | Example                       | Source                                         |
| ----------- | ----------------------------- | ---------------------------------------------- |
| `Name`      | `payments-api` / `payments-7c…-xj9` / `api.openai.com` / `10.0.5.41` | K8s API or DNS cache |
| `Namespace` | `prod` / `node` / `external`  | K8s API or synthetic                           |
| `Kind`      | `Deployment` / `Service` / `pod` / `node` / `external` | K8s API or synthetic       |
| `Region`    | `us-east-1`                   | `topology.kubernetes.io/region` node label      |
| `Zone`      | `us-east-1c`                  | `topology.kubernetes.io/zone` node label        |
| `Instance`  | `ip-10-0-5-41.ec2.internal`   | name of the K8s Node hosting the destination   |

This record is attached as labels / span attributes to the affected
metrics and traces.

## Resolution order

Sources are checked in this priority:

1. **Service ClusterIP** — IP matches a `Service.spec.clusterIPs`.
   The selector is then walked to identify the backing
   Deployment / ReplicaSet / StatefulSet so the result includes the
   owning workload, not just the Service object.
2. **Pod IP** — IP matches a `Pod.status.podIPs`. Ownership references
   are followed upward (Pod → ReplicaSet → Deployment), and ephemeral
   pods (bare Pods, standalone Jobs) are aggregated by their standard
   `app.kubernetes.io/*` labels to prevent label cardinality blowups
   on workloads like Airflow tasks.
3. **Node IP** — IP matches a `Node.status.addresses`.
4. **eBPF DNS cache** — if `--resolve-dns` is enabled, fall back to
   reverse-resolution using DNS replies the agent has captured live
   on the node. No `net.LookupAddr` calls are made; only data already
   observed in flight.
5. **IP literal** — last resort: `Name = "<the IP>"`, kind =
   `external`, namespace = `external`.

When two sources would resolve the same IP (e.g. an in-cluster
proxy's Service IP overlapping a Pod IP), priority is deterministic:
Services > Nodes > Pods.

## What's watched

The resolver maintains Kubernetes informers on: Pods, Nodes, Services,
Deployments, ReplicaSets, DaemonSets, StatefulSets, Jobs, CronJobs.
Each watched object is stripped to a minimal projection (name,
namespace, labels, owner references, IPs) before being stored, which
reduces informer-cache memory roughly 5×.

The DNS cache is an LRU bounded at 10,000 entries. The pod-IP index
is an LRU bounded at 30,000 entries.

## Standalone hosts (no Kubernetes)

When the agent finds no Kubernetes API, it runs with a host-only
resolver instead. The agent is in a cluster when the in-cluster service
account config is present, or when `KUBECONFIG` is set explicitly. A
kubeconfig at the default path (`~/.kube/config`) is **not** used, so an
admin host with `kubectl` set up is not mistaken for a cluster node.

On a standalone host:

| Endpoint                      | `Name`                  | `Namespace`  | `Kind`      |
| ----------------------------- | ----------------------- | ------------ | ----------- |
| Connection source             | systemd unit or container name | host name | `container` |
| One of the host's own IPs     | host name               | host name    | `vm`        |
| Other private IP              | DNS name, else the IP   | `private`    | `private`   |
| Public IP                     | DNS name, else the IP   | `external`   | `external`  |
| Loopback                      | `localhost`             | `localhost`  | `localhost` |

The source of a connection is the service that opened it, not the
host's address. Private addresses are kept apart from `external`
because on a fleet of hosts they are usually other hosts, not the
internet. Matching a private IP to a specific host needs data from every
host, so it is left to whatever consumes the metrics.

## Configuration

| Flag                              | Default | Purpose                                                          |
| --------------------------------- | ------- | ---------------------------------------------------------------- |
| `--resolve-dns`                   | `true`  | Enable the DNS-cache fallback for non-cluster IPs                |
| `--aggregate-ephemeral-workloads` | `true`  | Collapse Job/bare-Pod cardinality via `app.kubernetes.io/*` labels |

All flags can also be set as environment variables — see
`flags/flags.go`.

## Limitations

- **K8s API access required.** Without RBAC permission to watch Pods,
  Services, Nodes, etc., the resolver falls back to DNS-cache and
  IP-literal only. The manifests in `manifests/` ship with the
  minimum RBAC needed.
- **In-cluster Service IPs only.** Resolution works on ClusterIP
  values; LoadBalancer/external IPs are seen as the underlying
  cloud-provider IP, which then falls through to DNS.
- **CNI-overlay NAT.** If a CNI rewrites source/destination IPs in
  ways the kernel doesn't surface in the connect tuple, the resolver
  sees the rewritten IP and resolves against that.
