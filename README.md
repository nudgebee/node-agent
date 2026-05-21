# Nudgebee Node Agent

[![Continuous Integration](https://github.com/nudgebee/node-agent/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/nudgebee/node-agent/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/nudgebee/node-agent)](https://goreportcard.com/report/github.com/nudgebee/node-agent)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A per-node observability agent for Kubernetes and Linux hosts. The agent
gathers container and host metrics, logs, and L7 traffic using eBPF and
exposes them in Prometheus format.

Minimum Linux kernel: **5.1** (eBPF CO-RE).

> This project is a fork of
> [coroot/coroot-node-agent](https://github.com/coroot/coroot-node-agent)
> with additional features developed at Nudgebee. See [NOTICE](NOTICE)
> for attribution and [CHANGELOG.md](CHANGELOG.md) for the list of
> divergences from upstream.

## Features

### Inherited from upstream

- **TCP connection tracing** — service map and inter-service latency,
  derived from eBPF `connect()` / `accept()` / retransmit / RTT events.
- **Log pattern extraction** — clusters container logs into recurring
  patterns at the node, drastically reducing log volume for analysis.
  Reads from `/var/log/`, journald, dockerd, and containerd CRI logs.
- **Delay accounting** — per-container CPU and disk-wait metrics from
  the kernel's [delay accounting](https://www.kernel.org/doc/html/latest/accounting/delay-accounting.html)
  subsystem via Netlink.
- **OOM-kill events** — surfaces `container_oom_kills_total`.
- **Cloud instance metadata** — auto-detects AWS, GCP, Azure, Hetzner,
  IBM Cloud, and Oracle Cloud and tags metrics with account ID,
  instance type, region, AZ, lifecycle (spot/on-demand), and addresses.
- **GPU monitoring** (NVIDIA via NVML), JVM metrics (via JMX/jattach),
  .NET and Node.js process detection.

### Added in this fork

- **LLM observability** — detects calls to OpenAI, Anthropic, AWS
  Bedrock, Google AI, Mistral, and OpenAI-compatible endpoints from
  eBPF-traced TLS sessions, and emits per-request metrics including
  model name, token counts, latency, and estimated cost.
- **IP-to-FQDN resolver** — enriches outbound flows with hostnames by
  observing HTTP `Host` headers and DNS responses, so the service map
  shows `api.example.com` instead of `203.0.113.42`.
- **Enhanced L7 protocol detection** — TLS SNI extraction, lightweight
  HTTP/2 parsing with HPACK, improved Go TLS capture, Node.js TLS,
  FoundationDB.
- **PSI cgroup metrics** — pressure-stall info for CPU, memory, and IO.
- **Stability fixes** — graceful shutdown, bounded caches, label
  cardinality controls, panic guards in L7 parsers, OOM mitigations.

## Installation

### Kubernetes (DaemonSet)

```sh
kubectl apply -f https://raw.githubusercontent.com/nudgebee/node-agent/main/manifests/nudgebee-node-agent.yaml
```

This creates the `nudgebee` namespace and a privileged DaemonSet that
exposes `/metrics` on port 80.

### systemd (bare-metal)

```sh
curl -fsSL https://raw.githubusercontent.com/nudgebee/node-agent/main/install.sh | sudo sh -
```

Pass `-v vX.Y.Z` to pin to a specific release. The script writes a
systemd unit at `/etc/systemd/system/nudgebee-node-agent.service` and
starts it.

### Container image

Multi-arch images (linux/amd64, linux/arm64) are published to GHCR on
every tag:

```
ghcr.io/nudgebee/node-agent:<version>
ghcr.io/nudgebee/node-agent:<major>.<minor>
ghcr.io/nudgebee/node-agent:<major>
```

## Metrics

The agent exposes Prometheus metrics on `:80/metrics`. Self-identifying
label: `job="nudgebee-node-agent"`. The full metric catalogue
(inherited from upstream) is documented at
[docs.coroot.com/metrics/node-agent](https://docs.coroot.com/metrics/node-agent);
nudgebee-specific LLM and FQDN-resolver metrics will be documented
under `docs/` in this repo.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and pull requests
are welcome.

## Security

Please report vulnerabilities privately per [SECURITY.md](SECURITY.md).

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).

The eBPF C code in `ebpftracer/ebpf/` is licensed under the GNU General
Public License, Version 2.0; see [LICENSES/GPL-2.0.txt](LICENSES/GPL-2.0.txt).

See [NOTICE](NOTICE) for attribution to the original
coroot/coroot-node-agent project.
