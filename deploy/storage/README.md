# Storage for standalone hosts

On Kubernetes, the node-agent's metrics, traces and logs go to storage that
runs in the cluster. Standalone hosts have none, so this directory runs it on
one machine that every agent on the network sends to.

| Service | Stores | Port | Auth |
|---|---|---|---|
| gateway (nginx) | — receives from agents and routes | 8080 | `X-Api-Key` header (the agent's `API_KEY`) |
| VictoriaMetrics | metrics, 15 days | 8428 | basic auth |
| otel-collector → ClickHouse | traces and logs, 7 days | 8123 (ClickHouse HTTP) | password |

VictoriaMetrics accepts Prometheus remote-write and serves the Prometheus
query API, so anything that queries Prometheus can query it. ClickHouse uses
the same image and table layout (`otel_traces`, `otel_logs`) as the
Kubernetes chart.

If you already run a Prometheus-compatible store that accepts remote-write,
you can point `METRICS_ENDPOINT` at it and skip this one. Plain Prometheus
needs `--web.enable-remote-write-receiver`.

## Install

On a Linux machine with Docker and Compose v2, reachable from the hosts on
TCP 8080:

```sh
./setup.sh
```

The first run generates credentials in `.env`, readable by its owner only.
The script starts the stack and prints the agent install command. Re-running
it keeps the credentials. Set `STORAGE_HOST` if the address printed is not
the one the hosts should use.

Then, on each host:

```sh
curl -fsSL https://raw.githubusercontent.com/nudgebee/node-agent/main/install.sh | sudo \
  METRICS_ENDPOINT=http://STORAGE_HOST:8080/v1/metrics \
  TRACES_ENDPOINT=http://STORAGE_HOST:8080/v1/traces \
  LOGS_ENDPOINT=http://STORAGE_HOST:8080/v1/logs \
  API_KEY=... sh -
```

Set the three endpoints rather than `COLLECTOR_ENDPOINT`.
`COLLECTOR_ENDPOINT` also sets a profiles endpoint, which turns on eBPF CPU
profiling of every process on the host, and this stack has nowhere to store
profiles.

## Network

- **8080:** open to the hosts running the agent.
- **8428 and 8123:** open only to whatever queries the data. Both require
  credentials, but they should not be exposed more widely.

## Sizing

Rough starting point, to be refined:

- **Series:** about 300-450 per host with default settings.
- **Traces:** sampled at 10% by the agent (`TRACES_SAMPLING`). The collector
  drops health-check and `/metrics` spans and does not sample again.
- **ClickHouse:** the most memory-hungry service. Allow at least 2 GB for the
  machine.

## Retention

Set in `.env`, then run `docker compose up -d`:

- `METRICS_RETENTION` (default `15d`)
- `TRACES_RETENTION` (default `168h`), which applies to traces and logs
