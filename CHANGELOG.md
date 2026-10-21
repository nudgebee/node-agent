# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Open-source release of the Nudgebee Node Agent, forked from
  [coroot/coroot-node-agent](https://github.com/coroot/coroot-node-agent).
- LLM observability pipeline: detects and parses LLM API traffic
  (OpenAI, Bedrock, Google AI, Anthropic, others) and emits per-request
  metrics with token counts, latency, and pricing.
- IP-to-FQDN resolver: enriches outbound flows with reverse-DNS names
  via HTTP `Host` headers and DNS metadata.
- Enhanced eBPF L7 protocol detection: TLS SNI, HTTP/2, Node.js, and
  improved Go TLS capture.
- Oracle Cloud instance-metadata support.
- Pressure Stall Information (PSI) cgroup metrics.
- Fleet install guide and an Ansible playbook for installing the agent on many hosts at once.
- Exported container logs carry `k8s.namespace.name`, `k8s.pod.name`,
  `k8s.container.name`, `k8s.node.name` (new `NODE_NAME` / `--node-name`,
  default: the host name), a Deployment, StatefulSet, DaemonSet or CronJob
  owner's `k8s.<kind>.name`, and `log.iostream`.
  Their record time is the line's own time from the container runtime, and
  lines the runtime split are joined.
- `LOGS_POSITIONS_FILE` / `--logs-positions-file`: where the agent saves how
  far each container log file has been delivered, so after a restart it resumes
  there instead of skipping the lines written meanwhile. A log file it has not
  seen before (a container that started while it was down, or since it found
  the containers running when it started) is read from its start; on its first
  run on a node, the files already there are read from their end.
  `LOGS_POSITIONS_MAX_AGE` / `--logs-positions-max-age` (default `24h`, `0`
  disables): a positions file saved longer ago than this is ignored, as on a
  first run, so a long downtime does not send a burst of old lines.

### Changed

- Prometheus `job` label and outbound `User-Agent` are now
  `nudgebee-node-agent`. Update any dashboards or alerts that filter on
  `job="coroot-node-agent"`.
- OpenTelemetry service name is now `nudgebee-node-agent`.
- Default systemd unit name is `nudgebee-node-agent.service`.
- Container image is published at `ghcr.io/nudgebee/node-agent`.
- Logs are exported gzip-compressed (`Content-Encoding: gzip`), so the
  `LOGS_ENDPOINT` receiver must accept gzip, as the OpenTelemetry
  Collector's OTLP/HTTP receiver does.
- Container logs are delivered at least once instead of dropped when the
  logs endpoint is unreachable, slow or restarting: export is retried (refused
  or reset connections, timeouts, 5xx, 429) until it succeeds, readers pause
  while many records wait (unsent lines stay in the log files), the old file
  is read to its end on rotation (also when it was rotated while the agent
  was down: it is found again by its inode), and on SIGTERM the agent delivers what it
  has read (up to 15 s) before exiting. A paused reader finishes the file it
  has open, then reads the files rotated in between that the kubelet has not
  gzipped yet (all but the newest), so an outage is absorbed while a
  container's log file is rotated at most twice; files gzipped before they are
  read are skipped, which the agent logs as a warning. After a restart the
  oldest file with undelivered lines is read, then the current one; files
  rotated in between are not, which the agent logs as a warning. Any other
  error (a 4xx other than 408 and 429, or a response that is not OTLP) drops
  the batch, since resending it would fail the same way. journald records are dropped while the endpoint is backed
  up and once the agent is stopping; `node_agent_log_records_dropped_total`
  counts dropped records by `reason` (`backpressure`, `shutdown`, `rejected`).
