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

### Changed

- Prometheus `job` label and outbound `User-Agent` are now
  `nudgebee-node-agent`. Update any dashboards or alerts that filter on
  `job="coroot-node-agent"`.
- OpenTelemetry service name is now `nudgebee-node-agent`.
- Default systemd unit name is `nudgebee-node-agent.service`.
- Container image is published at `ghcr.io/nudgebee/node-agent`.
