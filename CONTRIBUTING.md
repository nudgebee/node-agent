# Contributing

Thanks for your interest in contributing. This document covers the
basics; see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community
expectations and [SECURITY.md](SECURITY.md) for vulnerability reports.

## Requirements

- Linux ≥ 5.1, amd64 or arm64 (the agent only builds and runs on Linux)
- Go ≥ 1.24
- `libsystemd-dev` (for journald log reading)
- `clang`, `llvm`, `make`, `pkg-config` (only required if you change eBPF code)

The repository is a fork of
[coroot/coroot-node-agent](https://github.com/coroot/coroot-node-agent);
see [NOTICE](NOTICE) for attribution.

## Running locally

```sh
sudo go run .
curl http://127.0.0.1:80/metrics
```

The agent needs `CAP_SYS_ADMIN` / `CAP_BPF` to load eBPF programs and
host-pid + cgroup access to enumerate containers — `sudo` covers all of
this during development.

## Pull-request checklist

- Branch off `main`; rebase if `main` has moved before opening the PR.
- Keep commits small and self-contained — each commit should build and
  pass tests on its own.
- Add tests for new functionality or bug fixes.
- `make lint` must pass (gofmt, goimports, go vet, go mod tidy).
- `make test` must pass.
- Update `CHANGELOG.md` under `## [Unreleased]` for user-visible changes.

## eBPF changes

The compiled eBPF programs live in `ebpftracer/ebpf.go`, which is
generated. If you edit anything under `ebpftracer/ebpf/`, regenerate:

```sh
cd ebpftracer
make build
```

Commit the regenerated `ebpf.go` along with your `.c`/`.h` changes. The
main Dockerfile only runs `go build` and will not rebuild eBPF for you.

## Module layout

- `cgroup/` — cgroup v1/v2 inspection and PSI
- `common/` — shared utilities including the IP→FQDN resolver
- `containers/` — container discovery, log readers, LLM detection and
  parsing, per-container metric registries
- `ebpftracer/` — eBPF probe loader and L7 protocol parsers
- `node/`, `node/metadata/` — host-level metrics and cloud metadata
- `prom/` — Prometheus remote-write client
- `logs/`, `tracing/`, `profiling/` — OpenTelemetry exporters

## License

By submitting a contribution you agree to license your changes under
the same terms as the project: Apache-2.0 for Go code, GPL-2.0 for
eBPF C code.

No Developer Certificate of Origin (DCO) sign-off or Contributor
License Agreement (CLA) is required — opening a pull request is taken
as acceptance of the above.
