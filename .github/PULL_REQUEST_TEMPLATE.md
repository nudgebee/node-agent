<!--
Thanks for the contribution. A short, focused description helps reviewers
move fast. Delete sections that aren't applicable.
-->

## What this PR does

<!-- One or two sentences. Focus on the "why" — the diff shows the "what". -->

## Linked issue / context

<!-- e.g. Fixes #123, or a short note if there's no issue. -->

## How was this tested?

<!--
- Unit tests added/updated?
- Did you run it on a real node / in a kind cluster?
- Did /metrics still look sane after the change?
-->

## eBPF changes?

<!--
If yes:
- [ ] I edited files under ebpftracer/ebpf/
- [ ] I ran `cd ebpftracer && make build` to regenerate ebpftracer/ebpf.go
- [ ] Both .c/.h sources and the regenerated ebpf.go are committed
-->

## Checklist

- [ ] `make lint` passes (gofmt, goimports, go vet, go mod tidy)
- [ ] `make test` passes
- [ ] CHANGELOG.md updated under `## [Unreleased]` for user-visible changes
- [ ] No real credentials, internal hostnames, or production captures in test fixtures
