FROM debian:bullseye AS builder
# Using Debian instead of the official Golang image because it’s based on newer OS versions
# with newer glibc, which causes compatibility issues.

# deb.debian.org publishes a bullseye-security index that can advertise .debs
# already pruned from the pool after a point release, so the build fails with a
# 404 on an exact version (seen 2026-09-05: git 1:2.30.2-1+deb11u5). It is a
# mirror-side inconsistency, so clearing local lists and retrying do not help —
# both were tried and both still failed on every attempt.
#
# snapshot.debian.org serves index and pool as a matched pair at a point in
# time, which makes this build reproducible and immune to archive rotation.
# Check-Valid-Until is disabled because a pinned snapshot's Release file is
# intentionally older than apt's freshness window.
#
# bullseye is oldstable and its archive keeps rotating; without this pin the
# failure recurs and blocks every build in the repo, releases included.
ARG DEBIAN_SNAPSHOT=20260801T000000Z
RUN set -eux; \
    printf '%s\n' \
      "deb http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bullseye main" \
      "deb http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bullseye-security main" \
      "deb http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bullseye-updates main" \
      > /etc/apt/sources.list; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=5 update; \
    apt-get install -y --no-install-recommends -o Acquire::Retries=5 \
        ca-certificates curl git build-essential pkg-config libsystemd-dev; \
    rm -rf /var/lib/apt/lists/*

ARG GO_VERSION=1.26.5
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz -o go.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && rm go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /tmp/src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
ARG VERSION=unknown
RUN CGO_ENABLED=1 go build -mod=readonly -ldflags "-extldflags='-Wl,-z,lazy' -X 'github.com/coroot/coroot-node-agent/flags.Version=${VERSION}'" -o nudgebee-node-agent .

FROM registry.access.redhat.com/ubi9/ubi-minimal AS runtime

ARG VERSION=unknown

# Patch the UBI9 base to the latest package set, then install SSL/TLS libraries
# for HTTPS LLM API tracing. microdnf update clears the fixable RedHat OS CVEs
# (gnutls, openssl-libs, glibc, krb5-libs, ...) the pinned ubi-minimal ships stale.
RUN microdnf update -y && \
    microdnf install -y openssl-libs && \
    microdnf clean all

COPY --from=builder /tmp/src/nudgebee-node-agent /usr/bin/nudgebee-node-agent

ENTRYPOINT ["/usr/bin/nudgebee-node-agent"]