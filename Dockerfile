FROM debian:bullseye AS builder
# Using Debian instead of the official Golang image because it’s based on newer OS versions
# with newer glibc, which causes compatibility issues.

# The base image ships a package index that can reference .debs the mirror has
# already pruned after a point release, which fails the build with a 404 on a
# specific version (seen 2026-09-04: libperl5.32 5.32.1-4+deb11u5). Dropping the
# cached lists forces a genuinely fresh index rather than a conditional-GET that
# may be answered from CDN cache, and Acquire::Retries rides out single-node
# staleness. bullseye is oldstable, so this will recur as the archive rotates.
RUN rm -rf /var/lib/apt/lists/* \
    && apt-get update -o Acquire::Retries=5 \
    && apt-get install -y --no-install-recommends -o Acquire::Retries=5 \
        curl git build-essential pkg-config libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*

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