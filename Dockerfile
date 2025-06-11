FROM golang:1.23.10-bullseye AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends libsystemd-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
ARG VERSION=unknown
RUN CGO_ENABLED=1 go build -mod=readonly -ldflags "-extldflags='-Wl,-z,lazy' -X 'github.com/coroot/coroot-node-agent/flags.Version=${VERSION}'" -o coroot-node-agent .

FROM registry.access.redhat.com/ubi9/ubi-minimal AS runtime

ARG VERSION=unknown

COPY --from=builder /tmp/src/coroot-node-agent /usr/bin/coroot-node-agent

ENTRYPOINT ["coroot-node-agent"]