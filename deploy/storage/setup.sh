#!/bin/sh
# Generates credentials on first run (kept in .env), starts the stack, and
# prints what to configure on the agents and on whatever queries the data.
set -e
cd "$(dirname "$0")"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "docker compose v2 is required" >&2; exit 1; }

rand() { head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32; }

if [ ! -f .env ]; then
    VM_USER=nudgebee
    VM_PASSWORD=$(rand)
    umask 077
    cat > .env <<ENV
API_KEY=$(rand)
VM_USER=${VM_USER}
VM_PASSWORD=${VM_PASSWORD}
VM_BASIC_AUTH=$(printf '%s:%s' "${VM_USER}" "${VM_PASSWORD}" | base64 | tr -d '\n')
CLICKHOUSE_PASSWORD=$(rand)
METRICS_RETENTION=15d
TRACES_RETENTION=168h
ENV
    echo "Generated credentials in $(pwd)/.env"
fi

docker compose up -d

. ./.env
HOST=${STORAGE_HOST:-$(hostname -I 2>/dev/null | cut -d' ' -f1)}
cat <<INFO

Storage is running on ${HOST}.

Install the agent on each host (allow TCP 8080 from the hosts to ${HOST}):

  curl -fsSL https://raw.githubusercontent.com/nudgebee/node-agent/main/install.sh | sudo \\
    METRICS_ENDPOINT=http://${HOST}:8080/v1/metrics \\
    TRACES_ENDPOINT=http://${HOST}:8080/v1/traces \\
    LOGS_ENDPOINT=http://${HOST}:8080/v1/logs \\
    API_KEY=${API_KEY} sh -

Query endpoints (allow only from the machine that queries them):

  Prometheus (PromQL): http://${HOST}:8428  user ${VM_USER}, password in .env (VM_PASSWORD)
  ClickHouse (SQL):    http://${HOST}:8123  user default, password in .env (CLICKHOUSE_PASSWORD)
INFO
