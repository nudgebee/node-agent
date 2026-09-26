#!/bin/sh
set -e

GITHUB_URL="https://github.com/nudgebee/node-agent/releases"
DOWNLOADER=
SUDO=sudo
if [ $(id -u) -eq 0 ]; then
    SUDO=
fi

BIN_DIR=/usr/bin
SYSTEMD_DIR=/etc/systemd/system
VERSION="latest"
LOCAL_BINARY=
SYSTEM_NAME=nudgebee-node-agent
SYSTEMD_SERVICE=${SYSTEM_NAME}.service
UNINSTALL_SH=${BIN_DIR}/${SYSTEM_NAME}-uninstall.sh
FILE_SERVICE=${SYSTEMD_DIR}/${SYSTEMD_SERVICE}
FILE_ENV=${SYSTEMD_DIR}/${SYSTEMD_SERVICE}.env
STATE_DIR=/var/lib/${SYSTEM_NAME}
# Every environment variable the agent reads. Only these are copied from the
# installer's environment into the env file. flags/install_env_test.go fails
# when an agent flag is missing here.
ENV_VARS="^(ACCOUNT_ID|AGGREGATE_EPHEMERAL_WORKLOADS|API_KEY|AVAILABILITY_ZONE|CGROUPFS_ROOT|COLLAPSE_INTERNAL_DESTINATIONS|COLLECTOR_ENDPOINT|CONTAINER_ALLOWLIST|CONTAINER_DENYLIST|DISABLE_GPU_MONITORING|DISABLE_KUBE_PROBE|DISABLE_L7_TRACING|DISABLE_LOG_PARSING|DISABLE_PINGER|DISABLE_SENSITIVE_LOG_PARSING|ENABLE_DOTNET_TRACING|ENABLE_DYNAMIC_LOG_TAILING|ENABLE_NODEJS_TRACING|EPHEMERAL_PORT_RANGE|EXCLUDE_HTTP_REQUESTS_BY_PATH|HTTP_PATH_NORMALIZATION_RULES|IGNORE_CONTROL_PLANE|INSECURE_SKIP_VERIFY|INSTANCE_LIFE_CYCLE|INSTANCE_TYPE|LISTEN|LOG_BURST|LOG_PATTERNS_PER_CONTAINER|LOG_PER_SECOND|LOGS_ENDPOINT|MAX_LABEL_LENGTH|MAX_SPOOL_SIZE|METRICS_ENDPOINT|PROFILES_ENDPOINT|PROVIDER|REGION|RESOLVE_DNS|SANITIZE_HEADERS|SCRAPE_INTERVAL|SENSITIVE_HEADERS|SENSITIVE_LOG_MAX_DETECTIONS_PER_CONTAINER|SENSITIVE_LOG_MIN_CONFIDENCE|SENSITIVE_LOG_SAMPLE_RATE|SKIP_SYSTEMD_SYSTEM_SERVICES|TRACE_ID_HEADERS|TRACES_ENDPOINT|TRACES_SAMPLING|TRACK_PUBLIC_NETWORK|WAL_DIR|GOMEMLIMIT|KLOG_V)="
# Resource limits for the unit, read at install time. Defaults match the limits
# of the Kubernetes DaemonSet. The agent sets GOMEMLIMIT from the memory limit,
# so without one its heap is unbounded.
DEFAULT_MEMORY_MAX=1G
DEFAULT_CPU_QUOTA=100%

info()
{
    echo '[INFO] ' "$@"
}

fatal()
{
    echo '[ERROR] ' "$@" >&2
    show_help
    exit 1
}

show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help                        Show this help message and exit"
    echo "  -v v1.22.2, --version v1.22.2     Specify the version to install (default: latest)"
    echo "  -b PATH, --binary PATH            Install this binary instead of downloading one,"
    echo "                                    for hosts without access to GitHub"
    echo
    echo "Agent settings are read from the environment, e.g. COLLECTOR_ENDPOINT, API_KEY,"
    echo "TRACES_SAMPLING. They are kept across re-runs; set a variable again to change it."
    echo "MEMORY_MAX (default ${DEFAULT_MEMORY_MAX}) and CPU_QUOTA (default ${DEFAULT_CPU_QUOTA}) limit the systemd unit,"
    echo "and are kept across re-runs in the same way."
}

verify_system() {
    if [ -x /bin/systemctl ] || type systemctl > /dev/null 2>&1; then
        return
    fi
    fatal 'Cannot find systemd'
}

verify_executable() {
    if [ ! -x ${BIN_DIR}/${SYSTEM_NAME} ]; then
        fatal "Executable ${SYSTEM_NAME} binary not found at ${BIN_DIR}/${SYSTEM_NAME}"
    fi
}

verify_arch() {
    if [ -z "$ARCH" ]; then
        ARCH=$(uname -m)
    fi
    case $ARCH in
        amd64)
            ARCH=amd64
            ;;
        x86_64)
            ARCH=amd64
            ;;
        arm64)
            ARCH=arm64
            ;;
        aarch64)
            ARCH=arm64
            ;;
        *)
            fatal "Unsupported architecture $ARCH"
    esac
}

verify_downloader() {
    [ -x "$(command -v $1)" ] || return 1
    DOWNLOADER=$1
    return 0
}

setup_tmp() {
    TMP_DIR=$(mktemp -d -t ${SYSTEM_NAME}-install.XXXXXXXXXX)
    TMP_BIN=${TMP_DIR}/${SYSTEM_NAME}
    cleanup() {
        code=$?
        set +e
        trap - EXIT
        rm -rf ${TMP_DIR}
        exit $code
    }
    trap cleanup INT EXIT
}

get_release_version() {
    if [ "$VERSION" = "latest" ]; then
        info "Finding the latest release"
        latest_release_url=${GITHUB_URL}/latest
        case $DOWNLOADER in
            curl)
                VERSION=$(curl -w '%{url_effective}' -L -s -S ${latest_release_url} -o /dev/null | sed -e 's|.*/||')
                ;;
            wget)
                VERSION=$(wget -SqO /dev/null ${latest_release_url} 2>&1 | grep -i Location | sed -e 's|.*/||')
                ;;
            *)
                fatal "Incorrect downloader executable '$DOWNLOADER'"
                ;;
        esac
        info "The latest release is ${VERSION}"
    else
        info "Using specified version ${VERSION}"
    fi
}

download_binary() {
    info "Downloading binary"
    # Release artifacts are named <binary>-<semver>-<arch>, where <semver>
    # is the tag without the leading "v". Strip "v" if present.
    VERSION_NO_V="${VERSION#v}"
    URL="${GITHUB_URL}/download/${VERSION}/${SYSTEM_NAME}-${VERSION_NO_V}-${ARCH}"
    set +e
    case $DOWNLOADER in
        curl)
            curl -o ${TMP_BIN} -sfL ${URL}
            ;;
        wget)
            wget -qO ${TMP_BIN} ${URL}
            ;;
        *)
            fatal "Incorrect executable '$DOWNLOADER'"
            ;;
    esac

    [ $? -eq 0 ] || fatal 'Download failed'
    set -e
}

setup_binary() {
    chmod 755 ${TMP_BIN}
    info "Installing ${SYSTEM_NAME} to ${BIN_DIR}/${SYSTEM_NAME}"
    $SUDO chown root:root ${TMP_BIN}
    $SUDO mv -f ${TMP_BIN} ${BIN_DIR}/${SYSTEM_NAME}
}

download() {
    if [ -n "${LOCAL_BINARY}" ]; then
        [ -f "${LOCAL_BINARY}" ] || fatal "Binary not found: ${LOCAL_BINARY}"
        setup_tmp
        info "Using local binary ${LOCAL_BINARY}"
        cp "${LOCAL_BINARY}" ${TMP_BIN}
        setup_binary
        return
    fi
    verify_arch
    verify_downloader curl || verify_downloader wget || fatal 'Can not find curl or wget for downloading files'
    setup_tmp
    get_release_version
    download_binary
    setup_binary
}

create_uninstall() {
    info "Creating uninstall script ${UNINSTALL_SH}"
    $SUDO tee ${UNINSTALL_SH} >/dev/null << EOF
#!/bin/sh
set -x
[ \$(id -u) -eq 0 ] || exec sudo \$0 \$@

systemctl stop ${SYSTEM_NAME}
systemctl disable ${SYSTEM_NAME}
systemctl reset-failed ${SYSTEM_NAME}
# Also disable the legacy upstream unit if it's still installed; ignore failures
# so this script also works on hosts that never ran coroot-node-agent.
systemctl stop coroot-node-agent 2>/dev/null || true
systemctl disable coroot-node-agent 2>/dev/null || true
systemctl reset-failed coroot-node-agent 2>/dev/null || true
systemctl daemon-reload

rm -f ${FILE_SERVICE}
rm -f ${FILE_ENV}
rm -f ${SYSTEMD_DIR}/coroot-node-agent.service
rm -f ${SYSTEMD_DIR}/coroot-node-agent.service.env

remove_uninstall() {
    rm -f ${UNINSTALL_SH}
}
trap remove_uninstall EXIT

rm -rf /var/lib/${SYSTEM_NAME} /var/lib/coroot-node-agent || true
rm -f ${BIN_DIR}/${SYSTEM_NAME} ${BIN_DIR}/coroot-node-agent
EOF
    $SUDO chmod 755 ${UNINSTALL_SH}
    $SUDO chown root:root ${UNINSTALL_SH}
}

systemd_disable() {
    $SUDO systemctl disable ${SYSTEM_NAME} >/dev/null 2>&1 || true
    $SUDO rm -f ${FILE_SERVICE} || true
    $SUDO rm -f ${FILE_ENV} || true
}

# Settings from a previous install, read before systemd_disable removes the
# file. Without this, upgrading by re-running the installer with no variables
# set would wipe API_KEY and the endpoints.
read_existing_env() {
    EXISTING_ENV=$($SUDO cat ${FILE_ENV} 2>/dev/null || true)
    # Resource limits: set now > previous install > default.
    if [ -z "${MEMORY_MAX}" ]; then
        MEMORY_MAX=$(sed -n 's/^MemoryMax=//p' ${FILE_SERVICE} 2>/dev/null | head -n 1 || true)
    fi
    if [ -z "${CPU_QUOTA}" ]; then
        CPU_QUOTA=$(sed -n 's/^CPUQuota=//p' ${FILE_SERVICE} 2>/dev/null | head -n 1 || true)
    fi
    MEMORY_MAX=${MEMORY_MAX:-${DEFAULT_MEMORY_MAX}}
    CPU_QUOTA=${CPU_QUOTA:-${DEFAULT_CPU_QUOTA}}
}

create_env_file() {
    info "env: Creating environment file ${FILE_ENV}"
    # Double-quote each value, escaping \ and ", which systemd's EnvironmentFile
    # parser unescapes back. Regex settings such as HTTP_PATH_NORMALIZATION_RULES
    # contain backslashes that an unquoted value, or "read" without -r, loses.
    NEW_ENV=$(env | grep -E "${ENV_VARS}" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/=/="/' -e 's/$/"/' || true)
    $SUDO touch ${FILE_ENV}
    $SUDO chmod 0600 ${FILE_ENV}
    # Variables set now win; the rest are carried over from the previous install.
    { printf '%s\n' "${NEW_ENV}"; printf '%s\n' "${EXISTING_ENV}"; } | awk -F= 'NF && !seen[$1]++' | $SUDO tee ${FILE_ENV} >/dev/null
}

create_systemd_service_file() {
    info "systemd: Creating service file ${FILE_SERVICE}"
    $SUDO tee ${FILE_SERVICE} >/dev/null << EOF
[Unit]
Description=Nudgebee node agent
Documentation=https://github.com/nudgebee/node-agent
Wants=network-online.target
After=network-online.target

[Install]
WantedBy=multi-user.target

[Service]
Type=exec
# Defaults for standalone hosts; the env files below override them.
# /tmp is cleared on reboot on some distros, which would drop unsent metrics.
Environment=WAL_DIR=${STATE_DIR}
# Hosts outside Kubernetes run many chatty local services; sample traces
# instead of exporting every request.
Environment=TRACES_SAMPLING=0.1
StateDirectory=${SYSTEM_NAME}
MemoryMax=${MEMORY_MAX}
CPUQuota=${CPU_QUOTA}
EnvironmentFile=-/etc/default/%N
EnvironmentFile=-/etc/sysconfig/%N
EnvironmentFile=-${FILE_ENV}
KillMode=process
Delegate=yes
# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStart=${BIN_DIR}/${SYSTEM_NAME}
EOF
}

create_service_file() {
    create_systemd_service_file
    return 0
}

get_installed_hashes() {
    $SUDO sha256sum ${BIN_DIR}/${SYSTEM_NAME} ${FILE_SERVICE} ${FILE_ENV} 2>&1 || true
}

systemd_enable() {
    info "systemd: Enabling ${SYSTEM_NAME} unit"
    $SUDO systemctl enable ${FILE_SERVICE} >/dev/null
    $SUDO systemctl daemon-reload >/dev/null
}

systemd_start() {
    info "systemd: Starting ${SYSTEM_NAME}"
    $SUDO systemctl restart ${SYSTEM_NAME}
}

service_enable_and_start() {
    systemd_enable

    POST_INSTALL_HASHES=$(get_installed_hashes)
    if [ "${PRE_INSTALL_HASHES}" = "${POST_INSTALL_HASHES}" ]; then
        info 'No change detected so skipping service start'
        return
    fi

    systemd_start

    return 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -b|--binary)
            LOCAL_BINARY="$2"
            shift 2
            ;;
        *)
            fatal "Unknown option: $1"
            ;;
    esac
done

{
    verify_system
    PRE_INSTALL_HASHES=$(get_installed_hashes)
    read_existing_env
    download
    create_uninstall
    systemd_disable
    create_env_file
    create_service_file
    service_enable_and_start
}
