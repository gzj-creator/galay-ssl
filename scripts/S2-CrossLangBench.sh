#!/bin/bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: S2-CrossLangBench.sh [options]

Local wrapper for the remote cross-language SSL benchmark.

Required:
  --remote-host HOST               Remote benchmark host
  --remote-user USER               Remote SSH user
  --remote-root PATH               Remote working root

Optional:
  --remote-password PASS           Remote SSH password
  --remote-kernel-source PATH      Remote galay-kernel source (default: /home/ubuntu/git/galay-kernel)
  --output-dir PATH                Local artifact output directory
  --server-cpus LIST               CPU set for benchmark servers (default: 0-1)
  --client-cpus LIST               CPU set for benchmark client (default: 2-3)
  --streaming-connections N        Streaming scenario connections (default: 64)
  --streaming-requests N           Streaming requests per connection (default: 500)
  --streaming-payload N            Streaming payload bytes (default: 256)
  --handshake-connections N        Handshake-heavy connections (default: 128)
  --handshake-requests N           Handshake-heavy requests per connection (default: 1)
  --handshake-payload N            Handshake-heavy payload bytes (default: 47)
  --galay-ssl-workers N            galay-ssl benchmark server workers (default: 1)
  --build-jobs N                   Remote build parallelism limit (default: 1)
  --threads N                      Benchmark client threads (default: 4)
  --connect-retries N              Benchmark client connect retries (default: 3)
  --backlog N                      Server listen backlog (default: 4096)
  --warmup-runs N                  Warmup runs per implementation (default: 1)
  --formal-runs N                  Formal runs per implementation (default: 5)
  --total-cpu-threshold N          Combined avg CPU threshold (default: 70)
  --side-cpu-threshold N           Per-side avg CPU threshold (default: 80)
  --bootstrap-toolchains           Install cargo and go on remote host if missing
  --skip-sync                      Skip rsync upload step
  --help                           Show this help
EOF
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

REMOTE_HOST=""
REMOTE_USER=""
REMOTE_PASSWORD="${REMOTE_PASSWORD:-}"
REMOTE_ROOT=""
REMOTE_KERNEL_SOURCE="/home/ubuntu/git/galay-kernel"
OUTPUT_DIR=""
SERVER_CPUS="0-1"
CLIENT_CPUS="2-3"
STREAMING_CONNECTIONS=64
STREAMING_REQUESTS=500
STREAMING_PAYLOAD=256
HANDSHAKE_CONNECTIONS=128
HANDSHAKE_REQUESTS=1
HANDSHAKE_PAYLOAD=47
GALAY_SSL_WORKERS=1
BUILD_JOBS=1
THREADS=4
CONNECT_RETRIES=3
BACKLOG=4096
WARMUP_RUNS=1
FORMAL_RUNS=5
TOTAL_CPU_THRESHOLD=70
SIDE_CPU_THRESHOLD=80
BOOTSTRAP_TOOLCHAINS=0
SKIP_SYNC=0

while [ $# -gt 0 ]; do
    case "$1" in
        --remote-host)
            REMOTE_HOST="$2"
            shift 2
            ;;
        --remote-user)
            REMOTE_USER="$2"
            shift 2
            ;;
        --remote-password)
            REMOTE_PASSWORD="$2"
            shift 2
            ;;
        --remote-root)
            REMOTE_ROOT="$2"
            shift 2
            ;;
        --remote-kernel-source)
            REMOTE_KERNEL_SOURCE="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --server-cpus)
            SERVER_CPUS="$2"
            shift 2
            ;;
        --client-cpus)
            CLIENT_CPUS="$2"
            shift 2
            ;;
        --streaming-connections)
            STREAMING_CONNECTIONS="$2"
            shift 2
            ;;
        --streaming-requests)
            STREAMING_REQUESTS="$2"
            shift 2
            ;;
        --streaming-payload)
            STREAMING_PAYLOAD="$2"
            shift 2
            ;;
        --handshake-connections)
            HANDSHAKE_CONNECTIONS="$2"
            shift 2
            ;;
        --handshake-requests)
            HANDSHAKE_REQUESTS="$2"
            shift 2
            ;;
        --handshake-payload)
            HANDSHAKE_PAYLOAD="$2"
            shift 2
            ;;
        --galay-ssl-workers)
            GALAY_SSL_WORKERS="$2"
            shift 2
            ;;
        --build-jobs)
            BUILD_JOBS="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --connect-retries)
            CONNECT_RETRIES="$2"
            shift 2
            ;;
        --backlog)
            BACKLOG="$2"
            shift 2
            ;;
        --warmup-runs)
            WARMUP_RUNS="$2"
            shift 2
            ;;
        --formal-runs)
            FORMAL_RUNS="$2"
            shift 2
            ;;
        --total-cpu-threshold)
            TOTAL_CPU_THRESHOLD="$2"
            shift 2
            ;;
        --side-cpu-threshold)
            SIDE_CPU_THRESHOLD="$2"
            shift 2
            ;;
        --bootstrap-toolchains)
            BOOTSTRAP_TOOLCHAINS=1
            shift
            ;;
        --skip-sync)
            SKIP_SYNC=1
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ -z "$REMOTE_HOST" ] || [ -z "$REMOTE_USER" ] || [ -z "$REMOTE_ROOT" ]; then
    usage >&2
    exit 1
fi

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$PROJECT_DIR/.crosslang-bench-results/$(date +%Y%m%d-%H%M%S)"
fi

mkdir -p "$OUTPUT_DIR"

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing required command: $cmd" >&2
        exit 1
    fi
}

require_cmd expect
require_cmd rsync
require_cmd ssh

run_with_expect() {
    local command_text="$1"
    if [ -n "$REMOTE_PASSWORD" ]; then
        EXPECT_COMMAND="$command_text" REMOTE_PASSWORD="$REMOTE_PASSWORD" expect <<'EOF'
set timeout -1
set password $env(REMOTE_PASSWORD)
set command_text $env(EXPECT_COMMAND)
spawn bash -lc $command_text
expect {
    -re "yes/no" {
        send "yes\r"
        exp_continue
    }
    -re "(?i)(password|passphrase).*:" {
        send "$password\r"
        exp_continue
    }
    eof
}
catch wait result
set status [lindex $result 3]
exit $status
EOF
    else
        bash -lc "$command_text"
    fi
}

run_remote() {
    local remote_command="$1"
    local ssh_cmd
    ssh_cmd="ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${REMOTE_HOST} $(printf '%q' "$remote_command")"
    run_with_expect "$ssh_cmd"
}

sync_repo() {
    local remote_src="${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_ROOT}/src/"
    local rsync_cmd
    rsync_cmd=$(
        cat <<EOF
rsync -az --delete \
  --exclude '.git/' \
  --exclude '.worktrees/' \
  --exclude 'build*/' \
  --exclude '.crosslang-bench-results/' \
  --exclude '.crosslang-bench-remote/' \
  --exclude '.verify-install-*/' \
  --exclude 'benchmark/rust-tokio-rustls-server/target/' \
  --exclude 'benchmark/go-crypto-tls-server/go-crypto-tls-server' \
  -e "ssh -o StrictHostKeyChecking=no" \
  $(printf '%q' "$PROJECT_DIR/") $(printf '%q' "$remote_src")
EOF
    )
    run_with_expect "$rsync_cmd"
}

check_or_bootstrap_toolchains() {
    local probe_cmd
    probe_cmd="command -v cargo >/dev/null 2>&1 && command -v go >/dev/null 2>&1"
    if run_remote "$probe_cmd"; then
        return 0
    fi

    if [ "$BOOTSTRAP_TOOLCHAINS" -ne 1 ]; then
        echo "remote cargo/go missing; rerun with --bootstrap-toolchains or install them manually" >&2
        exit 1
    fi

    run_remote "sudo -S DEBIAN_FRONTEND=noninteractive apt-get update && sudo -S DEBIAN_FRONTEND=noninteractive apt-get install -y cargo golang-go"
}

run_benchmark() {
    local remote_output
    local remote_command
    local artifact_dir
    local raw_csv
    local summary_csv
    local sync_back_cmd

    remote_command=$(
        cat <<EOF
mkdir -p $(printf '%q' "$REMOTE_ROOT") && \
cd $(printf '%q' "$REMOTE_ROOT/src") && \
bash scripts/S2-CrossLangBench.remote.sh \
  --source-root $(printf '%q' "$REMOTE_ROOT/src") \
  --remote-kernel-source $(printf '%q' "$REMOTE_KERNEL_SOURCE") \
  --work-root $(printf '%q' "$REMOTE_ROOT/work") \
  --server-cpus $(printf '%q' "$SERVER_CPUS") \
  --client-cpus $(printf '%q' "$CLIENT_CPUS") \
  --streaming-connections $(printf '%q' "$STREAMING_CONNECTIONS") \
  --streaming-requests $(printf '%q' "$STREAMING_REQUESTS") \
  --streaming-payload $(printf '%q' "$STREAMING_PAYLOAD") \
  --handshake-connections $(printf '%q' "$HANDSHAKE_CONNECTIONS") \
  --handshake-requests $(printf '%q' "$HANDSHAKE_REQUESTS") \
  --handshake-payload $(printf '%q' "$HANDSHAKE_PAYLOAD") \
  --galay-ssl-workers $(printf '%q' "$GALAY_SSL_WORKERS") \
  --build-jobs $(printf '%q' "$BUILD_JOBS") \
  --threads $(printf '%q' "$THREADS") \
  --connect-retries $(printf '%q' "$CONNECT_RETRIES") \
  --backlog $(printf '%q' "$BACKLOG") \
  --warmup-runs $(printf '%q' "$WARMUP_RUNS") \
  --formal-runs $(printf '%q' "$FORMAL_RUNS") \
  --total-cpu-threshold $(printf '%q' "$TOTAL_CPU_THRESHOLD") \
  --side-cpu-threshold $(printf '%q' "$SIDE_CPU_THRESHOLD")
EOF
    )

    remote_output="$(run_remote "$remote_command")"
    remote_output="$(printf '%s\n' "$remote_output" | tr -d '\r')"
    printf '%s\n' "$remote_output" | tee "$OUTPUT_DIR/remote-run.log"

    artifact_dir="$(printf '%s\n' "$remote_output" | awk -F= '/^ARTIFACT_DIR=/{print $2}' | tail -n1)"
    raw_csv="$(printf '%s\n' "$remote_output" | awk -F= '/^RAW_CSV=/{print $2}' | tail -n1)"
    summary_csv="$(printf '%s\n' "$remote_output" | awk -F= '/^SUMMARY_CSV=/{print $2}' | tail -n1)"

    if [ -z "$artifact_dir" ] || [ -z "$summary_csv" ]; then
        echo "failed to parse remote artifact paths" >&2
        exit 1
    fi

    sync_back_cmd=$(
        cat <<EOF
rsync -az -e "ssh -o StrictHostKeyChecking=no" \
  $(printf '%q' "${REMOTE_USER}@${REMOTE_HOST}:${artifact_dir}/") \
  $(printf '%q' "$OUTPUT_DIR/")
EOF
    )
    run_with_expect "$sync_back_cmd"

    printf '%s\n' "$raw_csv" >"$OUTPUT_DIR/remote-raw-csv-path.txt"
    printf '%s\n' "$summary_csv" >"$OUTPUT_DIR/remote-summary-csv-path.txt"
}

run_remote "mkdir -p $(printf '%q' "$REMOTE_ROOT") $(printf '%q' "$REMOTE_ROOT/src")"

if [ "$SKIP_SYNC" -ne 1 ]; then
    sync_repo
fi

check_or_bootstrap_toolchains
run_benchmark

echo "local_output_dir=$OUTPUT_DIR"
