#!/bin/bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: S2-CrossLangBench.remote.sh [options]

Remote runner for controlled galay-ssl / tokio-rustls / crypto-tls benchmark comparisons.

Options:
  --source-root PATH               Synced galay-ssl source root on remote host
  --remote-kernel-source PATH      galay-kernel source root on remote host
  --work-root PATH                 Working directory for builds and artifacts
  --artifact-dir PATH              Override artifact output directory
  --server-cpus LIST               CPU set for benchmark servers (default: 0-1)
  --client-cpus LIST               CPU set for benchmark client (default: 2-3)
  --streaming-connections N        Streaming scenario connections (default: 64)
  --streaming-requests N           Streaming requests per connection (default: 500)
  --streaming-payload N            Streaming payload bytes (default: 256)
  --handshake-connections N        Handshake-heavy scenario connections (default: 128)
  --handshake-requests N           Handshake-heavy requests per connection (default: 1)
  --handshake-payload N            Handshake-heavy payload bytes (default: 47)
  --galay-ssl-workers N            galay-ssl benchmark server workers (default: 1)
  --build-jobs N                   Build parallelism limit for CMake/Cargo/Go (default: 1)
  --threads N                      Benchmark client threads (default: 4)
  --connect-retries N              Benchmark client connect retries (default: 3)
  --backlog N                      Server listen backlog (default: 4096)
  --warmup-runs N                  Warmup runs per implementation (default: 1)
  --formal-runs N                  Formal runs per implementation (default: 5)
  --total-cpu-threshold N          Combined avg CPU threshold in percent of host capacity (default: 70)
  --side-cpu-threshold N           Avg CPU threshold in percent of pinned cores per side (default: 80)
  --help                           Show this help
EOF
}

SOURCE_ROOT=""
REMOTE_KERNEL_SOURCE="/home/ubuntu/git/galay-kernel"
WORK_ROOT=""
ARTIFACT_DIR=""
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

while [ $# -gt 0 ]; do
    case "$1" in
        --source-root)
            SOURCE_ROOT="$2"
            shift 2
            ;;
        --remote-kernel-source)
            REMOTE_KERNEL_SOURCE="$2"
            shift 2
            ;;
        --work-root)
            WORK_ROOT="$2"
            shift 2
            ;;
        --artifact-dir)
            ARTIFACT_DIR="$2"
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

if [ -z "$SOURCE_ROOT" ]; then
    SOURCE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi

if [ -z "$WORK_ROOT" ]; then
    WORK_ROOT="$SOURCE_ROOT/.crosslang-bench-remote"
fi

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
if [ -z "$ARTIFACT_DIR" ]; then
    ARTIFACT_DIR="$WORK_ROOT/artifacts/$TIMESTAMP"
fi

BUILD_ROOT="$WORK_ROOT/build"
INSTALL_ROOT="$WORK_ROOT/install"
KERNEL_INSTALL_PREFIX="$INSTALL_ROOT/galay-kernel"
GALAY_SSL_BUILD_DIR="$BUILD_ROOT/galay-ssl"
KERNEL_BUILD_DIR="$BUILD_ROOT/galay-kernel"
RAW_CSV="$ARTIFACT_DIR/raw-results.csv"
SUMMARY_CSV="$ARTIFACT_DIR/summary.csv"
PORT=9443

mkdir -p "$BUILD_ROOT" "$INSTALL_ROOT" "$ARTIFACT_DIR"

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing required command: $cmd" >&2
        exit 1
    fi
}

require_cmd awk
require_cmd cmake
require_cmd g++
require_cmd python3
require_cmd taskset
require_cmd cargo
require_cmd go

cpu_list_size() {
    python3 - "$1" <<'PY'
import sys

spec = sys.argv[1]
count = 0
for part in spec.split(','):
    part = part.strip()
    if not part:
        continue
    if '-' in part:
        left, right = part.split('-', 1)
        count += int(right) - int(left) + 1
    else:
        count += 1
print(count)
PY
}

wait_for_port() {
    python3 - "$1" "$2" "$3" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3])
deadline = time.time() + timeout

while time.time() < deadline:
    sock = socket.socket()
    sock.settimeout(0.5)
    try:
        sock.connect((host, port))
    except OSError:
        time.sleep(0.1)
    else:
        sock.close()
        sys.exit(0)
    finally:
        try:
            sock.close()
        except OSError:
            pass

sys.exit(1)
PY
}

monitor_process() {
    local pid="$1"
    local outfile="$2"
    : >"$outfile"
    while kill -0 "$pid" 2>/dev/null; do
        ps -p "$pid" -o %cpu=,rss= | awk -v ts="$(date +%s)" 'NF == 2 { printf "%s,%s,%s\n", ts, $1, $2 }' >>"$outfile" || true
        sleep 1
    done
}

summarize_monitor() {
    local file="$1"
    awk -F, '
        NF >= 3 {
            cpu += $2
            if ($3 > rss_max) rss_max = $3
            count += 1
        }
        END {
            if (count == 0) {
                printf "0,0"
            } else {
                printf "%.2f,%d", cpu / count, rss_max
            }
        }
    ' "$file"
}

median_from_stdin() {
    awk '
        { values[NR] = $1 }
        END {
            if (NR == 0) {
                print 0
                exit
            }
            if (NR % 2 == 1) {
                print values[(NR + 1) / 2]
            } else {
                printf "%.4f\n", (values[NR / 2] + values[(NR / 2) + 1]) / 2
            }
        }
    '
}

value_gt() {
    awk -v left="$1" -v right="$2" 'BEGIN { exit !(left > right) }'
}

parse_metric() {
    local file="$1"
    local key="$2"
    local value
    value="$(awk -F': ' -v key="$key" '$1 == key { print $2; exit }' "$file")"
    if [ -z "$value" ]; then
        echo 0
    else
        echo "$value"
    fi
}

server_cmd_for_impl() {
    local impl="$1"
    local port="$2"
    case "$impl" in
        galay_ssl)
            SERVER_CMD=("$GALAY_SSL_BUILD_DIR/bin/B1-SslBenchServer" "$port" "$SOURCE_ROOT/certs/server.crt" "$SOURCE_ROOT/certs/server.key" "$BACKLOG" "$GALAY_SSL_WORKERS")
            ;;
        rust)
            SERVER_CMD=("$SOURCE_ROOT/benchmark/rust-tokio-rustls-server/target/release/rust-tokio-rustls-server" "$port" "$SOURCE_ROOT/certs/server.crt" "$SOURCE_ROOT/certs/server.key" "$BACKLOG")
            ;;
        go)
            SERVER_CMD=("$SOURCE_ROOT/benchmark/go-crypto-tls-server/go-crypto-tls-server" "$port" "$SOURCE_ROOT/certs/server.crt" "$SOURCE_ROOT/certs/server.key" "$BACKLOG")
            ;;
        *)
            echo "unknown implementation: $impl" >&2
            exit 1
            ;;
    esac
}

build_kernel() {
    cmake -S "$REMOTE_KERNEL_SOURCE" -B "$KERNEL_BUILD_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTS=OFF \
        -DBUILD_BENCHMARKS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DCMAKE_INSTALL_PREFIX="$KERNEL_INSTALL_PREFIX"
    cmake --build "$KERNEL_BUILD_DIR" --parallel "$BUILD_JOBS"
    cmake --install "$KERNEL_BUILD_DIR"
}

build_galay_ssl_bench() {
    cmake -S "$SOURCE_ROOT" -B "$GALAY_SSL_BUILD_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_LTO=ON \
        -DBUILD_TESTS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_BENCHMARKS=ON \
        -DDISABLE_IOURING=ON \
        -DCMAKE_PREFIX_PATH="$KERNEL_INSTALL_PREFIX"
    cmake --build "$GALAY_SSL_BUILD_DIR" --target B1-SslBenchServer B1-SslBenchClient --parallel "$BUILD_JOBS"
}

build_rust_server() {
    local manifest_path="$SOURCE_ROOT/benchmark/rust-tokio-rustls-server/Cargo.toml"
    local lock_path="$SOURCE_ROOT/benchmark/rust-tokio-rustls-server/Cargo.lock"

    if [ -f "$lock_path" ] && ! cargo metadata --manifest-path "$manifest_path" --format-version 1 --locked >/dev/null 2>&1; then
        echo "rust cargo too old for committed lockfile; regenerating lockfile locally on remote host" >&2
        rm -f "$lock_path"
    fi

    CARGO_BUILD_JOBS="$BUILD_JOBS" cargo build \
        --manifest-path "$manifest_path" \
        --release \
        -j "$BUILD_JOBS"
}

build_go_server() {
    (
        cd "$SOURCE_ROOT/benchmark/go-crypto-tls-server" && \
        GOTOOLCHAIN=local GOMAXPROCS="$BUILD_JOBS" GOFLAGS="-p=$BUILD_JOBS" go test ./... && \
        GOTOOLCHAIN=local GOMAXPROCS="$BUILD_JOBS" GOFLAGS="-p=$BUILD_JOBS" go build -o go-crypto-tls-server ./...
    )
}

TOTAL_CPUS="$(nproc)"
SERVER_CPU_SLOTS="$(cpu_list_size "$SERVER_CPUS")"
CLIENT_CPU_SLOTS="$(cpu_list_size "$CLIENT_CPUS")"
TOTAL_CPU_LIMIT="$((TOTAL_CPUS * TOTAL_CPU_THRESHOLD))"
SERVER_CPU_LIMIT="$((SERVER_CPU_SLOTS * SIDE_CPU_THRESHOLD))"
CLIENT_CPU_LIMIT="$((CLIENT_CPU_SLOTS * SIDE_CPU_THRESHOLD))"

echo "timestamp,scenario,implementation,phase,run_index,connections,requests_per_conn,payload_bytes,threads,connect_retries,total_requests,total_errors,duration_ms,qps,throughput_mb_s,server_cpu_avg,server_rss_kb,client_cpu_avg,client_rss_kb,combined_cpu_avg,client_status,server_log,client_log" >"$RAW_CSV"

LAST_ERRORS=0
LAST_OVER_THRESHOLD=0
LAST_CONNECTIONS=0
LAST_REQUESTS=0
LAST_PAYLOAD=0

run_one() {
    local phase="$1"
    local impl="$2"
    local scenario="$3"
    local run_index="$4"
    local connections="$5"
    local requests="$6"
    local payload="$7"
    local run_dir="$ARTIFACT_DIR/$scenario/$impl/$phase-$run_index"
    local server_log="$run_dir/server.log"
    local client_log="$run_dir/client.log"
    local server_mon="$run_dir/server-monitor.csv"
    local client_mon="$run_dir/client-monitor.csv"
    local server_pid=""
    local server_mon_pid=""
    local client_pid=""
    local client_mon_pid=""
    local client_status=0

    mkdir -p "$run_dir"
    server_cmd_for_impl "$impl" "$PORT"

    taskset -c "$SERVER_CPUS" "${SERVER_CMD[@]}" >"$server_log" 2>&1 &
    server_pid="$!"
    monitor_process "$server_pid" "$server_mon" &
    server_mon_pid="$!"

    if ! wait_for_port 127.0.0.1 "$PORT" 10; then
        echo "server failed to listen for $impl $scenario" >&2
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        wait "$server_mon_pid" 2>/dev/null || true
        exit 1
    fi

    taskset -c "$CLIENT_CPUS" \
        "$GALAY_SSL_BUILD_DIR/bin/B1-SslBenchClient" 127.0.0.1 "$PORT" \
        "$connections" "$requests" "$payload" "$THREADS" "$CONNECT_RETRIES" \
        >"$client_log" 2>&1 &
    client_pid="$!"
    monitor_process "$client_pid" "$client_mon" &
    client_mon_pid="$!"

    set +e
    wait "$client_pid"
    client_status="$?"
    set -e

    wait "$client_mon_pid" 2>/dev/null || true
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    wait "$server_mon_pid" 2>/dev/null || true

    local server_stats
    local client_stats
    local server_cpu_avg
    local server_rss_kb
    local client_cpu_avg
    local client_rss_kb
    local total_requests
    local total_errors
    local duration_ms
    local qps
    local throughput_mb_s
    local combined_cpu_avg

    server_stats="$(summarize_monitor "$server_mon")"
    client_stats="$(summarize_monitor "$client_mon")"
    server_cpu_avg="${server_stats%%,*}"
    server_rss_kb="${server_stats##*,}"
    client_cpu_avg="${client_stats%%,*}"
    client_rss_kb="${client_stats##*,}"
    total_requests="$(parse_metric "$client_log" "Total requests")"
    total_errors="$(parse_metric "$client_log" "Total errors")"
    duration_ms="$(parse_metric "$client_log" "Duration")"
    duration_ms="${duration_ms% ms}"
    qps="$(parse_metric "$client_log" "Requests/sec")"
    throughput_mb_s="$(parse_metric "$client_log" "Throughput")"
    throughput_mb_s="${throughput_mb_s% MB/s}"
    combined_cpu_avg="$(awk -v server="$server_cpu_avg" -v client="$client_cpu_avg" 'BEGIN { printf "%.2f", server + client }')"

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(date +%FT%T)" "$scenario" "$impl" "$phase" "$run_index" \
        "$connections" "$requests" "$payload" "$THREADS" "$CONNECT_RETRIES" \
        "$total_requests" "$total_errors" "$duration_ms" "$qps" "$throughput_mb_s" \
        "$server_cpu_avg" "$server_rss_kb" "$client_cpu_avg" "$client_rss_kb" "$combined_cpu_avg" \
        "$client_status" "$server_log" "$client_log" >>"$RAW_CSV"

    LAST_ERRORS="$total_errors"
    LAST_OVER_THRESHOLD=0
    LAST_CONNECTIONS="$connections"
    LAST_REQUESTS="$requests"
    LAST_PAYLOAD="$payload"

    if value_gt "$combined_cpu_avg" "$TOTAL_CPU_LIMIT"; then
        LAST_OVER_THRESHOLD=1
    fi
    if value_gt "$server_cpu_avg" "$SERVER_CPU_LIMIT"; then
        LAST_OVER_THRESHOLD=1
    fi
    if value_gt "$client_cpu_avg" "$CLIENT_CPU_LIMIT"; then
        LAST_OVER_THRESHOLD=1
    fi

    echo "run_result scenario=$scenario impl=$impl phase=$phase run=$run_index qps=$qps errors=$total_errors combined_cpu=$combined_cpu_avg" >&2

    if [ "$client_status" -ne 0 ]; then
        return 1
    fi
    return 0
}

probe_scenario() {
    local scenario="$1"
    local requested_connections="$2"
    local requests="$3"
    local payload="$4"
    local safe_connections="$requested_connections"
    local impl=""

    while :; do
        local exceeded=0
        echo "probing scenario=$scenario connections=$safe_connections requests=$requests payload=$payload" >&2
        for impl in galay_ssl rust go; do
            run_one probe "$impl" "$scenario" 0 "$safe_connections" "$requests" "$payload" || exceeded=1
            if [ "$LAST_ERRORS" -ne 0 ] || [ "$LAST_OVER_THRESHOLD" -ne 0 ]; then
                exceeded=1
            fi
        done
        if [ "$exceeded" -eq 0 ]; then
            printf '%s' "$safe_connections"
            return 0
        fi
        if [ "$safe_connections" -le 1 ]; then
            printf '%s' "$safe_connections"
            return 0
        fi
        safe_connections="$(((safe_connections + 1) / 2))"
        echo "downgrading $scenario connections to $safe_connections to stay within CPU/error limits" >&2
    done
}

run_scenario() {
    local scenario="$1"
    local connections="$2"
    local requests="$3"
    local payload="$4"
    local impl=""
    local run_index=0

    for impl in galay_ssl rust go; do
        for ((run_index = 1; run_index <= WARMUP_RUNS; run_index += 1)); do
            run_one warmup "$impl" "$scenario" "$run_index" "$connections" "$requests" "$payload"
        done
        for ((run_index = 1; run_index <= FORMAL_RUNS; run_index += 1)); do
            run_one formal "$impl" "$scenario" "$run_index" "$connections" "$requests" "$payload"
        done
    done
}

generate_summary() {
    echo "scenario,implementation,connections,requests_per_conn,payload_bytes,threads,formal_runs,qps_median,throughput_median,server_cpu_median,client_cpu_median,combined_cpu_median,server_rss_max,client_rss_max,total_errors_sum" >"$SUMMARY_CSV"

    while IFS=, read -r scenario impl; do
        [ -z "$scenario" ] && continue
        local rows
        local connections
        local requests
        local payload
        local qps_median
        local throughput_median
        local server_cpu_median
        local client_cpu_median
        local combined_cpu_median
        local server_rss_max
        local client_rss_max
        local total_errors_sum

        rows="$(awk -F, -v scenario="$scenario" -v impl="$impl" '$2 == scenario && $3 == impl && $4 == "formal"' "$RAW_CSV")"
        [ -z "$rows" ] && continue

        connections="$(printf '%s\n' "$rows" | awk -F, 'NR == 1 { print $6 }')"
        requests="$(printf '%s\n' "$rows" | awk -F, 'NR == 1 { print $7 }')"
        payload="$(printf '%s\n' "$rows" | awk -F, 'NR == 1 { print $8 }')"
        qps_median="$(printf '%s\n' "$rows" | awk -F, '{ print $14 }' | sort -n | median_from_stdin)"
        throughput_median="$(printf '%s\n' "$rows" | awk -F, '{ print $15 }' | sort -n | median_from_stdin)"
        server_cpu_median="$(printf '%s\n' "$rows" | awk -F, '{ print $16 }' | sort -n | median_from_stdin)"
        client_cpu_median="$(printf '%s\n' "$rows" | awk -F, '{ print $18 }' | sort -n | median_from_stdin)"
        combined_cpu_median="$(printf '%s\n' "$rows" | awk -F, '{ print $20 }' | sort -n | median_from_stdin)"
        server_rss_max="$(printf '%s\n' "$rows" | awk -F, 'BEGIN { max = 0 } { if ($17 > max) max = $17 } END { print max }')"
        client_rss_max="$(printf '%s\n' "$rows" | awk -F, 'BEGIN { max = 0 } { if ($19 > max) max = $19 } END { print max }')"
        total_errors_sum="$(printf '%s\n' "$rows" | awk -F, '{ sum += $12 } END { print sum + 0 }')"

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$scenario" "$impl" "$connections" "$requests" "$payload" "$THREADS" "$FORMAL_RUNS" \
            "$qps_median" "$throughput_median" "$server_cpu_median" "$client_cpu_median" "$combined_cpu_median" \
            "$server_rss_max" "$client_rss_max" "$total_errors_sum" >>"$SUMMARY_CSV"
    done < <(awk -F, 'NR > 1 && $4 == "formal" { print $2 "," $3 }' "$RAW_CSV" | sort -u)
}

build_kernel
build_galay_ssl_bench
build_rust_server
build_go_server

SAFE_STREAMING_CONNECTIONS="$(probe_scenario streaming "$STREAMING_CONNECTIONS" "$STREAMING_REQUESTS" "$STREAMING_PAYLOAD")"
SAFE_HANDSHAKE_CONNECTIONS="$(probe_scenario handshake "$HANDSHAKE_CONNECTIONS" "$HANDSHAKE_REQUESTS" "$HANDSHAKE_PAYLOAD")"

run_scenario streaming "$SAFE_STREAMING_CONNECTIONS" "$STREAMING_REQUESTS" "$STREAMING_PAYLOAD"
run_scenario handshake "$SAFE_HANDSHAKE_CONNECTIONS" "$HANDSHAKE_REQUESTS" "$HANDSHAKE_PAYLOAD"

generate_summary

echo "ARTIFACT_DIR=$ARTIFACT_DIR"
echo "RAW_CSV=$RAW_CSV"
echo "SUMMARY_CSV=$SUMMARY_CSV"
echo "SAFE_STREAMING_CONNECTIONS=$SAFE_STREAMING_CONNECTIONS"
echo "SAFE_HANDSHAKE_CONNECTIONS=$SAFE_HANDSHAKE_CONNECTIONS"
