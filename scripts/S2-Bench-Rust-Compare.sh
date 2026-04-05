#!/bin/bash
# Compare C++ SSL benchmark with minimal Rust TLS counterpart.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
BIN_DIR="$BUILD_DIR/bin"
CACHE_FILE="$BUILD_DIR/CMakeCache.txt"
RUST_MANIFEST="$PROJECT_DIR/benchmark/compare/rust/Cargo.toml"
RUST_TARGET_DIR="$PROJECT_DIR/benchmark/compare/rust/target"
RUST_SERVER_BIN="$RUST_TARGET_DIR/release/rust_ssl_bench_server"
RUST_CLIENT_BIN="$RUST_TARGET_DIR/release/rust_ssl_bench_client"

SERVER_PORT=8443
CONNECTIONS=50
REQUESTS_PER_CONN=200
PAYLOAD_BYTES=47
THREADS=1
CONNECT_RETRIES=3
SERVER_PID=""

ensure_release_lto() {
    if [ ! -f "$CACHE_FILE" ]; then
        echo "ERROR: $CACHE_FILE not found. Build galay-ssl first with Release+LTO."
        exit 1
    fi

    local build_type
    build_type=$(grep -E "^CMAKE_BUILD_TYPE:STRING=" "$CACHE_FILE" | cut -d'=' -f2)
    if [ "$build_type" != "Release" ]; then
        echo "ERROR: Benchmark compare requires Release build, current is '$build_type'."
        exit 1
    fi

    local lto
    lto=$(grep -E "^ENABLE_LTO:BOOL=" "$CACHE_FILE" | cut -d'=' -f2 || true)
    if [ "$lto" != "ON" ]; then
        echo "ERROR: Benchmark compare requires ENABLE_LTO=ON."
        exit 1
    fi
}

ensure_cpp_bins() {
    if [ ! -x "$BIN_DIR/B1-SslBenchServer" ] || [ ! -x "$BIN_DIR/B1-SslBenchClient" ]; then
        echo "ERROR: C++ benchmark binaries are missing under $BIN_DIR."
        exit 1
    fi
}

ensure_rust_bins() {
    if [ ! -f "$RUST_MANIFEST" ]; then
        echo "ERROR: Rust benchmark manifest missing: $RUST_MANIFEST"
        exit 1
    fi

    cargo build --release --manifest-path "$RUST_MANIFEST" --target-dir "$RUST_TARGET_DIR"

    if [ ! -x "$RUST_SERVER_BIN" ] || [ ! -x "$RUST_CLIENT_BIN" ]; then
        echo "ERROR: Rust benchmark binaries are missing after build."
        exit 1
    fi
}

cleanup() {
    if [ -n "${SERVER_PID}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}

start_cpp_server() {
    cleanup
    "$BIN_DIR/B1-SslBenchServer" "$SERVER_PORT" "$PROJECT_DIR/certs/server.crt" "$PROJECT_DIR/certs/server.key" > /tmp/galay_ssl_cpp_server.log 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: C++ benchmark server failed to start."
        cat /tmp/galay_ssl_cpp_server.log
        exit 1
    fi
}

start_rust_server() {
    cleanup
    "$RUST_SERVER_BIN" "$SERVER_PORT" "$PROJECT_DIR/certs/server.crt" "$PROJECT_DIR/certs/server.key" > /tmp/galay_ssl_rust_server.log 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: Rust benchmark server failed to start."
        cat /tmp/galay_ssl_rust_server.log
        exit 1
    fi
}

extract_metric() {
    local output="$1"
    local key="$2"
    echo "$output" | awk -F': ' -v k="$key" '$1==k {print $2}' | tail -n 1
}

run_cpp_client() {
    "$BIN_DIR/B1-SslBenchClient" 127.0.0.1 "$SERVER_PORT" "$CONNECTIONS" "$REQUESTS_PER_CONN" "$PAYLOAD_BYTES" "$THREADS" "$CONNECT_RETRIES"
}

run_rust_client() {
    "$RUST_CLIENT_BIN" localhost "$SERVER_PORT" "$CONNECTIONS" "$REQUESTS_PER_CONN" "$PAYLOAD_BYTES" "$THREADS" "$CONNECT_RETRIES" "$PROJECT_DIR/certs/ca.crt"
}

main() {
    trap cleanup EXIT

    ensure_release_lto
    ensure_cpp_bins
    ensure_rust_bins

    echo "=== C++ Benchmark ==="
    start_cpp_server
    local cpp_output
    cpp_output="$(run_cpp_client)"
    echo "$cpp_output"
    cleanup

    local cpp_errors
    cpp_errors="$(extract_metric "$cpp_output" "Total errors")"
    if [ -z "$cpp_errors" ] || [ "$cpp_errors" != "0" ]; then
        echo "ERROR: C++ benchmark reported errors."
        exit 1
    fi

    local cpp_qps cpp_thr
    cpp_qps="$(extract_metric "$cpp_output" "Requests/sec")"
    cpp_thr="$(extract_metric "$cpp_output" "Throughput")"

    echo ""
    echo "=== Rust Benchmark ==="
    start_rust_server
    local rust_output
    rust_output="$(run_rust_client)"
    echo "$rust_output"
    cleanup

    local rust_errors
    rust_errors="$(extract_metric "$rust_output" "Total errors")"
    if [ -z "$rust_errors" ] || [ "$rust_errors" != "0" ]; then
        echo "ERROR: Rust benchmark reported errors."
        exit 1
    fi

    local rust_qps rust_thr
    rust_qps="$(extract_metric "$rust_output" "Requests/sec")"
    rust_thr="$(extract_metric "$rust_output" "Throughput")"

    echo ""
    echo "=== Summary ==="
    echo "Scenario: connections=$CONNECTIONS requests_per_conn=$REQUESTS_PER_CONN payload=$PAYLOAD_BYTES threads=$THREADS"
    echo "C++ Requests/sec: $cpp_qps"
    echo "Rust Requests/sec: $rust_qps"
    echo "C++ Throughput: $cpp_thr"
    echo "Rust Throughput: $rust_thr"
}

main "$@"
