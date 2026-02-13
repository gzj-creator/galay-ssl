#!/bin/bash
# SSL 性能测试脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
BIN_DIR="$BUILD_DIR/bin"
CACHE_FILE="$BUILD_DIR/CMakeCache.txt"

SERVER_PORT=8443
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

ensure_release_lto() {
    if [ ! -f "$CACHE_FILE" ]; then
        echo "ERROR: $CACHE_FILE not found. Please build first with Release+LTO."
        echo "Hint: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON && cmake --build build -j"
        exit 1
    fi

    local build_type
    build_type=$(grep -E "^CMAKE_BUILD_TYPE:STRING=" "$CACHE_FILE" | cut -d'=' -f2)
    if [ "$build_type" != "Release" ]; then
        echo "ERROR: Benchmark requires Release build, current is '$build_type'."
        echo "Hint: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON && cmake --build build -j"
        exit 1
    fi

    local lto
    lto=$(grep -E "^ENABLE_LTO:BOOL=" "$CACHE_FILE" | cut -d'=' -f2 || true)
    if [ "$lto" != "ON" ]; then
        echo "ERROR: Benchmark requires ENABLE_LTO=ON."
        echo "Hint: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON && cmake --build build -j"
        exit 1
    fi
}

start_server() {
    echo "Starting SSL server on port $SERVER_PORT..."
    "$BIN_DIR/B1-SslBenchServer" $SERVER_PORT "$BIN_DIR/certs/server.crt" "$BIN_DIR/certs/server.key" > /tmp/ssl_server.log 2>&1 &
    SERVER_PID=$!
    sleep 1

    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: Server failed to start"
        cat /tmp/ssl_server.log
        exit 1
    fi
    echo "Server started (PID: $SERVER_PID)"
}

run_test() {
    local connections=$1
    local requests=$2
    local desc=$3

    echo ""
    echo "=== $desc ==="
    echo "Connections: $connections, Requests/conn: $requests"

    local output
    output=$("$BIN_DIR/B1-SslBenchClient" 127.0.0.1 $SERVER_PORT $connections $requests 2>&1)

    local total_requests=$(echo "$output" | grep "Total requests:" | awk '{print $3}')
    local total_errors=$(echo "$output" | grep "Total errors:" | awk '{print $3}')
    local duration=$(echo "$output" | grep "Duration:" | awk '{print $2}')
    local qps=$(echo "$output" | grep "Requests/sec:" | awk '{print $2}')
    local throughput=$(echo "$output" | grep "Throughput:" | awk '{print $2}')

    echo "Results: $total_requests requests, $total_errors errors, ${duration}ms, $qps QPS, $throughput MB/s"

    if [ "$total_errors" != "0" ]; then
        echo "WARNING: Test had errors!"
        return 1
    fi

    local expected=$((connections * requests))
    if [ "$total_requests" != "$expected" ]; then
        echo "WARNING: Expected $expected requests, got $total_requests"
        return 1
    fi

    return 0
}

main() {
    echo "=========================================="
    echo "  galay-ssl Performance Benchmark"
    echo "=========================================="

    ensure_release_lto

    if [ ! -f "$BIN_DIR/B1-SslBenchServer" ] || [ ! -f "$BIN_DIR/B1-SslBenchClient" ]; then
        echo "ERROR: Binaries not found. Please build first."
        exit 1
    fi

    start_server

    echo ""
    echo "Running benchmarks..."

    # 基础测试
    run_test 1 100 "Warmup"

    # 单连接测试
    run_test 1 1000 "Single connection, 1000 requests"
    run_test 1 5000 "Single connection, 5000 requests"
    run_test 1 10000 "Single connection, 10000 requests"

    # 多连接测试
    run_test 10 1000 "10 connections, 1000 requests each"
    run_test 50 200 "50 connections, 200 requests each"
    run_test 100 100 "100 connections, 100 requests each"

    echo ""
    echo "=========================================="
    echo "  Benchmark Complete"
    echo "=========================================="
}

main "$@"
