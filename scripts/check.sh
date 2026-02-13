#!/bin/bash
# 验证测试结果和压测指标脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
BIN_DIR="$BUILD_DIR/bin"
CACHE_FILE="$BUILD_DIR/CMakeCache.txt"

check_tests() {
    echo "=========================================="
    echo "  Checking Test Results"
    echo "=========================================="

    if [ ! -f "$BIN_DIR/T1-SslSocketTest" ]; then
        echo "ERROR: Test binary not found."
        return 1
    fi

    cd "$BIN_DIR"
    local output
    output=$(./T1-SslSocketTest 2>&1)
    local result=$?
    cd "$PROJECT_DIR"

    local passed=$(echo "$output" | grep "Passed:" | awk '{print $2}')
    local failed=$(echo "$output" | grep "Failed:" | awk '{print $2}')

    echo "Test Results: $passed passed, $failed failed"

    if [ "$failed" != "0" ] || [ $result -ne 0 ]; then
        echo "FAILED: Some tests did not pass"
        return 1
    fi

    echo "PASSED: All tests passed"
    return 0
}

check_benchmarks() {
    echo ""
    echo "=========================================="
    echo "  Checking Benchmark Binaries"
    echo "=========================================="

    local missing=0

    if [ ! -f "$BIN_DIR/B1-SslBenchServer" ]; then
        echo "MISSING: B1-SslBenchServer"
        missing=1
    else
        echo "OK: B1-SslBenchServer"
    fi

    if [ ! -f "$BIN_DIR/B1-SslBenchClient" ]; then
        echo "MISSING: B1-SslBenchClient"
        missing=1
    else
        echo "OK: B1-SslBenchClient"
    fi

    if [ $missing -eq 1 ]; then
        echo "WARNING: Some benchmark binaries are missing"
        return 1
    fi

    if [ ! -f "$CACHE_FILE" ]; then
        echo "WARNING: CMakeCache.txt not found, cannot verify Release+LTO"
        return 1
    fi

    local build_type
    build_type=$(grep -E "^CMAKE_BUILD_TYPE:STRING=" "$CACHE_FILE" | cut -d'=' -f2)
    local lto
    lto=$(grep -E "^ENABLE_LTO:BOOL=" "$CACHE_FILE" | cut -d'=' -f2 || true)

    if [ "$build_type" != "Release" ] || [ "$lto" != "ON" ]; then
        echo "WARNING: Benchmark build is not Release+LTO (CMAKE_BUILD_TYPE=$build_type, ENABLE_LTO=$lto)"
        return 1
    fi

    echo "OK: Benchmark build type is Release+LTO"
    echo "PASSED: All benchmark binaries present"
    return 0
}

check_certs() {
    echo ""
    echo "=========================================="
    echo "  Checking Certificates"
    echo "=========================================="

    local certs_dir="$BIN_DIR/certs"
    local missing=0

    for cert in ca.crt server.crt server.key client.crt client.key; do
        if [ ! -f "$certs_dir/$cert" ]; then
            echo "MISSING: $cert"
            missing=1
        else
            echo "OK: $cert"
        fi
    done

    if [ $missing -eq 1 ]; then
        echo "WARNING: Some certificates are missing"
        return 1
    fi

    echo "PASSED: All certificates present"
    return 0
}

main() {
    local all_passed=0

    check_tests || all_passed=1
    check_benchmarks || all_passed=1
    check_certs || all_passed=1

    echo ""
    echo "=========================================="
    if [ $all_passed -eq 0 ]; then
        echo "  All Checks PASSED"
    else
        echo "  Some Checks FAILED"
    fi
    echo "=========================================="

    return $all_passed
}

main "$@"
