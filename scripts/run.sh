#!/bin/bash
# 运行测试脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
BIN_DIR="$BUILD_DIR/bin"

build_project() {
    echo "Building project..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=ON
    make -j$(sysctl -n hw.ncpu 2>/dev/null || nproc)
    cd "$PROJECT_DIR"
}

run_tests() {
    echo ""
    echo "=========================================="
    echo "  Running Unit Tests"
    echo "=========================================="

    if [ ! -f "$BIN_DIR/T1-SslSocketTest" ]; then
        echo "ERROR: Test binary not found. Building first..."
        build_project
    fi

    cd "$BIN_DIR"
    ./T1-SslSocketTest
    local result=$?
    cd "$PROJECT_DIR"

    return $result
}

main() {
    case "${1:-test}" in
        build)
            build_project
            ;;
        test)
            run_tests
            ;;
        bench)
            "$SCRIPT_DIR/S1-Bench.sh"
            ;;
        all)
            build_project
            run_tests
            "$SCRIPT_DIR/S1-Bench.sh"
            ;;
        *)
            echo "Usage: $0 {build|test|bench|all}"
            exit 1
            ;;
    esac
}

main "$@"
