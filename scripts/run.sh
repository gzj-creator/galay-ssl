#!/bin/bash
# 运行测试脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
BIN_DIR="$BUILD_DIR/bin"

build_project() {
    echo "Building project..."
    cmake -S "$PROJECT_DIR" -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_LTO=ON \
        -DBUILD_TESTING=ON \
        -DBUILD_BENCHMARKS=ON \
        -DBUILD_MODULE_EXAMPLES=OFF \
        "$@"
    cmake --build "$BUILD_DIR" --parallel
}

run_tests() {
    echo ""
    echo "=========================================="
    echo "  Running Unit Tests"
    echo "=========================================="

    if [ ! -f "$BUILD_DIR/CTestTestfile.cmake" ]; then
        echo "ERROR: CTest metadata not found. Building first..."
        build_project
    fi

    ctest --test-dir "$BUILD_DIR" --output-on-failure
}

main() {
    case "${1:-test}" in
        build)
            shift
            build_project "$@"
            ;;
        test)
            run_tests
            ;;
        bench)
            "$SCRIPT_DIR/S1-Bench.sh"
            ;;
        all)
            shift
            build_project "$@"
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
