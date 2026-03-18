# Rust/Go SSL Benchmark Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a controlled, reproducible Linux benchmark that compares `galay-ssl`, Rust `tokio-rustls`, and Go `crypto/tls` TLS echo servers using the same `galay-ssl` benchmark client.

**Architecture:** Keep the existing C++ benchmark client as the single load generator, add Rust and Go TLS echo servers that match the current echo contract, and wrap all three server implementations in one CPU-safe orchestration script that performs warmup, formal runs, CSV capture, and median aggregation. Lock the benchmark protocol to TLS 1.3 and disable session reuse so the comparison reflects one shared transport contract instead of three drifting defaults.

**Tech Stack:** CMake/C++23, `galay-ssl`, Rust `tokio` + `tokio-rustls`, Go `crypto/tls`, POSIX shell, `ssh`, `scp`, `awk`

---

### Task 1: Lock The Existing C++ Benchmark Contract

**Files:**
- Modify: `benchmark/B1-ssl_bench_server.cc`
- Modify: `benchmark/B1-ssl_bench_client.cc`
- Modify: `benchmark/README.md`
- Test: `build-crosslang-contract/bin/B1-SslBenchServer`
- Test: `build-crosslang-contract/bin/B1-SslBenchClient`

**Step 1: Write the smallest failing contract check**

Run:

```bash
cmake -S . -B build-crosslang-contract \
  -DCMAKE_PREFIX_PATH=/Users/gongzhijie/Desktop/projects/git/galay-kernel/.verify-install-kernel-20260318 \
  -DBUILD_BENCHMARKS=ON \
  -DBUILD_TESTS=OFF \
  -DBUILD_EXAMPLES=OFF
cmake --build build-crosslang-contract --target B1-SslBenchServer B1-SslBenchClient --parallel
./build-crosslang-contract/bin/B1-SslBenchServer 9443 certs/server.crt certs/server.key >/tmp/galay_ssl_cpp_bench_server.log 2>&1 &
SERVER_PID=$!
sleep 1
./build-crosslang-contract/bin/B1-SslBenchClient 127.0.0.1 9443 1 1 47 1 1
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected before edits: the smoke passes, but the source still does not make TLS 1.3 / session behavior explicit. This is the baseline command to keep rerunning after each benchmark-contract edit.

**Step 2: Write the minimal implementation**

Change both benchmark endpoints so the comparison contract is explicit in code:

- server context uses `SslMethod::TLS_1_3_Server`
- client context uses `SslMethod::TLS_1_3_Client`
- server and client both disable session cache / reuse for benchmark runs
- `benchmark/README.md` records that the cross-language benchmark is pinned to TLS 1.3 and no resumption

**Step 3: Run the contract check again**

Run the exact command from Step 1.

Expected: `Total requests: 1`, `Total errors: 0`, and the benchmark README now documents the TLS 1.3 / no-resumption contract.

**Step 4: Commit**

```bash
git add benchmark/B1-ssl_bench_server.cc benchmark/B1-ssl_bench_client.cc benchmark/README.md
git commit -m "bench: pin ssl benchmark contract to tls13"
```

### Task 2: Add The Rust `tokio-rustls` Echo Server

**Files:**
- Create: `benchmark/rust-tokio-rustls-server/Cargo.toml`
- Create: `benchmark/rust-tokio-rustls-server/src/main.rs`
- Create: `benchmark/rust-tokio-rustls-server/README.md`
- Test: `benchmark/rust-tokio-rustls-server/target/release/rust-tokio-rustls-server`
- Test: `build-crosslang-contract/bin/B1-SslBenchClient`

**Step 1: Run the missing-server smoke to verify the red state**

Run:

```bash
cargo build --manifest-path benchmark/rust-tokio-rustls-server/Cargo.toml --release
```

Expected: FAIL with “manifest path does not exist”.

**Step 2: Write the minimal implementation**

Create a small Tokio TLS echo server with this contract:

- CLI: `<port> <cert_file> <key_file> [backlog]`
- load the existing PEM cert/key pair from `certs/`
- configure `rustls` for TLS 1.3 only
- disable session resumption / ticket behavior for the benchmark path
- accept TCP connections with Tokio
- wrap each accepted socket with `TlsAcceptor`
- read bytes into a fixed buffer and write back exactly what was read
- exit non-zero on setup failure and log one-line errors to stderr

Prefer a single `main.rs` first; avoid extra abstraction until the smoke passes.

**Step 3: Run the local smoke against the Rust server**

Run:

```bash
cargo build --manifest-path benchmark/rust-tokio-rustls-server/Cargo.toml --release
./benchmark/rust-tokio-rustls-server/target/release/rust-tokio-rustls-server 9444 certs/server.crt certs/server.key >/tmp/rust_tls_bench_server.log 2>&1 &
SERVER_PID=$!
sleep 1
./build-crosslang-contract/bin/B1-SslBenchClient 127.0.0.1 9444 1 1 47 1 1
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: `Total requests: 1`, `Total errors: 0`.

**Step 4: Commit**

```bash
git add benchmark/rust-tokio-rustls-server/Cargo.toml benchmark/rust-tokio-rustls-server/src/main.rs benchmark/rust-tokio-rustls-server/README.md
git commit -m "bench: add rust tokio-rustls echo server"
```

### Task 3: Add The Go `crypto/tls` Echo Server

**Files:**
- Create: `benchmark/go-crypto-tls-server/go.mod`
- Create: `benchmark/go-crypto-tls-server/main.go`
- Create: `benchmark/go-crypto-tls-server/README.md`
- Test: `benchmark/go-crypto-tls-server/go-crypto-tls-server`
- Test: `build-crosslang-contract/bin/B1-SslBenchClient`

**Step 1: Run the missing-server smoke to verify the red state**

Run:

```bash
go build -o benchmark/go-crypto-tls-server/go-crypto-tls-server ./benchmark/go-crypto-tls-server
```

Expected: FAIL with “directory not found” or “go.mod not found”.

**Step 2: Write the minimal implementation**

Create a small Go TLS echo server with this contract:

- CLI: `<port> <cert_file> <key_file> [backlog]`
- load the same PEM cert/key
- configure `crypto/tls.Config` for TLS 1.3 only
- disable session tickets / resumption for benchmark runs
- listen with `tls.Listen`
- accept each connection in a goroutine
- read into a fixed buffer and write back exactly what was read
- print one-line fatal errors to stderr and exit non-zero on setup failure

Keep the first version in one file; only extract helpers if the smoke becomes unreadable.

**Step 3: Run the local smoke against the Go server**

Run:

```bash
go build -o benchmark/go-crypto-tls-server/go-crypto-tls-server ./benchmark/go-crypto-tls-server
./benchmark/go-crypto-tls-server/go-crypto-tls-server 9445 certs/server.crt certs/server.key >/tmp/go_tls_bench_server.log 2>&1 &
SERVER_PID=$!
sleep 1
./build-crosslang-contract/bin/B1-SslBenchClient 127.0.0.1 9445 1 1 47 1 1
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: `Total requests: 1`, `Total errors: 0`.

**Step 4: Commit**

```bash
git add benchmark/go-crypto-tls-server/go.mod benchmark/go-crypto-tls-server/main.go benchmark/go-crypto-tls-server/README.md
git commit -m "bench: add go crypto tls echo server"
```

### Task 4: Add One CPU-Safe Cross-Language Runner

**Files:**
- Create: `scripts/S2-CrossLangBench.sh`
- Create: `scripts/S2-CrossLangBench.remote.sh`
- Modify: `benchmark/README.md`
- Modify: `docs/05-性能测试.md`
- Test: `scripts/S2-CrossLangBench.sh`

**Step 1: Write the first failing runner invocation**

Run:

```bash
bash scripts/S2-CrossLangBench.sh --help
```

Expected: FAIL with “No such file or directory”.

**Step 2: Write the minimal implementation**

Add two shell entrypoints:

- `scripts/S2-CrossLangBench.sh`
- local wrapper that uploads the current benchmark assets to the remote host, invokes the remote runner, and downloads CSV/log artifacts
- `scripts/S2-CrossLangBench.remote.sh`
- remote runner that:
- builds the needed C++, Rust, and Go binaries
- starts exactly one server implementation at a time
- pins client/server to non-overlapping CPU sets
- performs one warmup run plus five formal runs per scenario
- probes low load first and downgrades parameters if CPU thresholds are exceeded
- records per-run QPS, throughput, errors, server CPU, client CPU, server RSS, client RSS
- writes one raw CSV per scenario and one summary CSV with medians

Document the CLI and safety thresholds in `benchmark/README.md` and `docs/05-性能测试.md`.

**Step 3: Run a dry-run or local help verification**

Run:

```bash
bash scripts/S2-CrossLangBench.sh --help
```

Expected: usage text documents required flags such as remote host, user, password or key, remote workspace, CPU sets, and output directory.

**Step 4: Commit**

```bash
git add scripts/S2-CrossLangBench.sh scripts/S2-CrossLangBench.remote.sh benchmark/README.md docs/05-性能测试.md
git commit -m "bench: add cross language benchmark runner"
```

### Task 5: Run The Controlled Linux Benchmark And Publish Results

**Files:**
- Create: `docs/plans/2026-03-18-rust-go-ssl-benchmark-results.md`
- Modify: `benchmark/README.md`
- Modify: `docs/05-性能测试.md`
- Test: remote CSV artifacts under a timestamped output directory

**Step 1: Run a smoke benchmark on the remote host**

Run:

```bash
bash scripts/S2-CrossLangBench.sh \
  --remote-host 140.143.142.251 \
  --remote-user ubuntu \
  --remote-root /home/ubuntu/tmp/galay-ssl-crosslang-bench \
  --server-cpus 0-1 \
  --client-cpus 2-3 \
  --streaming-connections 16 \
  --streaming-requests 100 \
  --handshake-connections 32 \
  --handshake-requests 1 \
  --formal-runs 1 \
  --warmup-runs 1
```

Expected: all three implementations finish both smoke scenarios with `Total errors = 0`, and the output directory contains raw CSV files.

**Step 2: Run the formal benchmark**

Run:

```bash
bash scripts/S2-CrossLangBench.sh \
  --remote-host 140.143.142.251 \
  --remote-user ubuntu \
  --remote-root /home/ubuntu/tmp/galay-ssl-crosslang-bench \
  --server-cpus 0-1 \
  --client-cpus 2-3 \
  --streaming-connections 64 \
  --streaming-requests 500 \
  --streaming-payload 256 \
  --handshake-connections 128 \
  --handshake-requests 1 \
  --handshake-payload 47 \
  --threads 4 \
  --warmup-runs 1 \
  --formal-runs 5
```

Expected: the runner auto-downgrades if CPU safety thresholds are exceeded, completes all formal runs, and writes summary CSV data with medians.

**Step 3: Write the results document**

Create `docs/plans/2026-03-18-rust-go-ssl-benchmark-results.md` with:

- remote machine and toolchain details
- exact benchmark commands
- CPU-set layout and thresholds
- per-scenario median table
- raw-data artifact paths
- interpretation of where `galay-ssl` is ahead, behind, or tied
- a short section on methodological limits

Then update `benchmark/README.md` and `docs/05-性能测试.md` to link to the results document instead of embedding hand-copied numbers in multiple places.

**Step 4: Verify the report matches the artifacts**

Run:

```bash
ls -R /home/ubuntu/tmp/galay-ssl-crosslang-bench
```

Expected: raw CSV / log files referenced in the report exist in the remote output directory.

**Step 5: Commit**

```bash
git add docs/plans/2026-03-18-rust-go-ssl-benchmark-results.md benchmark/README.md docs/05-性能测试.md
git commit -m "bench: publish rust go ssl comparison results"
```
