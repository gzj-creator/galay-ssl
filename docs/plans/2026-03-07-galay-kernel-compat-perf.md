# galay-kernel Compatibility and SSL Benchmark Optimization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Adapt `galay-ssl` to the current `galay-kernel`, recover a correct benchmarkable baseline, optimize the clearest hot paths, and compare the result against temporary Go and Rust SSL echo benchmarks.

**Architecture:** Keep the public `SslSocket` API stable and localize compatibility fixes to the async bridge between `galay-kernel` IO helpers and the SSL state machines in `galay-ssl/async/Awaitable.cc`. Build correctness confidence with a loopback smoke test before using the existing benchmark binaries plus profiling data to guide one hotspot optimization at a time, then compare against external `Go crypto/tls` and `Rust rustls + tokio` harnesses living outside the repository.

**Tech Stack:** C++23, CMake, OpenSSL 3.x, `galay-kernel`, macOS `sample`, Go `crypto/tls`, Rust `tokio` + `rustls`

---

### Task 1: Reproduce the galay-kernel compatibility break

**Files:**
- Check: `CMakeLists.txt`
- Check: `galay-ssl/async/Awaitable.cc`
- Check: `/usr/local/include/galay-kernel/kernel/IOHandlers.hpp`
- Check: `/usr/local/include/galay-kernel/kernel/Awaitable.inl`

**Step 1: Reproduce the failing build**

Run:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON
cmake --build build --parallel
```

Expected: FAIL in `galay-ssl/async/Awaitable.cc` with `member reference base type 'unsigned long' is not a structure or union`.

**Step 2: Verify the upstream contract change**

Run:

```bash
rg -n "handleRecv\\(" /usr/local/include/galay-kernel/kernel/IOHandlers.hpp /usr/local/include/galay-kernel/kernel/Awaitable.inl
```

Expected: `handleRecv(...)` now returns `std::expected<size_t, IOError>` instead of a byte container.

**Step 3: Record the root-cause hypothesis**

Use this working hypothesis for all later changes:

```text
galay-ssl still treats io::handleRecv(...) as if result.value() exposes data()/size(),
but the updated galay-kernel now returns a byte count and leaves the payload in the caller buffer.
```

**Step 4: Do not patch anything else yet**

Before touching code, keep the scope focused on:
- `SslRecvAwaitable::RecvCtx::handleComplete`
- `SslHandshakeAwaitable::HandshakeRecvCtx::handleComplete`
- `SslShutdownAwaitable::ShutdownRecvCtx::handleComplete`

**Step 5: Commit the investigation checkpoint**

```bash
git add docs/plans/2026-03-07-galay-kernel-compat-perf.md
git commit -m "plan: capture galay-kernel compatibility work"
```

### Task 2: Add a loopback SSL smoke test before the fix

**Files:**
- Create: `test/T2-SslLoopbackSmoke.cc`
- Modify: `test/CMakeLists.txt`
- Reference: `examples/include/E1-SslEchoServer.cc`
- Reference: `examples/include/E2-SslClient.cc`

**Step 1: Write the failing smoke test**

Add a new executable-style test that:
- starts a scheduler,
- loads `test/certs/server.crt`, `test/certs/server.key`, `test/certs/ca.crt`,
- accepts one loopback client,
- completes handshake,
- sends one payload such as `"ping-from-test"`,
- reads the echo back,
- closes cleanly.

Use this skeleton as the starting point:

```cpp
TEST(SslSocket_LoopbackHandshakeAndEcho) {
    TestScheduler scheduler;
    scheduler.start();

    SslContext serverCtx(SslMethod::TLS_Server);
    SslContext clientCtx(SslMethod::TLS_Client);
    EXPECT_TRUE(serverCtx.isValid());
    EXPECT_TRUE(clientCtx.isValid());

    std::atomic<bool> done{false};
    std::string echoed;

    scheduler.spawn(runServer(&scheduler, &serverCtx, &done));
    scheduler.spawn(runClient(&scheduler, &clientCtx, &echoed, &done));

    waitUntil(done);
    EXPECT_EQ(echoed, "ping-from-test");

    scheduler.stop();
}
```

**Step 2: Register the new test target**

Update `test/CMakeLists.txt` to build `T2-SslLoopbackSmoke` and copy `test/certs` for that target the same way `T1-SslSocketTest` already does.

**Step 3: Run the new target in red state**

Run:

```bash
cmake --build build --target T2-SslLoopbackSmoke --parallel
```

Expected: still RED because `galay-ssl/async/Awaitable.cc` does not compile against the new `handleRecv` contract yet.

**Step 4: Keep the assertions narrow**

Assert only:
- handshake completes,
- echoed payload matches,
- no unexpected SSL error is returned.

Do not add benchmark assertions here.

**Step 5: Commit the red test**

```bash
git add test/CMakeLists.txt test/T2-SslLoopbackSmoke.cc
git commit -m "test: add ssl loopback smoke coverage"
```

### Task 3: Adapt recv/handshake/shutdown paths to the new `handleRecv` contract

**Files:**
- Modify: `galay-ssl/async/Awaitable.cc`
- Reference: `/usr/local/include/galay-kernel/kernel/IOHandlers.hpp`

**Step 1: Replace old byte-container assumptions**

In every recv completion path, stop doing this:

```cpp
auto& bytes = result.value();
m_owner->m_engine->feedEncryptedInput(reinterpret_cast<const char*>(bytes.data()), bytes.size());
```

Replace it with a count-based feed using the existing buffer:

```cpp
const size_t recvBytes = result.value();
if (recvBytes == 0) {
    // map EOF to the awaitable-specific completion path
}
m_owner->m_engine->feedEncryptedInput(m_buffer, recvBytes);
```

**Step 2: Preserve the old EOF semantics per state machine**

Implement the zero-byte case deliberately:
- `SslRecvAwaitable::RecvCtx::handleComplete(...)` → finish with `Bytes()` when no plaintext is pending.
- `SslHandshakeAwaitable::HandshakeRecvCtx::handleComplete(...)` → finish with `SslErrorCode::kHandshakeFailed`.
- `SslShutdownAwaitable::ShutdownRecvCtx::handleComplete(...)` → finish successfully (`m_result = {}`).

For the edge-triggered loops, stop feeding once `recvBytes == 0`; do not continue looping forever.

**Step 3: Rebuild the library and smoke tests**

Run:

```bash
cmake --build build --target galay-ssl T1-SslSocketTest T2-SslLoopbackSmoke --parallel
```

Expected: `galay-ssl` compiles, and any remaining failures point to the next true compatibility issue rather than this signature mismatch.

**Step 4: Run the correctness checks**

Run:

```bash
./build/bin/T1-SslSocketTest
./build/bin/T2-SslLoopbackSmoke
```

Expected: both pass with `Failed: 0`.

**Step 5: Commit the minimal compatibility fix**

```bash
git add galay-ssl/async/Awaitable.cc test/CMakeLists.txt test/T2-SslLoopbackSmoke.cc
git commit -m "fix: adapt ssl awaitables to galay-kernel recv contract"
```

### Task 4: Clear any remaining kernel-upgrade fallout one compiler error at a time

**Files:**
- Modify: `galay-ssl/async/SslSocket.cc`
- Modify: `galay-ssl/async/SslSocket.h`
- Modify: `galay-ssl/async/Awaitable.h`
- Modify: `benchmark/B1-SslBenchClient.cc`
- Modify: `benchmark/B1-SslBenchServer.cc`
- Modify: `examples/include/E1-SslEchoServer.cc`
- Modify: `examples/include/E2-SslClient.cc`

**Step 1: Run the full build**

Run:

```bash
cmake --build build --parallel
```

Expected: either GREEN, or the next compiler error points to one exact file above.

**Step 2: Fix one API mismatch at a time**

For each new error:
- read the exact compiler message,
- compare with the current `galay-kernel` header,
- patch only the file named in the error,
- rebuild immediately.

Do not batch speculative refactors.

**Step 3: Verify all shipped binaries**

Run:

```bash
./scripts/check.sh
```

Expected: tests pass, benchmark binaries exist, certs are copied.

**Step 4: Run one minimal example smoke**

Run:

```bash
./build/bin/E1-SslEchoServer-Include 9443 build/certs/server.crt build/certs/server.key >/tmp/galay-ssl-example.log 2>&1 &
SERVER_PID=$!
sleep 1
printf 'hello\n' | ./build/bin/E2-SslClient-Include 127.0.0.1 9443
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: the client receives echoed plaintext and the server exits cleanly.

**Step 5: Commit the compatibility baseline**

```bash
git add galay-ssl/async galay-ssl/ssl benchmark examples test
git commit -m "fix: restore galay-ssl against updated galay-kernel"
```

### Task 5: Establish the post-compatibility performance baseline

**Files:**
- Check: `benchmark/B1-SslBenchClient.cc`
- Check: `benchmark/B1-SslBenchServer.cc`
- Check: `scripts/S1-Bench.sh`
- Output: `/tmp/galay-ssl-baseline-small.txt`
- Output: `/tmp/galay-ssl-baseline-large.txt`
- Output: `/tmp/galay-ssl-baseline-handshake.txt`

**Step 1: Run the small-payload baseline**

Run:

```bash
./build/bin/B1-SslBenchServer 9443 build/certs/server.crt build/certs/server.key >/tmp/galay-ssl-bench-server.log 2>&1 &
SERVER_PID=$!
sleep 1
./build/bin/B1-SslBenchClient 127.0.0.1 9443 200 500 47 4 | tee /tmp/galay-ssl-baseline-small.txt
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: `Total errors: 0`.

**Step 2: Run the large-payload baseline**

Run:

```bash
./build/bin/B1-SslBenchServer 9444 build/certs/server.crt build/certs/server.key >/tmp/galay-ssl-bench-server-large.log 2>&1 &
SERVER_PID=$!
sleep 1
./build/bin/B1-SslBenchClient 127.0.0.1 9444 10 200 65536 1 | tee /tmp/galay-ssl-baseline-large.txt
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: `Total errors: 0`.

**Step 3: Run a handshake-focused pass**

Run:

```bash
./build/bin/B1-SslBenchServer 9445 build/certs/server.crt build/certs/server.key >/tmp/galay-ssl-bench-server-handshake.log 2>&1 &
SERVER_PID=$!
sleep 1
./build/bin/B1-SslBenchClient 127.0.0.1 9445 400 1 47 4 | tee /tmp/galay-ssl-baseline-handshake.txt
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: use this as the handshake baseline before optimization.

**Step 4: Save only reproducible numbers**

Repeat any suspicious run until:
- `Total errors: 0`,
- request count matches expectation,
- outliers are explained.

**Step 5: Commit only if instrumentation is added**

If no repository file changed, skip the commit. If you changed benchmark code during setup:

```bash
git add benchmark
git commit -m "chore: prepare benchmark baseline capture"
```

### Task 6: Profile first, then add the smallest useful instrumentation

**Files:**
- Modify: `benchmark/SslStats.h`
- Modify: `benchmark/SslStats.cc`
- Modify: `benchmark/B1-SslBenchClient.cc`
- Modify: `galay-ssl/async/Awaitable.cc`
- Output: `/tmp/galay-ssl-small.sample.txt`
- Output: `/tmp/galay-ssl-large.sample.txt`

**Step 1: Capture a small-payload sample**

Run:

```bash
./build/bin/B1-SslBenchServer 9446 build/certs/server.crt build/certs/server.key >/tmp/galay-ssl-profile-server.log 2>&1 &
SERVER_PID=$!
sleep 1
sample $SERVER_PID 10 -file /tmp/galay-ssl-small.sample.txt &
SAMPLE_PID=$!
./build/bin/B1-SslBenchClient 127.0.0.1 9446 200 500 47 4 >/tmp/galay-ssl-small-profile-client.txt
wait $SAMPLE_PID
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: a sample report dominated by a few frames in `SSL_*`, `galay::ssl`, or scheduler code.

**Step 2: Capture a large-payload sample**

Run the same pattern with payload `65536` and save to `/tmp/galay-ssl-large.sample.txt`.

**Step 3: Pick one hotspot only**

Pick the hottest actionable path, for example:
- repeated ciphertext copy / chunk reshaping in `galay-ssl/async/Awaitable.cc`,
- unnecessary `Bytes::fromString(...)` construction on partial reads,
- redundant extract/feed loops around `SslEngine`.

Do not optimize more than one root cause in the same patch.

**Step 4: Add benchmark-only counters only if the sample is ambiguous**

If `sample` does not explain the gap, extend `benchmark/SslStats.*` and `benchmark/B1-SslBenchClient.cc` with one extra counter family, such as:

```cpp
struct SslIoStats {
    uint64_t recv_zero_reads = 0;
    uint64_t handshake_want_read = 0;
    uint64_t handshake_want_write = 0;
};
```

Keep those counters behind the existing `GALAY_SSL_STATS` gate.

**Step 5: Commit the profiling aids**

```bash
git add benchmark/SslStats.h benchmark/SslStats.cc benchmark/B1-SslBenchClient.cc galay-ssl/async/Awaitable.cc
git commit -m "perf: add focused ssl benchmark instrumentation"
```

### Task 7: Apply the first evidence-backed hotspot optimization

**Files:**
- Modify: `galay-ssl/async/Awaitable.cc`
- Modify: `galay-ssl/ssl/SslEngine.cc`
- Modify: `galay-ssl/ssl/SslEngine.h`
- Test: `test/T2-SslLoopbackSmoke.cc`

**Step 1: Protect behavior first**

Run:

```bash
./build/bin/T1-SslSocketTest
./build/bin/T2-SslLoopbackSmoke
```

Expected: both are GREEN before changing internals.

**Step 2: Implement the smallest optimization that matches the profile**

Examples of acceptable changes:
- reuse already-sized cipher buffers instead of re-growing or re-syncing them,
- reduce temporary `Bytes` creation on small-path partial reads,
- collapse duplicated recv/send wakeup transitions when the profile shows scheduler churn.

Use one patch, not a grab-bag.

**Step 3: Re-run correctness and the targeted benchmark**

Run:

```bash
./build/bin/T1-SslSocketTest
./build/bin/T2-SslLoopbackSmoke
./build/bin/B1-SslBenchServer 9447 build/certs/server.crt build/certs/server.key >/tmp/galay-ssl-opt-server.log 2>&1 &
SERVER_PID=$!
sleep 1
./build/bin/B1-SslBenchClient 127.0.0.1 9447 200 500 47 4 | tee /tmp/galay-ssl-small-after-opt.txt
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: correctness remains green and the chosen metric improves or stays flat without regressions.

**Step 4: Re-check the large-payload case**

Run one `65536` payload pass to ensure the small-payload optimization did not hurt throughput.

**Step 5: Commit the optimization**

```bash
git add galay-ssl/async/Awaitable.cc galay-ssl/ssl/SslEngine.cc galay-ssl/ssl/SslEngine.h
git commit -m "perf: optimize top ssl hot path"
```

### Task 8: Build a temporary Go `crypto/tls` comparison harness outside the repo

**Files:**
- Create: `/tmp/galay-ssl-compare/go-ssl-bench/go.mod`
- Create: `/tmp/galay-ssl-compare/go-ssl-bench/main.go`
- Output: `/tmp/galay-ssl-compare/results/go-small.txt`
- Output: `/tmp/galay-ssl-compare/results/go-large.txt`
- Output: `/tmp/galay-ssl-compare/results/go-handshake.txt`

**Step 1: Create the harness skeleton**

Initialize:

```bash
mkdir -p /tmp/galay-ssl-compare/go-ssl-bench /tmp/galay-ssl-compare/results
cd /tmp/galay-ssl-compare/go-ssl-bench
go mod init go-ssl-bench
```

**Step 2: Write one binary with `server` and `client` modes**

Use a single `main.go` that:
- loads `build/certs/server.crt` and `build/certs/server.key`,
- accepts CLI args for `mode`, `host`, `port`, `connections`, `requests`, `payload`,
- uses `tls.Listen` for the server,
- uses `tls.Dial` for the client,
- echoes payload bytes exactly,
- prints `Total requests`, `Total errors`, `Duration`, `Requests/sec`, `Throughput`.

Start from this shape:

```go
switch os.Args[1] {
case "server":
    runServer(certFile, keyFile, port)
case "client":
    runClient(host, port, connections, requests, payload)
default:
    log.Fatal("unknown mode")
}
```

**Step 3: Build and run the Go matrix**

Run:

```bash
go build -o /tmp/galay-ssl-compare/go-ssl-bench/go-ssl-bench .
/tmp/galay-ssl-compare/go-ssl-bench/go-ssl-bench server 9550 build/certs/server.crt build/certs/server.key >/tmp/galay-ssl-compare/go-server.log 2>&1 &
SERVER_PID=$!
sleep 1
/tmp/galay-ssl-compare/go-ssl-bench/go-ssl-bench client 127.0.0.1 9550 200 500 47 | tee /tmp/galay-ssl-compare/results/go-small.txt
/tmp/galay-ssl-compare/go-ssl-bench/go-ssl-bench client 127.0.0.1 9550 10 200 65536 | tee /tmp/galay-ssl-compare/results/go-large.txt
/tmp/galay-ssl-compare/go-ssl-bench/go-ssl-bench client 127.0.0.1 9550 400 1 47 | tee /tmp/galay-ssl-compare/results/go-handshake.txt
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: all three outputs use the same metric names as `B1-SslBenchClient`.

**Step 4: Keep security knobs aligned with the C++ benchmark**

Use the same benchmark posture as `galay-ssl`:
- self-signed test cert,
- client verification disabled unless the C++ run enables it,
- local loopback only.

**Step 5: Do not commit anything**

This harness stays outside the repository.

### Task 9: Build a temporary Rust `tokio` + `rustls` comparison harness outside the repo

**Files:**
- Create: `/tmp/galay-ssl-compare/rustls-bench/Cargo.toml`
- Create: `/tmp/galay-ssl-compare/rustls-bench/src/main.rs`
- Output: `/tmp/galay-ssl-compare/results/rust-small.txt`
- Output: `/tmp/galay-ssl-compare/results/rust-large.txt`
- Output: `/tmp/galay-ssl-compare/results/rust-handshake.txt`

**Step 1: Create the Rust project**

Run:

```bash
mkdir -p /tmp/galay-ssl-compare/rustls-bench/src
cat > /tmp/galay-ssl-compare/rustls-bench/Cargo.toml <<'EOF'
[package]
name = "rustls-bench"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
rustls = "0.23"
rustls-pemfile = "2"
anyhow = "1"
EOF
```

**Step 2: Write one binary with `server` and `client` subcommands**

`src/main.rs` should:
- load the same PEM files used by the C++ benchmark,
- use `TcpListener` + `TlsAcceptor` for server mode,
- use `TcpStream` + `TlsConnector` for client mode,
- accept `connections`, `requests`, `payload`,
- print the same result labels as the C++ and Go harnesses.

Use this structure:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("server") => run_server().await,
        Some("client") => run_client().await,
        _ => anyhow::bail!("unknown mode"),
    }
}
```

**Step 3: Build and run the Rust matrix**

Run:

```bash
cd /tmp/galay-ssl-compare/rustls-bench
cargo build --release
./target/release/rustls-bench server 9560 build/certs/server.crt build/certs/server.key >/tmp/galay-ssl-compare/rust-server.log 2>&1 &
SERVER_PID=$!
sleep 1
./target/release/rustls-bench client 127.0.0.1 9560 200 500 47 | tee /tmp/galay-ssl-compare/results/rust-small.txt
./target/release/rustls-bench client 127.0.0.1 9560 10 200 65536 | tee /tmp/galay-ssl-compare/results/rust-large.txt
./target/release/rustls-bench client 127.0.0.1 9560 400 1 47 | tee /tmp/galay-ssl-compare/results/rust-handshake.txt
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected: output labels line up with the C++ and Go runs for easy diffing.

**Step 4: Keep the runtime simple**

Use straightforward `tokio` tasks and avoid extra pooling, tracing, or metrics dependencies until the first comparable baseline exists.

**Step 5: Do not commit anything**

This harness stays outside the repository.

### Task 10: Compare results, document the gap, and decide whether a second optimization round is justified

**Files:**
- Modify: `docs/05-性能测试.md`
- Create: `docs/plans/2026-03-07-galay-kernel-compat-perf-results.md`
- Check: `/tmp/galay-ssl-baseline-small.txt`
- Check: `/tmp/galay-ssl-baseline-large.txt`
- Check: `/tmp/galay-ssl-baseline-handshake.txt`
- Check: `/tmp/galay-ssl-compare/results/go-small.txt`
- Check: `/tmp/galay-ssl-compare/results/go-large.txt`
- Check: `/tmp/galay-ssl-compare/results/go-handshake.txt`
- Check: `/tmp/galay-ssl-compare/results/rust-small.txt`
- Check: `/tmp/galay-ssl-compare/results/rust-large.txt`
- Check: `/tmp/galay-ssl-compare/results/rust-handshake.txt`

**Step 1: Normalize the matrix**

Create a short comparison table with:
- small payload QPS,
- large payload throughput,
- handshake requests/sec,
- error count.

**Step 2: Write the evidence-backed conclusion**

In `docs/plans/2026-03-07-galay-kernel-compat-perf-results.md`, answer:
- where `galay-ssl` is slower,
- whether the gap tracks OpenSSL, scheduler cost, or local state-machine overhead,
- which exact frame or counter supports that conclusion.

**Step 3: Update the public performance doc only with stable numbers**

Refresh `docs/05-性能测试.md` only if:
- compatibility is restored,
- `errors=0`,
- runs are repeatable enough to quote.

**Step 4: Decide on round two**

Only start another optimization pass if at least one of these is true:
- the same hotspot still dominates after round one,
- Go or Rust clearly wins in a path that `galay-ssl` owns,
- the new data disproves the current benchmark design.

**Step 5: Commit the documentation**

```bash
git add docs/05-性能测试.md docs/plans/2026-03-07-galay-kernel-compat-perf-results.md
git commit -m "docs: capture galay-ssl compatibility and benchmark results"
```
