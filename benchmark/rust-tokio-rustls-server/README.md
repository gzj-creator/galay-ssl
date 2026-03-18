# Rust TLS Echo Benchmark Server

Minimal TLS echo server used by the cross-language benchmark harness.

Build:

```bash
cargo build --manifest-path benchmark/rust-tokio-rustls-server/Cargo.toml --release
```

Run:

```bash
./benchmark/rust-tokio-rustls-server/target/release/rust-tokio-rustls-server 9444 certs/server.crt certs/server.key
```

Contract:

- TLS 1.3 only
- Session cache / resumption disabled
- Echoes exactly the bytes it reads
