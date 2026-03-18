# Go TLS Echo Benchmark Server

Minimal TLS echo server used by the cross-language benchmark harness.

Build:

```bash
go build -C benchmark/go-crypto-tls-server -o go-crypto-tls-server .
```

Run:

```bash
./benchmark/go-crypto-tls-server/go-crypto-tls-server 9445 certs/server.crt certs/server.key
```

Contract:

- TLS 1.3 only
- Session tickets disabled
- Echoes exactly the bytes it reads
