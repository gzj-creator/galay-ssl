use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Builder;
use tokio::time::{Duration, sleep};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    errors: AtomicU64,
    connect_fail: AtomicU64,
    handshake_fail: AtomicU64,
    send_fail: AtomicU64,
    recv_fail: AtomicU64,
    peer_closed: AtomicU64,
}

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader).collect()
}

fn build_tls_config(ca_cert_path: &Path) -> io::Result<ClientConfig> {
    let certs = load_certs(ca_cert_path)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("add root cert: {e}")))?;
    }

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    let _ = roots;
    Ok(config)
}

async fn run_connection(
    host: String,
    port: u16,
    requests_per_conn: usize,
    payload: Arc<Vec<u8>>,
    connect_retries: usize,
    connector: TlsConnector,
    metrics: Arc<Metrics>,
) {
    let server_name = match ServerName::try_from(host.clone()) {
        Ok(name) => name.to_owned(),
        Err(_) => {
            metrics.errors.fetch_add(1, Ordering::Relaxed);
            metrics.handshake_fail.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let mut tls_stream_opt = None;
    for attempt in 0..connect_retries {
        let stream = match TcpStream::connect((host.as_str(), port)).await {
            Ok(stream) => stream,
            Err(_) => {
                if attempt + 1 == connect_retries {
                    metrics.errors.fetch_add(1, Ordering::Relaxed);
                    metrics.connect_fail.fetch_add(1, Ordering::Relaxed);
                } else {
                    sleep(Duration::from_millis(5)).await;
                }
                continue;
            }
        };

        match connector.connect(server_name.clone(), stream).await {
            Ok(tls_stream) => {
                tls_stream_opt = Some(tls_stream);
                break;
            }
            Err(_) => {
                if attempt + 1 == connect_retries {
                    metrics.errors.fetch_add(1, Ordering::Relaxed);
                    metrics.handshake_fail.fetch_add(1, Ordering::Relaxed);
                } else {
                    sleep(Duration::from_millis(5)).await;
                }
            }
        }
    }

    let Some(mut tls_stream) = tls_stream_opt else {
        return;
    };

    let mut recv_buf = vec![0_u8; payload.len().min(64 * 1024)];
    for _ in 0..requests_per_conn {
        if tls_stream.write_all(payload.as_slice()).await.is_err() {
            metrics.errors.fetch_add(1, Ordering::Relaxed);
            metrics.send_fail.fetch_add(1, Ordering::Relaxed);
            break;
        }
        metrics
            .bytes_sent
            .fetch_add(payload.len() as u64, Ordering::Relaxed);

        let mut remaining = payload.len();
        let mut recv_failed = false;
        let mut loops = 0usize;
        while remaining > 0 {
            loops += 1;
            if loops > 200_000 {
                recv_failed = true;
                break;
            }

            let recv_len = remaining.min(recv_buf.len());
            match tls_stream.read(&mut recv_buf[..recv_len]).await {
                Ok(0) => {
                    metrics.peer_closed.fetch_add(1, Ordering::Relaxed);
                    recv_failed = true;
                    break;
                }
                Ok(n) => {
                    remaining -= n;
                    metrics.bytes_recv.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(_) => {
                    metrics.recv_fail.fetch_add(1, Ordering::Relaxed);
                    recv_failed = true;
                    break;
                }
            }
        }

        if recv_failed || remaining != 0 {
            metrics.errors.fetch_add(1, Ordering::Relaxed);
            break;
        }

        metrics.requests.fetch_add(1, Ordering::Relaxed);
    }

    let _ = tls_stream.shutdown().await;
}

fn parse_u16_arg(args: &[String], idx: usize, default: u16) -> u16 {
    args.get(idx)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(default)
}

fn parse_usize_arg(args: &[String], idx: usize, default: usize) -> usize {
    args.get(idx)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "usage: rust_ssl_bench_client <host> <port> <connections> <requests_per_conn> [payload_bytes] [threads] [connect_retries] [ca_cert]"
        );
        return Ok(());
    }

    let host = args[1].clone();
    let port = parse_u16_arg(&args, 2, 8443);
    let connections = parse_usize_arg(&args, 3, 1);
    let requests_per_conn = parse_usize_arg(&args, 4, 100);
    let payload_bytes = parse_usize_arg(&args, 5, 47).max(1);
    let threads = parse_usize_arg(&args, 6, 1).max(1);
    let connect_retries = parse_usize_arg(&args, 7, 3).max(1);
    let ca_cert = args
        .get(8)
        .map(|s| Path::new(s).to_path_buf())
        .unwrap_or_else(|| Path::new("certs/ca.crt").to_path_buf());

    let runtime = Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;

    let start = Instant::now();
    let metrics = Arc::new(Metrics::default());
    let payload = Arc::new(vec![b'x'; payload_bytes]);
    let tls_config = build_tls_config(&ca_cert)?;
    let connector = TlsConnector::from(Arc::new(tls_config));

    runtime.block_on(async {
        let mut handles = Vec::with_capacity(connections);
        for _ in 0..connections {
            let metrics = Arc::clone(&metrics);
            let payload = Arc::clone(&payload);
            let connector = connector.clone();
            let host = host.clone();
            handles.push(tokio::spawn(async move {
                run_connection(
                    host,
                    port,
                    requests_per_conn,
                    payload,
                    connect_retries,
                    connector,
                    metrics,
                )
                .await;
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }
    });

    let duration = start.elapsed();
    let duration_ms = duration.as_millis() as f64;
    let requests = metrics.requests.load(Ordering::Relaxed);
    let bytes_sent = metrics.bytes_sent.load(Ordering::Relaxed);
    let bytes_recv = metrics.bytes_recv.load(Ordering::Relaxed);
    let errors = metrics.errors.load(Ordering::Relaxed);

    println!();
    println!("Benchmark Results:");
    println!("==================");
    println!("Connections: {}", connections);
    println!("Requests per connection: {}", requests_per_conn);
    println!("Payload bytes: {}", payload_bytes);
    println!("Threads: {}", threads);
    println!("Total requests: {}", requests);
    println!("Total errors: {}", errors);
    if errors > 0 {
        println!(
            "Error breakdown: connect={} handshake={} send={} recv={} peer_closed={}",
            metrics.connect_fail.load(Ordering::Relaxed),
            metrics.handshake_fail.load(Ordering::Relaxed),
            metrics.send_fail.load(Ordering::Relaxed),
            metrics.recv_fail.load(Ordering::Relaxed),
            metrics.peer_closed.load(Ordering::Relaxed)
        );
    }
    println!("Total bytes sent: {}", bytes_sent);
    println!("Total bytes received: {}", bytes_recv);
    println!("Duration: {} ms", duration_ms.round() as u64);

    if duration_ms > 0.0 {
        let rps = (requests as f64) * 1000.0 / duration_ms;
        let throughput =
            ((bytes_sent + bytes_recv) as f64) / 1024.0 / 1024.0 * 1000.0 / duration_ms;
        println!("Requests/sec: {}", rps);
        println!("Throughput: {} MB/s", throughput);
    }

    Ok(())
}
