use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    match rustls_pemfile::private_key(&mut reader)? {
        Some(key) => Ok(key),
        None => Err(io::Error::new(io::ErrorKind::InvalidInput, "no private key found")),
    }
}

async fn run_server(
    port: u16,
    cert_file: &Path,
    key_file: &Path,
    connections: Arc<AtomicU64>,
    bytes_recv: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
) -> io::Result<()> {
    let certs = load_certs(cert_file)?;
    let key = load_private_key(key_file)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("tls config: {e}")))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("Starting Rust SSL benchmark server on port {port}");

    while running.load(Ordering::Relaxed) {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let connections = Arc::clone(&connections);
        let bytes_recv = Arc::clone(&bytes_recv);
        let bytes_sent = Arc::clone(&bytes_sent);
        let running = Arc::clone(&running);

        tokio::spawn(async move {
            let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                return;
            };
            connections.fetch_add(1, Ordering::Relaxed);
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                let n = match tls_stream.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                bytes_recv.fetch_add(n as u64, Ordering::Relaxed);
                if tls_stream.write_all(&buffer[..n]).await.is_err() {
                    break;
                }
                bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            let _ = tls_stream.shutdown().await;
        });
    }

    Ok(())
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
    if args.len() < 4 {
        eprintln!("usage: rust_ssl_bench_server <port> <cert_file> <key_file> [backlog] [worker_count]");
        return Ok(());
    }

    let port = parse_u16_arg(&args, 1, 8443);
    let cert_file = Path::new(&args[2]).to_path_buf();
    let key_file = Path::new(&args[3]).to_path_buf();
    let worker_count = parse_usize_arg(&args, 5, 1).max(1);

    let runtime = Builder::new_multi_thread()
        .worker_threads(worker_count)
        .enable_all()
        .build()?;

    let connections = Arc::new(AtomicU64::new(0));
    let bytes_recv = Arc::new(AtomicU64::new(0));
    let bytes_sent = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    let running_for_signal = Arc::clone(&running);
    runtime.spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        running_for_signal.store(false, Ordering::Relaxed);
    });

    let server_result = runtime.block_on(run_server(
        port,
        &cert_file,
        &key_file,
        Arc::clone(&connections),
        Arc::clone(&bytes_recv),
        Arc::clone(&bytes_sent),
        Arc::clone(&running),
    ));

    std::thread::sleep(Duration::from_millis(100));
    println!();
    println!("Final stats:");
    println!("Total connections: {}", connections.load(Ordering::Relaxed));
    println!("Total bytes received: {}", bytes_recv.load(Ordering::Relaxed));
    println!("Total bytes sent: {}", bytes_sent.load(Ordering::Relaxed));

    server_result
}
