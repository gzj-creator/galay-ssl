use std::env;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;

fn usage(program: &str) -> String {
    format!("usage: {program} <port> <cert_file> <key_file> [backlog]")
}

fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let pkcs8 = {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        rustls_pemfile::pkcs8_private_keys(&mut reader).collect::<io::Result<Vec<_>>>()?
    };
    if let Some(key) = pkcs8.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    let rsa = {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        rustls_pemfile::rsa_private_keys(&mut reader).collect::<io::Result<Vec<_>>>()?
    };
    if let Some(key) = rsa.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    let sec1 = {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        rustls_pemfile::ec_private_keys(&mut reader).collect::<io::Result<Vec<_>>>()?
    };
    if let Some(key) = sec1.into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no supported private key found",
    ))
}

fn build_tls_acceptor(cert_file: &str, key_file: &str) -> io::Result<TlsAcceptor> {
    let certs = load_certs(cert_file)?;
    let key = load_private_key(key_file)?;

    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn bind_listener(port: u16, backlog: i32) -> io::Result<TcpListener> {
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    socket.listen(backlog)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

async fn handle_client(acceptor: TlsAcceptor, socket: TcpStream) -> io::Result<()> {
    let mut stream = acceptor
        .accept(socket)
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::ConnectionAborted, err))?;

    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        stream.write_all(&buffer[..read]).await?;
    }

    let _ = stream.shutdown().await;
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("{}", usage(&args[0]));
        return ExitCode::from(1);
    }

    let port = match args[1].parse::<u16>() {
        Ok(port) => port,
        Err(err) => {
            eprintln!("invalid port '{}': {err}", args[1]);
            return ExitCode::from(1);
        }
    };
    let cert_file = &args[2];
    let key_file = &args[3];
    let backlog = match args.get(4) {
        Some(value) => match value.parse::<i32>() {
            Ok(parsed) if parsed >= 128 => parsed,
            Ok(_) => 128,
            Err(err) => {
                eprintln!("invalid backlog '{}': {err}", value);
                return ExitCode::from(1);
            }
        },
        None => 4096,
    };

    let acceptor = match build_tls_acceptor(cert_file, key_file) {
        Ok(acceptor) => acceptor,
        Err(err) => {
            eprintln!("tls config error: {err}");
            return ExitCode::from(1);
        }
    };

    let listener = match bind_listener(port, backlog) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("listen error: {err}");
            return ExitCode::from(1);
        }
    };

    println!("Rust TLS bench server listening on port {port}");

    loop {
        let (socket, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                eprintln!("accept error: {err}");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(acceptor, socket).await {
                eprintln!("client error: {err}");
            }
        });
    }
}
