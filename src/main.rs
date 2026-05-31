// ======================================================================
// the-server — Hardened multi-protocol test server
//
// Protocols:
//   • HTTP/1.1 + HTTP/2  over TLS 1.3  (TCP :443)
//   • HTTP/3             over QUIC     (UDP :443)
//   • Plaintext HTTP/1.1 redirect      (TCP :80  →  https://…:443)
//   • Tor Onion Service  (ephemeral .onion, via arti-client)
//
// Crypto:
//   • aws-lc-rs (FIPS-grade) via rustls 0.23
//   • Only AES-256-GCM-SHA384  (TLS 1.3)
//   • Key exchange: FIPS Complient only
//   • Self-signed ECDSA P-256 cert (runtime-generated via rcgen)
// ======================================================================

use std::convert::Infallible;
use std::sync::Arc;

use arti_client::config::CfgPath;
use arti_client::{TorClient, TorClientConfig};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use rustls::crypto::aws_lc_rs;
use safelog::DisplayRedacted;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tor_hsservice::config::OnionServiceConfigBuilder;

// h3 and quic_h3 bridge (local module — pure h3 + s2n_quic, no community crate)
mod quic_h3;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// ======================================================================
// AppState — shared state across all protocol handlers
// ======================================================================

/// Shared application state that is passed to every request handler regardless
/// of the originating protocol (HTTPS, HTTP/3, Onion, etc.).
///
/// Use this to hold connection pools, caches, config, or any other cross-cutting
/// concerns that should be available to request handlers.
pub struct AppState {
    pub onion_domain: std::sync::RwLock<String>,
    pub db_placeholder: String,
    pub started_at: std::time::Instant,
}

impl AppState {
    fn new() -> Self {
        Self {
            onion_domain: std::sync::RwLock::new(String::new()),
            db_placeholder: String::from("(no database configured)"),
            started_at: std::time::Instant::now(),
        }
    }
}

// ======================================================================
// Unified Router — single function for ALL protocols
// ======================================================================

/// Protocol-agnostic request representation.
/// This normalizes the different request sources into a common type so the
/// router logic is identical for HTTP/1.1, HTTP/2, HTTP/3, and Onion.
struct IncomingRequest {
    method: Method,
    uri: Uri,
    protocol: &'static str,
}

/// Route an incoming request through the unified handler.
/// Returns (status, headers, body) regardless of transport protocol.
fn router(
    state: &AppState,
    req: &IncomingRequest,
) -> (StatusCode, Vec<(&'static str, String)>, String) {
    let path = req.uri.path();

    match (req.method.clone(), path) {
        // ---- Health / readiness probe ----
        (Method::GET, "/health") => {
            let uptime = state.started_at.elapsed();
            let body = format!(
                "{{\"status\":\"ok\",\"uptime_secs\":{}}}\n",
                uptime.as_secs(),
            );
            (
                StatusCode::OK,
                vec![("Content-Type", "application/json; charset=utf-8".into())],
                body,
            )
        }

        // ---- Info endpoint ----
        (Method::GET, "/info") => {
            let onion = state
                .onion_domain
                .read()
                .map(|s| s.clone())
                .unwrap_or_default();
            let body = format!(
                "Onion      : {}\n\
                 DB Status  : {}\n\
                 Uptime     : {:?}\n\
                 Protocol   : {}\n",
                onion,
                state.db_placeholder,
                state.started_at.elapsed(),
                req.protocol,
            );
            (
                StatusCode::OK,
                vec![("Content-Type", "text/plain; charset=utf-8".into())],
                body,
            )
        }

        // ---- Default / catch-all ----
        (Method::GET, _) | (Method::HEAD, _) => {
            let onion = state
                .onion_domain
                .read()
                .map(|s| s.clone())
                .unwrap_or_default();
            let body = format!(
                "GREETINGS FROM THE SECURE ENCLAVE!\n\
                 \n\
                 Protocol : {}\n\
                 Method   : {}\n\
                 URI      : {}\n\
                 Onion    : {}\n",
                req.protocol, req.method, req.uri, onion,
            );
            (
                StatusCode::OK,
                vec![("Content-Type", "text/plain; charset=utf-8".into())],
                body,
            )
        }

        // ---- Method not allowed ----
        (_, _) => {
            let body = format!("405 Method Not Allowed: {} {}\n", req.method, req.uri);
            (
                StatusCode::METHOD_NOT_ALLOWED,
                vec![("Content-Type", "text/plain; charset=utf-8".into())],
                body,
            )
        }
    }
}

// ======================================================================
// Protocol-specific adapters (thin wrappers that call `router`)
// ======================================================================

/// Adapter for hyper (HTTP/1.1 + HTTP/2 over TLS)
async fn hyper_handler(
    state: Arc<AppState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let proto = match req.version() {
        hyper::Version::HTTP_2 => "HTTP/2",
        _ => "HTTP/1.1",
    };
    let incoming = IncomingRequest {
        method: req.method().clone(),
        uri: req.uri().clone(),
        protocol: proto,
    };
    let (status, headers, body) = router(&state, &incoming);

    let mut builder = Response::builder().status(status);
    builder = builder.header(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    );
    for (k, v) in &headers {
        builder = builder.header(*k, v.as_str());
    }
    Ok(builder.body(Full::new(Bytes::from(body))).unwrap())
}

/// Adapter for plaintext HTTP → HTTPS redirect (port 80)
async fn redirect_to_https(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    let host_no_port = host.split(':').next().unwrap_or(host);
    let is_dev = std::env::var("DEVELOPMENT").unwrap_or_else(|_| "false".to_string()) == "true";
    let tls_port = if is_dev { 5443 } else { 443 };
    let target = format!("https://{}:{}{}", host_no_port, tls_port, req.uri().path());

    Ok(Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header("Location", &target)
        .body(Full::new(Bytes::from(format!("Moved to {}\n", target))))
        .unwrap())
}

// ======================================================================
// TLS crypto policy — AES-256 only, FIPS-grade key exchange
// ======================================================================

fn hardened_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![
            aws_lc_rs::kx_group::SECP256R1MLKEM768,
            // Note - per NIST SP 800-56C Rev. 2, the X25519MLKEM768 is compliant.
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::MLKEM1024,
            aws_lc_rs::kx_group::MLKEM768,
            aws_lc_rs::kx_group::SECP384R1,
            aws_lc_rs::kx_group::SECP256R1,
        ],
        ..aws_lc_rs::default_provider()
    }
}

// ======================================================================
// Self-signed certificate generation (runtime, ephemeral)
// ======================================================================

struct SelfSignedCert {
    cert_pem: String,
    key_pem: String,
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
}

fn generate_self_signed() -> SelfSignedCert {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("failed to generate self-signed certificate");

    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
    );

    SelfSignedCert {
        cert_pem,
        key_pem,
        cert_der,
        key_der,
    }
}

// ======================================================================
// Listener launchers
// ======================================================================

/// 1. HTTPS listener — TCP :443 (HTTP/1.1 + HTTP/2 over TLS 1.3)
fn spawn_https_listener(listener: TcpListener, acceptor: TlsAcceptor, state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            let (tcp_stream, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[tcp]  accept error: {}", e);
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        let err_str = e.to_string();
                        if !err_str.contains("InvalidContentType") {
                            eprintln!("[tls]  handshake failed ({}): {}", peer, e);
                        }
                        return;
                    }
                };
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let state = state.clone();
                let svc = service_fn(move |req| {
                    let state = state.clone();
                    hyper_handler(state, req)
                });
                if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, svc)
                .await
                {
                    eprintln!("[http] connection error ({}): {}", peer, e);
                }
            });
        }
    });
}

/// 2. HTTP/3 listener — UDP :443 (QUIC + h3)
fn spawn_h3_listener(mut quic_server: s2n_quic::Server, state: Arc<AppState>) {
    tokio::spawn(async move {
        while let Some(conn) = quic_server.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                let h3_conn = quic_h3::Connection::new(conn);
                let mut h3_server = match h3::server::Connection::new(h3_conn).await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[h3]   connection setup failed: {}", e);
                        return;
                    }
                };

                loop {
                    match h3_server.accept().await {
                        Ok(Some((req, mut stream))) => {
                            let state = state.clone();
                            tokio::spawn(async move {
                                let incoming = IncomingRequest {
                                    method: req.method().clone(),
                                    uri: req.uri().clone(),
                                    protocol: "HTTP/3",
                                };
                                let (status, headers, body) = router(&state, &incoming);

                                let mut builder =
                                    hyper::Response::builder().status(status.as_u16()).header(
                                        "Strict-Transport-Security",
                                        "max-age=63072000; includeSubDomains",
                                    );
                                for (k, v) in &headers {
                                    builder = builder.header(*k, v.as_str());
                                }
                                let resp = builder.body(()).unwrap();

                                if let Err(e) = stream.send_response(resp).await {
                                    eprintln!("[h3]   send_response error: {}", e);
                                    return;
                                }
                                if let Err(e) = stream.send_data(Bytes::from(body)).await {
                                    eprintln!("[h3]   send_data error: {}", e);
                                    return;
                                }
                                let _ = stream.finish().await;
                            });
                        }
                        Ok(None) => break,
                        Err(e) => {
                            let err_str = e.to_string();
                            if !err_str.contains("application error")
                                && !err_str.contains("ConnectionError")
                            {
                                eprintln!("[h3]   accept error: {}", e);
                            }
                            break;
                        }
                    }
                }
            });
        }
    });
}

/// 3. Plaintext HTTP redirect — TCP :80 → https://..:443
fn spawn_http_redirect(listener: TcpListener) {
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[http] accept error: {}", e);
                    continue;
                }
            };
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = service_fn(redirect_to_https);
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    if !e.is_incomplete_message() {
                        eprintln!("[http] redirect connection error: {}", e);
                    }
                }
            });
        }
    });
}

/// 4. Tor Onion Service listener (ephemeral .onion via arti-client)
async fn spawn_onion_service(state: Arc<AppState>) {
    println!("[tor]  Bootstrapping Tor client...");

    // 1. Force 100% ephemeral state.
    let tor_state_dir = TempDir::new().expect("failed to create ephemeral tor state dir");

    // 2. Extract the path as a String and explicitly construct Arti's CfgPath
    let temp_path_str = tor_state_dir.path().to_string_lossy().into_owned();
    let temp_cfg_path = CfgPath::new(temp_path_str);

    // 3. Sandbox Arti's storage to the volatile directory
    let mut config_builder = TorClientConfig::builder();
    config_builder
        .storage()
        .cache_dir(temp_cfg_path.clone())
        .state_dir(temp_cfg_path);

    let tor_config = config_builder.build().expect("valid tor config");

    let tor_client = match TorClient::create_bootstrapped(tor_config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[tor]  FAILED to bootstrap Tor client: {}", e);
            eprintln!("[tor]  Onion service will NOT be available.");
            return;
        }
    };

    println!("[tor]  Tor client bootstrapped successfully.");

    // 16 bytes gives maximum 32 chars, which is what Tor allows.
    let mut rand_bytes = [0u8; 16];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut rand_bytes)
        .expect("aws-lc-rs RNG failure");

    // Constant-time hex encoding into a zero-allocation stack buffer
    let mut hex_buf = [0u8; 32];
    let random_nickname =
        base16ct::lower::encode_str(&rand_bytes, &mut hex_buf).expect("base16ct encoding failed");

    println!(
        "[tor]  Generated random enclave nickname: {}",
        random_nickname
    );

    // Build the onion service config
    let onion_config = OnionServiceConfigBuilder::default()
        .nickname(random_nickname.parse().expect("valid nickname"))
        .build()
        .expect("onion service config");

    // Launch the ephemeral onion service
    let (onion_svc, rend_requests) = match tor_client.launch_onion_service(onion_config) {
        Ok(Some(result)) => result,
        Ok(None) => {
            eprintln!("[tor]  Onion service is disabled in config.");
            return;
        }
        Err(e) => {
            eprintln!("[tor]  Failed to launch onion service: {}", e);
            return;
        }
    };

    // Print the .onion address
    if let Some(addr) = onion_svc.onion_address() {
        let full_addr = addr.display_unredacted().to_string();
        println!("[tor]  Onion service active: http://{}", full_addr);
        if let Ok(mut lock) = state.onion_domain.write() {
            *lock = full_addr;
        }
    } else {
        println!("[tor]  Onion service launched (address pending descriptor upload)");
    }

    // Process incoming rendezvous requests
    let state_clone = state.clone();
    tokio::spawn(async move {
        // Keep the TempDir alive here. If it drops, the OS immediately
        // shreds the directory, and Arti's async workers will panic on I/O.
        let _keepalive_dir = tor_state_dir;
        let _keepalive_client = tor_client;
        let _keepalive_svc = onion_svc;

        // Use handle_rend_requests to convert RendRequests into StreamRequests
        let mut stream_requests = tor_hsservice::handle_rend_requests(rend_requests);

        while let Some(stream_req) = stream_requests.next().await {
            let state = state_clone.clone();

            tokio::spawn(async move {
                // Accept the stream request to get a DataStream
                let data_stream = match stream_req
                    .accept(tor_cell::relaycell::msg::Connected::new_empty())
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[tor]  stream accept error: {}", e);
                        return;
                    }
                };

                // Serve a simple HTTP/1.1 response over the Tor stream
                let io = hyper_util::rt::TokioIo::new(data_stream);
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let state = state.clone();
                    async move {
                        let incoming = IncomingRequest {
                            method: req.method().clone(),
                            uri: req.uri().clone(),
                            protocol: "Tor Onion (HTTP/1.1)",
                        };
                        let (status, headers, body) = router(&state, &incoming);

                        let mut builder = Response::builder().status(status);
                        for (k, v) in &headers {
                            builder = builder.header(*k, v.as_str());
                        }
                        Ok::<_, Infallible>(builder.body(Full::new(Bytes::from(body))).unwrap())
                    }
                });

                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    if !e.is_incomplete_message() {
                        eprintln!("[tor]  connection error: {}", e);
                    }
                }
            });
        }
    });
}

// ======================================================================
// main — spin up all 4 listeners
// ======================================================================

#[tokio::main]
async fn main() {
    println!("\n=======================================================");
    println!("  THE-SERVER — Hardened Multi-Protocol Enclave Server");
    println!("  Crypto : aws-lc-rs FIPS (AES-256-GCM only)");
    println!("  TLS    : 1.3 only, PQ Key Exchange (ML-KEM)");
    println!("=======================================================\n");

    if let Ok(hash) = std::env::var("LOADER_PAYLOAD_HASH") {
        println!("[info] Payload measurement: {}", hash);
    }

    let is_dev = std::env::var("DEVELOPMENT").unwrap_or_else(|_| "false".to_string()) == "true";
    let tls_port = if is_dev { 5443 } else { 443 };
    let http_port = if is_dev { 5001 } else { 80 };

    if is_dev {
        println!("[info] Running in DEVELOPMENT mode.");
    }

    // ---- Shared state ----
    let state = Arc::new(AppState::new());

    // ---- Generate ephemeral self-signed cert ----
    let certs = generate_self_signed();
    println!("[tls]  Self-signed certificate generated (ECDSA P-256)");

    // ---- Build hardened crypto provider ----
    let provider = Arc::new(hardened_crypto_provider());

    // ---------------------------------------------------------------
    // 1. HTTPS listener — TCP :443
    // ---------------------------------------------------------------
    let mut tls_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 config")
        .with_no_client_auth()
        .with_single_cert(vec![certs.cert_der.clone()], certs.key_der.clone_key())
        .expect("cert/key pair");

    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let https_listener = TcpListener::bind(format!("0.0.0.0:{}", tls_port))
        .await
        .expect("bind https port");
    println!(
        "[tcp]  Listening on 0.0.0.0:{}  (HTTPS — HTTP/1.1 + HTTP/2)",
        tls_port
    );

    spawn_https_listener(https_listener, tls_acceptor, state.clone());

    // ---------------------------------------------------------------
    // 2. HTTP/3 listener — UDP :443
    // ---------------------------------------------------------------
    let quic_tls = s2n_quic::provider::tls::rustls::Server::builder()
        .with_certificate(certs.cert_pem.as_str(), certs.key_pem.as_str())
        .expect("QUIC TLS certificate")
        .with_application_protocols(["h3"].iter())
        .expect("QUIC ALPN")
        .build()
        .expect("QUIC TLS provider");

    let quic_server = s2n_quic::Server::builder()
        .with_tls(quic_tls)
        .expect("QUIC server TLS")
        .with_io(format!("0.0.0.0:{}", tls_port).as_str())
        .expect("QUIC bind")
        .start()
        .expect("QUIC server start");

    println!(
        "[quic] Listening on 0.0.0.0:{}  (HTTP/3 over QUIC)",
        tls_port
    );

    spawn_h3_listener(quic_server, state.clone());

    // ---------------------------------------------------------------
    // 3. Plaintext HTTP redirect — TCP :80
    // ---------------------------------------------------------------
    let http_listener = TcpListener::bind(format!("0.0.0.0:{}", http_port))
        .await
        .expect("bind http port");
    println!(
        "[http] Listening on 0.0.0.0:{}  (plaintext → HTTPS redirect)",
        http_port
    );

    spawn_http_redirect(http_listener);

    // ---------------------------------------------------------------
    // 4. Tor Onion Service (ephemeral)
    // ---------------------------------------------------------------
    if !is_dev {
        spawn_onion_service(state.clone()).await;
    } else {
        println!("[tor]  Onion service disabled in DEVELOPMENT mode.");
    }

    println!("\n[ready] All listeners active.\n");

    // Keep the main task alive forever
    std::future::pending::<()>().await;
}
