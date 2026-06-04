use std::convert::Infallible;
use std::sync::Arc;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::{AppState, IncomingRequest, router};
use crate::quic_h3;
use crate::connections::crypto::{generate_self_signed, hardened_crypto_provider};

// ======================================================================
// Protocol-specific adapters (thin wrappers that call `router`)
// ======================================================================

/// Adapter for hyper (HTTP/1.1 + HTTP/2 over TLS)
pub async fn hyper_handler(
    state: Arc<AppState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, Infallible>>, Infallible> {
    let proto = match req.version() {
        hyper::Version::HTTP_2 => "HTTP/2",
        _ => "HTTP/1.1",
    };
    let (parts, incoming_body) = req.into_parts();
    let body_bytes = match http_body_util::BodyExt::collect(incoming_body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };

    let mut header_map = std::collections::HashMap::new();
    for (k, v) in parts.headers.iter() {
        if let Ok(val) = v.to_str() {
            header_map.insert(k.as_str().to_lowercase(), val.to_string());
        }
    }

    let incoming = IncomingRequest {
        method: parts.method,
        uri: parts.uri,
        protocol: proto,
        headers: header_map,
        body: body_bytes,
    };
    let (status, headers, body) = router(&state, &incoming).await;

    let mut builder = Response::builder().status(status);
    builder = builder.header(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    )
    .header("Access-Control-Allow-Origin", "*")
    .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    .header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-KX-Algo, X-Server-Ticket, X-Client-Pub-Key, X-E2EE-Enabled, X-CSRF-Token, X-NearAI-E2EE-Enabled, X-NearAI-Client-Pub-Key");
    for (k, v) in &headers {
        builder = builder.header(*k, v.as_str());
    }
    Ok(builder.body(body).unwrap())
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
    let is_dev = cfg!(feature = "development");
    let tls_port = if is_dev { 5443 } else { 443 };
    let target = format!("https://{}:{}{}", host_no_port, tls_port, req.uri().path());

    Ok(Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header("Location", &target)
        .body(Full::new(Bytes::from(format!("Moved to {}\n", target))))
        .unwrap())
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
                                let (parts, _) = req.into_parts();
                                let mut body_bytes = Vec::new();
                                while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                    use bytes::Buf;
                                    while chunk.has_remaining() {
                                        let c = chunk.chunk();
                                        body_bytes.extend_from_slice(c);
                                        chunk.advance(c.len());
                                    }
                                }

                                let mut header_map = std::collections::HashMap::new();
                                for (k, v) in parts.headers.iter() {
                                    if let Ok(val) = v.to_str() {
                                        header_map.insert(k.as_str().to_lowercase(), val.to_string());
                                    }
                                }

                                let incoming = IncomingRequest {
                                    method: parts.method,
                                    uri: parts.uri,
                                    protocol: "HTTP/3",
                                    headers: header_map,
                                    body: Bytes::from(body_bytes),
                                };
                                let (status, headers, mut body_stream) = router(&state, &incoming).await;

                                let mut builder =
                                    hyper::Response::builder().status(status.as_u16())
                                        .header(
                                            "Strict-Transport-Security",
                                            "max-age=63072000; includeSubDomains",
                                        )
                                        .header("Access-Control-Allow-Origin", "*")
                                        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                                        .header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-KX-Algo, X-Server-Ticket, X-Client-Pub-Key, X-E2EE-Enabled, X-NearAI-E2EE-Enabled, X-NearAI-Client-Pub-Key");
                                for (k, v) in &headers {
                                    builder = builder.header(*k, v.as_str());
                                }
                                let resp = builder.body(()).unwrap();

                                if let Err(e) = stream.send_response(resp).await {
                                    eprintln!("[h3]   send_response error: {}", e);
                                    return;
                                }

                                use http_body_util::BodyExt;
                                while let Some(frame_res) = body_stream.frame().await {
                                    match frame_res {
                                        Ok(frame) => {
                                            if let Some(chunk) = frame.data_ref() {
                                                if let Err(e) = stream.send_data(chunk.clone()).await {
                                                    eprintln!("[h3]   send_data error: {}", e);
                                                    return;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("[h3]   stream frame error: {:?}", e);
                                            break;
                                        }
                                    }
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

/// 3. Plaintext HTTP (TCP :5001) - Serves API directly in Development, otherwise redirects to HTTPS
fn spawn_http(listener: TcpListener, state: Arc<AppState>) {
    let is_dev = cfg!(feature = "development");
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[http] accept error: {}", e);
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                if is_dev {
                    // Serve API directly in plaintext for localhost development to bypass self-signed cert errors
                    let svc = service_fn(move |req| {
                        let state = state.clone();
                        hyper_handler(state, req)
                    });
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await
                    {
                        if !e.is_incomplete_message() {
                            eprintln!("[http] dev connection error: {}", e);
                        }
                    }
                } else {
                    // Redirect to HTTPS in production
                    let svc = service_fn(redirect_to_https);
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await
                    {
                        if !e.is_incomplete_message() {
                            eprintln!("[http] redirect connection error: {}", e);
                        }
                    }
                }
            });
        }
    });
}

pub async fn start_all(state: Arc<AppState>, tls_port: u16, http_port: u16) {
    let certs = generate_self_signed(vec!["localhost".to_string()]);
    println!("[tls]  Self-signed certificate generated (ECDSA P-256)");

    let provider = Arc::new(hardened_crypto_provider());

    // 1. HTTPS listener
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

    // 2. HTTP/3 listener
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

    // 3. Plaintext HTTP redirect
    let http_listener = TcpListener::bind(format!("0.0.0.0:{}", http_port))
        .await
        .expect("bind http port");
    println!(
        "[http] Listening on 0.0.0.0:{}  (plaintext → API / HTTPS redirect)",
        http_port
    );

    spawn_http(http_listener, state.clone());
}
