use std::convert::Infallible;
use std::sync::Arc;

use arti_client::config::CfgPath;
use arti_client::{TorClient, TorClientConfig};
use bytes::Bytes;
use futures::StreamExt;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use safelog::DisplayRedacted;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_cell::relaycell::msg::End;
use tokio_rustls::TlsAcceptor;

use crate::{
    AppState, IncomingRequest, router,
    connections::crypto::{generate_self_signed, hardened_crypto_provider},
};

pub async fn start(state: Arc<AppState>) {
    println!("[tor]  Bootstrapping Tor client...");

    let tor_state_dir = tempfile::tempdir_in("/dev/shm").expect("failed to create ephemeral tor state dir in RAM");
    let temp_path_str = tor_state_dir.path().to_string_lossy().into_owned();
    let temp_cfg_path = CfgPath::new(temp_path_str);

    let mut config_builder = TorClientConfig::builder();
    config_builder
        .storage()
        .cache_dir(temp_cfg_path.clone())
        .state_dir(temp_cfg_path)
        .permissions()
        .dangerously_trust_everyone()
        .ignore_prefix("/dev/shm");

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

    let mut rand_bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut rand_bytes).unwrap();

    let mut hex_buf = [0u8; 32];
    let random_nickname = base16ct::lower::encode_str(&rand_bytes, &mut hex_buf).expect("base16ct encoding failed");

    println!("[tor]  Generated random enclave nickname: {}", random_nickname);

    let onion_config = OnionServiceConfigBuilder::default()
        .nickname(random_nickname.parse().expect("valid nickname"))
        .build()
        .expect("onion service config");

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

    let onion_domain = if let Some(addr) = onion_svc.onion_address() {
        let full_addr = addr.display_unredacted().to_string();
        println!("[tor]  Onion service active: http://{} and https://{}", full_addr, full_addr);
        full_addr
    } else {
        // Server must panic without onion support.
        panic!("[tor]  Onion service launched (address pending descriptor upload)");
    };

    // Generate a new self-signed certificate explicitly for the Onion HTTPS port
    let onion_certs = generate_self_signed(vec![onion_domain.clone(), "localhost".to_string()]);

    if let Ok(mut data) = state.onion_data.write() {
        data.onion_domain = onion_domain.clone();
        data.onion_https_cert = onion_certs.cert_pem.clone();
    }
    let provider = Arc::new(hardened_crypto_provider());
    let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 config")
        .with_no_client_auth()
        .with_single_cert(vec![onion_certs.cert_der.clone()], onion_certs.key_der.clone_key())
        .expect("onion cert/key pair");

    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let state_clone = state.clone();
    tokio::spawn(async move {
        // Keepalives
        let _keepalive_dir = tor_state_dir;
        let _keepalive_client = tor_client;
        let _keepalive_svc = onion_svc;

        let mut stream_requests = tor_hsservice::handle_rend_requests(rend_requests);

        while let Some(stream_req) = stream_requests.next().await {
            let state = state_clone.clone();
            let onion_domain_clone = onion_domain.clone();
            let tls_acceptor_clone = tls_acceptor.clone();

            tokio::spawn(async move {
                // WORKAROUND: Bypass the unnameable type bug by formatting the request
                // The debug string will look something like: "Begin(Begin { port: 443, ... })"
                let req_str = format!("{:?}", stream_req.request());

                let port = if req_str.contains("port: 443") {
                    443
                } else if req_str.contains("port: 80") {
                    80
                } else {
                    // Reject unsupported ports or DNS Resolve requests
                    let _ = stream_req.reject(End::new_misc()).await;
                    return;
                };

                if port == 80 {
                    let data_stream = match stream_req
                        .accept(tor_cell::relaycell::msg::Connected::new_empty())
                        .await
                    {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    let io = hyper_util::rt::TokioIo::new(data_stream);
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let onion_domain = onion_domain_clone.clone();
                        let state = state.clone();
                        async move {
                            if req.uri().path().starts_with("/v1") {
                                let proto = match req.version() {
                                    hyper::Version::HTTP_2 => "Tor Onion (HTTP/2) [Plaintext]",
                                    _ => "Tor Onion (HTTP/1.1) [Plaintext]",
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
                                for (k, v) in &headers {
                                    builder = builder.header(*k, v.as_str());
                                }
                                Ok::<_, Infallible>(builder.body(body).unwrap())
                            } else {
                                let p_q = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
                                let https_url = format!("https://{}{}", onion_domain, p_q);
                                
                                let resp = Response::builder()
                                    .status(StatusCode::PERMANENT_REDIRECT)
                                    .header(hyper::header::LOCATION, https_url)
                                    .body(crate::routes::full_body(String::new()))
                                    .unwrap();
                                Ok::<_, Infallible>(resp)
                            }
                        }
                    });

                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
                } else if port == 443 {
                    let data_stream = match stream_req
                        .accept(tor_cell::relaycell::msg::Connected::new_empty())
                        .await
                    {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    let tls_stream = match tls_acceptor_clone.accept(data_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[tor-tls] handshake failed: {}", e);
                            return;
                        }
                    };

                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let state = state.clone();
                        async move {
                            let proto = match req.version() {
                                hyper::Version::HTTP_2 => "Tor Onion (HTTP/2)",
                                _ => "Tor Onion (HTTP/1.1)",
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
                            builder = builder.header("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
                            for (k, v) in &headers {
                                builder = builder.header(*k, v.as_str());
                            }
                            Ok::<_, Infallible>(builder.body(body).unwrap())
                        }
                    });

                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, svc)
                    .await;
                }
            });
        }
    });
}
