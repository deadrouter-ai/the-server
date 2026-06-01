use crate::time::parse_http_date;
use reqwest::dns::{Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use aws_lc_rs::agreement;
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;

#[derive(Clone)]
#[allow(dead_code)]
struct DnscryptCert {
    resolver_pk: [u8; 32],
    client_magic: [u8; 8],
    serial: u32,
    ts_start: u32,
    ts_end: u32,
}

#[derive(Clone)]
struct DnscryptClientState {
    resolver_ip: SocketAddr,
    client_pk_bytes: [u8; 32],
    client_magic: [u8; 8],
    shared_key: [u8; 32],
    ts_end: u32,
}

struct HardcodedResolver {
    ip: SocketAddr,
    provider_name: &'static str,
    provider_pk: [u8; 32],
}

const HARDCODED_RESOLVERS: &[HardcodedResolver] = &[
    HardcodedResolver {
        ip: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 8443),
        provider_name: "2.dnscrypt-cert.quad9.net",
        provider_pk: [
            0x67, 0xc8, 0x47, 0xb8, 0xc8, 0x75, 0x8c, 0xd1,
            0x20, 0x24, 0x55, 0x43, 0xbe, 0x75, 0x67, 0x46,
            0xdf, 0x34, 0xdf, 0x1d, 0x84, 0xc0, 0x0b, 0x8c,
            0x47, 0x03, 0x68, 0xdf, 0x82, 0x1d, 0x86, 0x3e,
        ],
    },
    HardcodedResolver {
        ip: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), 8443),
        provider_name: "2.dnscrypt-cert.quad9.net",
        provider_pk: [
            0x67, 0xc8, 0x47, 0xb8, 0xc8, 0x75, 0x8c, 0xd1,
            0x20, 0x24, 0x55, 0x43, 0xbe, 0x75, 0x67, 0x46,
            0xdf, 0x34, 0xdf, 0x1d, 0x84, 0xc0, 0x0b, 0x8c,
            0x47, 0x03, 0x68, 0xdf, 0x82, 0x1d, 0x86, 0x3e,
        ],
    },
    HardcodedResolver {
        ip: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 9)), 8443),
        provider_name: "2.dnscrypt-cert.quad9.net",
        provider_pk: [
            0x67, 0xc8, 0x47, 0xb8, 0xc8, 0x75, 0x8c, 0xd1,
            0x20, 0x24, 0x55, 0x43, 0xbe, 0x75, 0x67, 0x46,
            0xdf, 0x34, 0xdf, 0x1d, 0x84, 0xc0, 0x0b, 0x8c,
            0x47, 0x03, 0x68, 0xdf, 0x82, 0x1d, 0x86, 0x3e,
        ],
    },
];

fn run_hchacha20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    use chacha20::{hchacha, R20};
    let out = hchacha::<R20>(&(*key).into(), &(*input).into());
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

fn verify_cert(cert: &[u8], provider_pk: &[u8; 32]) -> Option<DnscryptCert> {
    if cert.len() < 124 {
        return None;
    }
    if &cert[0..4] != b"DNSC" {
        return None;
    }
    if cert[4..6] != [0x00, 0x02] {
        return None;
    }
    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
    let pk = UnparsedPublicKey::new(&ED25519, provider_pk);
    if pk.verify(&cert[72..], &cert[8..72]).is_err() {
        println!("[DNS] Certificate signature verification failed");
        return None;
    }

    let mut resolver_pk = [0u8; 32];
    resolver_pk.copy_from_slice(&cert[72..104]);

    let mut client_magic = [0u8; 8];
    client_magic.copy_from_slice(&cert[104..112]);

    let serial = u32::from_be_bytes(cert[112..116].try_into().ok()?);
    let ts_start = u32::from_be_bytes(cert[116..120].try_into().ok()?);
    let ts_end = u32::from_be_bytes(cert[120..124].try_into().ok()?);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now > 1700000000 {
        if now < ts_start as u64 || now > ts_end as u64 {
            println!(
                "[DNS] Certificate expired or not yet valid (now: {}, start: {}, end: {})",
                now, ts_start, ts_end
            );
            return None;
        }
    }

    Some(DnscryptCert {
        resolver_pk,
        client_magic,
        serial,
        ts_start,
        ts_end,
    })
}

fn xchacha20_djb_poly1305_encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = XChaCha20::new(key.into(), nonce.into());

    // 1. Generate the Poly1305 key from the first 32 bytes of the stream
    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);

    // 2. Encrypt the plaintext in place (the cipher automatically continues from byte 32)
    let mut ciphertext = plaintext.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    // 3. Compute the unpadded MAC over just the ciphertext
    let tag = Poly1305::new(&poly_key.into()).compute_unpadded(&ciphertext);

    // 4. Assemble: Tag || Ciphertext
    let mut result = Vec::with_capacity(16 + ciphertext.len());
    result.extend_from_slice(&tag[..]);
    result.extend_from_slice(&ciphertext);
    
    result
}

fn xchacha20_djb_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, String> {
    if ciphertext_with_tag.len() < 16 {
        return Err("Ciphertext too short".to_string());
    }
    let (tag, ciphertext) = ciphertext_with_tag.split_at(16);

    let mut cipher = XChaCha20::new(key.into(), nonce.into());

    // 1. Extract the Poly1305 key
    let mut poly_key = [0u8; 32];
    cipher.apply_keystream(&mut poly_key);

    // 2. Verify the tag
    let computed_tag = Poly1305::new(&poly_key.into()).compute_unpadded(ciphertext);

    if aws_lc_rs::constant_time::verify_slices_are_equal(&computed_tag[..], tag).is_err() {
        return Err("Poly1305 authentication failed".to_string());
    }

    // 3. Decrypt in place (the cipher automatically continues from byte 32)
    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);
    
    Ok(plaintext)
}

fn pad_query(query: &[u8], min_len: usize) -> Vec<u8> {
    let mut padded = query.to_vec();
    padded.push(0x80);
    let mut target_len = padded.len();
    if target_len < min_len {
        target_len = min_len;
    }
    if target_len % 64 != 0 {
        target_len = ((target_len / 64) + 1) * 64;
    }
    padded.resize(target_len, 0x00);
    padded
}

fn unpad_response(decrypted: &[u8]) -> Result<Vec<u8>, String> {
    let mut end = decrypted.len();
    while end > 0 && decrypted[end - 1] == 0x00 {
        end -= 1;
    }
    if end == 0 || decrypted[end - 1] != 0x80 {
        return Err("Invalid ISO/IEC 7816-4 padding".to_string());
    }
    Ok(decrypted[..end - 1].to_vec())
}

async fn send_dns_query_udp(resolver_ip: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

    let mut buf = vec![0u8; 4096];
    for attempt in 1..=2 {
        if let Err(e) = socket.send_to(query, resolver_ip).await {
            if attempt == 2 {
                return Err(format!("UDP send failed: {}", e));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        match timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                return Ok(buf[..n].to_vec());
            }
            Ok(Err(e)) => {
                if attempt == 2 {
                    return Err(format!("UDP recv failed: {}", e));
                }
            }
            Err(_) => {
                if attempt == 2 {
                    return Err("UDP query timed out".to_string());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err("UDP query failed".to_string())
}

async fn send_dns_query_tcp(resolver_ip: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(resolver_ip))
        .await
        .map_err(|_| "TCP connection timeout".to_string())?
        .map_err(|e| format!("TCP connect failed: {}", e))?;

    let len_prefix = (query.len() as u16).to_be_bytes();
    stream
        .write_all(&len_prefix)
        .await
        .map_err(|e| format!("TCP write len failed: {}", e))?;
    stream
        .write_all(query)
        .await
        .map_err(|e| format!("TCP write data failed: {}", e))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("TCP read len failed: {}", e))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .await
        .map_err(|e| format!("TCP read data failed: {}", e))?;

    Ok(resp_buf)
}

async fn send_dns_query(
    resolver_ip: SocketAddr,
    query: &[u8],
    force_tcp: bool,
) -> Result<Vec<u8>, String> {
    if force_tcp {
        send_dns_query_tcp(resolver_ip, query).await
    } else {
        match send_dns_query_udp(resolver_ip, query).await {
            Ok(resp) => {
                let is_dnscrypt = resp.len() >= 8 && &resp[0..8] == &[0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
                if !is_dnscrypt && resp.len() >= 3 && (resp[2] & 0x02 != 0) {
                    println!("[DNS] UDP response truncated. Retrying over TCP...");
                    send_dns_query_tcp(resolver_ip, query).await
                } else {
                    Ok(resp)
                }
            }
            Err(e) => {
                println!("[DNS] UDP query failed: {}. Retrying over TCP...", e);
                send_dns_query_tcp(resolver_ip, query).await
            }
        }
    }
}

fn build_txt_record_query(domain: &str) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&[
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]);
    query
}

fn parse_txt_response(data: &[u8]) -> Vec<Vec<u8>> {
    let mut results = Vec::new();
    if data.len() < 12 {
        return results;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let mut offset = 12;

    while offset < data.len() && data[offset] != 0 {
        if (data[offset] & 0xC0) == 0xC0 {
            offset += 2;
            break;
        } else {
            offset += data[offset] as usize + 1;
        }
    }
    if offset < data.len() && data[offset] == 0 {
        offset += 1;
    }
    offset += 4;

    for _ in 0..ancount {
        if offset >= data.len() {
            break;
        }
        if offset + 2 > data.len() {
            break;
        }
        if (data[offset] & 0xC0) == 0xC0 {
            offset += 2;
        } else {
            while offset < data.len() && data[offset] != 0 {
                if (data[offset] & 0xC0) == 0xC0 {
                    offset += 2;
                    break;
                }
                offset += data[offset] as usize + 1;
            }
            if offset < data.len() && data[offset] == 0 {
                offset += 1;
            }
        }

        if offset + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            break;
        }

        if rtype == 16 {
            let mut txt_data = Vec::new();
            let mut i = 0;
            let rdata = &data[offset..offset + rdlength];
            while i < rdata.len() {
                let chunk_len = rdata[i] as usize;
                if i + 1 + chunk_len > rdata.len() {
                    break;
                }
                txt_data.extend_from_slice(&rdata[i + 1..i + 1 + chunk_len]);
                i += 1 + chunk_len;
            }
            if !txt_data.is_empty() {
                results.push(txt_data);
            }
        }
        offset += rdlength;
    }
    results
}

async fn establish_dnscrypt_session() -> Result<DnscryptClientState, String> {
    let mut errors = Vec::new();
    for resolver in HARDCODED_RESOLVERS {
        println!(
            "[DNS] Fetching DNSCrypt certificate from provider {} at {}...",
            resolver.provider_name, resolver.ip
        );
        let txt_query = build_txt_record_query(resolver.provider_name);
        match send_dns_query(resolver.ip, &txt_query, false).await {
            Ok(resp_data) => {
                let certs_raw = parse_txt_response(&resp_data);
                let mut best_cert: Option<DnscryptCert> = None;
                for cert_raw in certs_raw {
                    if let Some(cert) = verify_cert(&cert_raw, &resolver.provider_pk) {
                        if let Some(ref current_best) = best_cert {
                            if cert.serial > current_best.serial {
                                best_cert = Some(cert);
                            }
                        } else {
                            best_cert = Some(cert);
                        }
                    }
                }
                if let Some(cert) = best_cert {
                    println!(
                        "[DNS] Verified DNSCrypt cert (serial: {}) from resolver {}",
                        cert.serial, resolver.ip
                    );

                    let rng = aws_lc_rs::rand::SystemRandom::new();
                    let client_sk = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
                        .map_err(|e| format!("Failed to generate client private key: {:?}", e))?;

                    let client_pk = client_sk.compute_public_key()
                        .map_err(|e| format!("Failed to compute client public key: {:?}", e))?;

                    let mut client_pk_bytes = [0u8; 32];
                    client_pk_bytes.copy_from_slice(client_pk.as_ref());

                    let peer_pk =
                        agreement::UnparsedPublicKey::new(&agreement::X25519, &cert.resolver_pk);
                    let mut raw_shared_secret = [0u8; 32];
                    agreement::agree_ephemeral(
                        client_sk,
                        &peer_pk,
                        aws_lc_rs::error::Unspecified,
                        |secret| {
                            if secret.len() == 32 {
                                raw_shared_secret.copy_from_slice(secret);
                                Ok(())
                            } else {
                                Err(aws_lc_rs::error::Unspecified)
                            }
                        },
                    )
                    .map_err(|e| format!("X25519 agreement failed: {:?}", e))?;

                    let shared_key = run_hchacha20(&raw_shared_secret, &[0u8; 16]);

                    return Ok(DnscryptClientState {
                        resolver_ip: resolver.ip,
                        client_pk_bytes,
                        client_magic: cert.client_magic,
                        shared_key,
                        ts_end: cert.ts_end,
                    });
                } else {
                    let err_msg = format!("No valid certs found for resolver {}", resolver.ip);
                    println!("[DNS] {}", err_msg);
                    errors.push(err_msg);
                }
            }
            Err(e) => {
                let err_msg = format!("Failed to query cert from {}: {}", resolver.ip, e);
                println!("[DNS] {}", err_msg);
                errors.push(err_msg);
            }
        }
    }
    Err(format!(
        "Failed to establish DNSCrypt session: {}",
        errors.join("; ")
    ))
}

pub struct CustomDnscryptResolver {
    session: std::sync::Arc<tokio::sync::Mutex<Option<DnscryptClientState>>>,
}

impl CustomDnscryptResolver {
    pub fn new() -> Self {
        Self {
            session: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    async fn get_or_establish_session(&self) -> Result<DnscryptClientState, String> {
        let mut lock = self.session.lock().await;
        if let Some(ref session) = *lock {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now < session.ts_end as u64 {
                return Ok(session.clone());
            }
            println!("[DNS] Cached DNSCrypt certificate expired, establishing a new session...");
        }

        let new_session = establish_dnscrypt_session().await?;
        *lock = Some(new_session.clone());
        Ok(new_session)
    }

    fn clone_resolver(&self) -> Self {
        Self {
            session: self.session.clone(),
        }
    }
}

impl Resolve for CustomDnscryptResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let domain = name.as_str().to_string();
        let resolver = self.clone_resolver();

        Box::pin(async move {
            println!("[DNS] Resolving {} via DNSCrypt...", domain);
            let session = resolver
                .get_or_establish_session()
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    println!("[DNS] Failed to get/establish DNSCrypt session: {:?}", e);
                    Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))
                })?;

            let ip = resolve_domain_via_dnscrypt_session(&session, &domain)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    println!("[DNS] DNSCrypt resolution failed: {:?}", e);
                    Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, e))
                })?;

            println!("[DNS] Resolved {} -> {}", domain, ip);
            let addrs: Box<dyn Iterator<Item = SocketAddr> + Send> =
                Box::new(std::iter::once(SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

pub fn build_a_record_query(domain: &str) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&[
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    query
}

pub fn parse_dns_response(data: &[u8]) -> Option<IpAddr> {
    if data.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let mut offset = 12;

    while offset < data.len() && data[offset] != 0 {
        if (data[offset] & 0xC0) == 0xC0 {
            offset += 2;
            break;
        } else {
            offset += data[offset] as usize + 1;
        }
    }
    if offset < data.len() && data[offset] == 0 {
        offset += 1;
    }
    offset += 4;

    for _ in 0..ancount {
        if offset + 12 > data.len() {
            break;
        }
        if (data[offset] & 0xC0) == 0xC0 {
            offset += 2;
        } else {
            while offset < data.len() && data[offset] != 0 {
                if (data[offset] & 0xC0) == 0xC0 {
                    offset += 2;
                    break;
                }
                offset += data[offset] as usize + 1;
            }
            if offset < data.len() && data[offset] == 0 {
                offset += 1;
            }
        }
        if offset + 10 > data.len() {
            break;
        }
        let atype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if atype == 1 && rdlength == 4 && offset + 4 <= data.len() {
            return Some(IpAddr::V4(Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            )));
        }
        offset += rdlength;
    }
    None
}

async fn resolve_domain_via_dnscrypt_session(
    session: &DnscryptClientState,
    domain: &str,
) -> Result<IpAddr, String> {
    let client_query = build_a_record_query(domain);
    let padded_query = pad_query(&client_query, 1024);

    let mut client_nonce = [0u8; 12];
    aws_lc_rs::rand::fill(&mut client_nonce)
        .map_err(|e| format!("Entropy read failed: {:?}", e))?;

    let mut query_nonce = [0u8; 24];
    query_nonce[0..12].copy_from_slice(&client_nonce);

    let encrypted_query =
        xchacha20_djb_poly1305_encrypt(&session.shared_key, &query_nonce, &padded_query);

    let mut request_packet = Vec::with_capacity(8 + 32 + 12 + encrypted_query.len());
    request_packet.extend_from_slice(&session.client_magic);
    request_packet.extend_from_slice(&session.client_pk_bytes);
    request_packet.extend_from_slice(&client_nonce);
    request_packet.extend_from_slice(&encrypted_query);

    let response_packet = send_dns_query(session.resolver_ip, &request_packet, false).await?;

    if response_packet.len() < 32 {
        return Err("Response packet too short".to_string());
    }

    let resolver_magic = [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
    if response_packet[0..8] != resolver_magic {
        return Err("Invalid resolver magic".to_string());
    }

    let mut resp_nonce = [0u8; 24];
    resp_nonce.copy_from_slice(&response_packet[8..32]);

    if resp_nonce[0..12] != client_nonce {
        return Err("Client nonce mismatch in resolver response".to_string());
    }

    let encrypted_response = &response_packet[32..];
    let decrypted = xchacha20_djb_poly1305_decrypt(
        &session.shared_key,
        &resp_nonce,
        encrypted_response,
    )?;

    let unpadded = unpad_response(&decrypted)?;
    let ip = parse_dns_response(&unpadded)
        .ok_or_else(|| "No A record found in DNSCrypt response".to_string())?;

    Ok(ip)
}

pub async fn resolve_domain_via_dnscrypt(domain: &str) -> Result<(IpAddr, Option<u64>), String> {
    let session = establish_dnscrypt_session().await?;
    let ip = resolve_domain_via_dnscrypt_session(&session, domain).await?;
    Ok((ip, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_a_record_query() {
        let query = build_a_record_query("github.com");
        assert_eq!(
            &query[0..12],
            &[
                0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
        assert_eq!(query[12], 6);
        assert_eq!(&query[13..19], b"github");
        assert_eq!(query[19], 3);
        assert_eq!(&query[20..23], b"com");
        assert_eq!(query[23], 0);
        assert_eq!(&query[24..28], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_parse_dns_response_valid() {
        let mut response = Vec::new();
        response.extend_from_slice(&[
            0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        response.extend_from_slice(&[6]);
        response.extend_from_slice(b"github");
        response.extend_from_slice(&[3]);
        response.extend_from_slice(b"com");
        response.extend_from_slice(&[0]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0xc0, 0xc]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        response.extend_from_slice(&[0x00, 0x04]);
        response.extend_from_slice(&[140, 82, 121, 4]);

        let parsed = parse_dns_response(&response).expect("Should parse valid DNS response");
        assert_eq!(parsed, IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4)));
    }

    #[test]
    fn test_parse_dns_response_truncated() {
        assert!(parse_dns_response(&[]).is_none());
        assert!(parse_dns_response(&[0; 10]).is_none());

        let mut response = Vec::new();
        response.extend_from_slice(&[
            0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        response.extend_from_slice(&[6]);
        response.extend_from_slice(b"github");
        response.extend_from_slice(&[3]);
        response.extend_from_slice(b"com");
        response.extend_from_slice(&[0]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0xc0, 0xc]);
        assert!(parse_dns_response(&response).is_none());
    }

    #[test]
    fn test_pad_query() {
        let query = vec![1, 2, 3];
        let padded = pad_query(&query, 64);
        assert_eq!(padded.len(), 64);
        assert_eq!(padded[0..3], [1, 2, 3]);
        assert_eq!(padded[3], 0x80);
        assert!(padded[4..].iter().all(|&b| b == 0));

        let query2 = vec![5; 64];
        let padded2 = pad_query(&query2, 64);
        assert_eq!(padded2.len(), 128);
        assert_eq!(padded2[64], 0x80);
    }

    #[test]
    fn test_unpad_response() {
        let valid = vec![1, 2, 3, 0x80, 0, 0, 0];
        let unpadded = unpad_response(&valid).unwrap();
        assert_eq!(unpadded, vec![1, 2, 3]);

        let invalid_no_80 = vec![1, 2, 3, 0, 0, 0];
        assert!(unpad_response(&invalid_no_80).is_err());
    }

    #[test]
    fn test_xchacha20_djb_poly1305_encrypt_decrypt() {
        let key = [9u8; 32];
        let nonce = [12u8; 24];
        let msg = b"Hello, DNSCrypt!";

        let encrypted = xchacha20_djb_poly1305_encrypt(&key, &nonce, msg);
        assert_eq!(encrypted.len(), msg.len() + 16);

        let decrypted = xchacha20_djb_poly1305_decrypt(&key, &nonce, &encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }
}
