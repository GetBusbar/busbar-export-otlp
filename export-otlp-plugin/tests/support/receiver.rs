// SPDX-License-Identifier: Apache-2.0
//! Local HTTPS receiver for OTLP delivery tests. No exporter logic lives here.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::OnceLock;

struct Identity {
    pem: String,
    cert: rustls_pki_types::CertificateDer<'static>,
    key: Vec<u8>,
}
fn identity() -> &'static Identity {
    static ID: OnceLock<Identity> = OnceLock::new();
    ID.get_or_init(|| {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .expect("localhost identity");
        Identity {
            pem: cert.pem(),
            cert: cert.der().clone(),
            key: signing_key.serialize_der(),
        }
    })
}
pub fn anchors() -> &'static str {
    &identity().pem
}
pub fn far_end_on(
    listener: TcpListener,
    answer: fn(&[u8]) -> Option<Vec<u8>>,
) -> std::io::Result<SocketAddr> {
    let addr = listener.local_addr()?;
    let id = identity();
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![id.cert.clone()],
        rustls_pki_types::PrivatePkcs8KeyDer::from(id.key.clone()).into(),
    )
    .expect("TLS receiver");
    let config = std::sync::Arc::new(config);
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { break };
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .expect("read deadline");
            let config = config.clone();
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(config).expect("server connection");
                let mut stream = rustls::StreamOwned::new(conn, tcp);
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    if let Some(response) = answer(&request) {
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                        stream.conn.send_close_notify();
                        let _ = stream.flush();
                        break;
                    }
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
            });
        }
    });
    Ok(addr)
}
