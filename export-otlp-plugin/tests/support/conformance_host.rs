// SPDX-License-Identifier: Apache-2.0
#[path = "connector.rs"]
mod connector;
#[path = "receiver.rs"]
mod receiver;
pub use connector::host;
pub use receiver::anchors;
pub fn far_end(answer: fn(&[u8]) -> Option<Vec<u8>>) {
    static START: std::sync::Once = std::sync::Once::new();
    START.call_once(|| {
        receiver::far_end_on(
            std::net::TcpListener::bind("localhost:54017").expect("OTLP receiver"),
            answer,
        )
        .expect("TLS receiver");
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::abi::host::conn::connector::{
        DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_LOOPBACK_ALLOWED, EGRESS_OPERATOR_INFRASTRUCTURE,
    };
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_contract::conn::{
        ConnError, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, NO_TICKET,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    const OWNER: InstanceId = InstanceId(7);
    fn declare(c: &dyn DeclaredConns, id: NeedId, transport: &str, class: u32) {
        c.declare(
            OWNER,
            id,
            &ReadNeed {
                direction: DIRECTION_OUTBOUND,
                egress_class: class,
                transport: transport.into(),
                auth: String::new(),
                target_from: String::new(),
                trust_from: String::new(),
                details: ReadBlob {
                    fmt: 0,
                    flags: 0,
                    bytes: Vec::new(),
                },
                timeout_ms: 0,
                keep_response_headers: Vec::new(),
                keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
                deny_response_headers: Vec::new(),
            },
            None,
            None,
        )
        .expect("test need");
    }
    fn settle<T>(mut f: impl FnMut() -> Result<T, ConnError>) -> Result<T, ConnError> {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            match f() {
                Err(ConnError::Pending) if Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                answer => return answer,
            }
        }
    }
    fn tls_echo(trusted: bool) -> Result<Vec<u8>, ConnError> {
        let listener = TcpListener::bind("localhost:0").unwrap();
        let address = receiver::far_end_on(listener, |bytes| {
            (bytes.len() >= 5).then(|| bytes[..5].to_vec())
        })
        .unwrap();
        let c = host(Arc::new(|_, _| {}), trusted.then(anchors));
        declare(c.as_ref(), NeedId(0), "tcp", EGRESS_OPERATOR_INFRASTRUCTURE);
        let target = format!("localhost:{}", address.port());
        let id = settle(|| {
            c.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: &target,
                    timeout_ms: 5000,
                    ..Default::default()
                },
            )
        })?;
        let result = (|| {
            settle(|| c.upgrade_secure(OWNER, id, Some("localhost"), None, false, NO_TICKET))?;
            let mut at = 0;
            while at < 5 {
                at += settle(|| c.write(OWNER, id, &b"hello"[at..], false, false))?;
            }
            let mut body = Vec::new();
            let mut buffer = [0; 256];
            while body.len() < 5 {
                let piece = settle(|| c.read(OWNER, id, NO_TICKET, &mut buffer))?;
                if piece.kind == PieceKind::Body {
                    body.extend_from_slice(&buffer[..piece.len]);
                }
                if piece.kind == PieceKind::Completion {
                    break;
                }
            }
            Ok(body)
        })();
        let _ = c.close(OWNER, id);
        result
    }
    #[test]
    fn the_hosts_tls_upgrade_verifies_against_the_suites_test_anchors() {
        assert_eq!(tls_echo(true), Ok(b"hello".to_vec()));
    }
    #[test]
    fn red_with_the_anchors_withheld_the_hosts_tls_upgrade_is_refused() {
        assert!(tls_echo(false).is_err());
    }
    #[test]
    fn an_http_need_reaches_a_local_http_listener_through_the_hosts_framer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0; 512];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut buf).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buf[..n]);
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello")
                .unwrap();
            String::from_utf8(request).unwrap()
        });
        let c = host(Arc::new(|_, _| {}), None);
        assert!(c.serves_scheme("http"));
        declare(c.as_ref(), NeedId(0), "http", EGRESS_LOOPBACK_ALLOWED);
        let target = format!("http://{address}/v1/probe");
        let id = settle(|| {
            c.open(
                OWNER,
                NeedId(0),
                &OpenDesc {
                    target: &target,
                    method: b"GET",
                    head_target: b"/v1/probe",
                    timeout_ms: 5000,
                    ..Default::default()
                },
            )
        })
        .unwrap();
        let mut fields = 0;
        let mut body = Vec::new();
        let mut buf = [0; 256];
        while body.len() < 5 {
            let piece = settle(|| c.read(OWNER, id, NO_TICKET, &mut buf)).unwrap();
            match piece.kind {
                PieceKind::Fields => fields += 1,
                PieceKind::Body => body.extend_from_slice(&buf[..piece.len]),
                PieceKind::Completion => break,
                _ => {}
            }
        }
        assert!(peer
            .join()
            .unwrap()
            .starts_with("GET /v1/probe HTTP/1.1\r\n"));
        assert_eq!(fields, 1);
        assert_eq!(body, b"hello");
        c.close(OWNER, id).unwrap();
    }
    #[test]
    fn the_conformance_host_guard_refuses_a_private_destination() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let at = listener.local_addr().unwrap().to_string();
        let c = connector::guarded_host(Arc::new(|_, _| {}), Some(anchors()));
        let mut n = 0;
        let mut open = |class, target: &str| {
            n += 1;
            declare(c.as_ref(), NeedId(n), "tcp", class);
            settle(|| {
                c.open(
                    OWNER,
                    NeedId(n),
                    &OpenDesc {
                        target,
                        timeout_ms: 2000,
                        ..Default::default()
                    },
                )
            })
        };
        for (class, target) in [
            (EGRESS_DEFAULT, "10.0.0.1:443"),
            (EGRESS_DEFAULT, at.as_str()),
            (EGRESS_OPERATOR_INFRASTRUCTURE, "169.254.169.254:80"),
        ] {
            assert_eq!(open(class, target).map(|_| ()), Err(ConnError::Refused));
        }
        assert!(listener.accept().is_err(), "refused addresses dial nothing");
        let id = open(EGRESS_OPERATOR_INFRASTRUCTURE, &at).expect("operator loopback control");
        let until = Instant::now() + Duration::from_secs(5);
        while listener.accept().is_err() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(2));
        }
        c.close(OWNER, id).unwrap();
    }
}
