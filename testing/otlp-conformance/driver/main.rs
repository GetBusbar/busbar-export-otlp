// SPDX-License-Identifier: Apache-2.0
//! The conformance subject's driver: busbar-export-otlp's own request builder, fed a JSON-lines
//! `traces` batch, delivering what the sink would deliver to a real collector.
//!
//!   driver body <batch.jsonl> <out.bin>      write the OTLP request body the sink builds
//!   driver send <url> <batch.jsonl>          POST it with the sink's own headers and target
//!
//! Records that are no span are skipped, by the sink's own splitting (`door::batch_body`). Exit 0 iff the collector answered
//! 2xx (send) or a body was built (body). The sink's `Endpoint` supplies the request target and
//! headers, so what is sent is what the sink would send; only the host connector's socket is
//! replaced by a plain HTTP/1.1 client.
use std::io::{Read, Write};
use std::net::TcpStream;

use busbar_export_otlp::door::{self, Endpoint};
use busbar_export_otlp::OtlpSettings;

fn body(batch: &[u8]) -> Vec<u8> {
    door::batch_body(batch).expect("the batch holds no span")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("body") if args.len() == 4 => {
            let b = body(&std::fs::read(&args[2]).expect("read batch"));
            std::fs::write(&args[3], b).expect("write body");
        }
        Some("send") if args.len() == 4 => {
            let settings: OtlpSettings =
                serde_json::from_value(serde_json::json!({ "url": args[2].as_str() })).expect("settings");
            let endpoint = Endpoint::of(&settings);
            let payload = body(&std::fs::read(&args[3]).expect("read batch"));
            let (request, sealed) = endpoint.parts(payload);
            assert!(sealed.is_empty(), "the suite's collector url carries no credential");
            let collector = endpoint.collector;
            let authority = collector
                .split("://")
                .nth(1)
                .and_then(|r| r.split('/').next())
                .expect("authority")
                .to_string();
            let mut head = format!(
                "POST {} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: {}\r\n",
                String::from_utf8_lossy(&request.target),
                request.body.len()
            );
            for (k, v) in &request.fields {
                head.push_str(&format!(
                    "{}: {}\r\n",
                    String::from_utf8_lossy(k),
                    String::from_utf8_lossy(v)
                ));
            }
            head.push_str("\r\n");
            let mut s = TcpStream::connect(&authority).expect("connect");
            s.write_all(head.as_bytes()).expect("write head");
            s.write_all(&request.body).expect("write body");
            let mut reply = Vec::new();
            s.read_to_end(&mut reply).expect("read reply");
            let text = String::from_utf8_lossy(&reply);
            let status = text.lines().next().unwrap_or("");
            println!("{status}");
            let code: u16 = status.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
            std::process::exit(if (200..300).contains(&code) { 0 } else { 1 });
        }
        _ => {
            eprintln!("usage: driver body <batch> <out> | driver send <url> <batch>");
            std::process::exit(2);
        }
    }
}
