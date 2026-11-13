// SPDX-License-Identifier: Apache-2.0
//! Official Weaver checks on this invocation's real Collector-captured plugin spans.
//!
//! No custom advice policy, finding filter, or severity override. A declared Busbar registry
//! extends the upstream schema; the base-only result is retained separately. This evaluates
//! traces/resources only: the plugin does not export metrics or logs.
//!
//! `testing/weaver-conformance/run.sh` runs [`weaver_conformance`] (ignored by ordinary test runs)
//! with `CONFORMANCE_OUT` set; the remaining tests are this rig's own targeted tests.
//!
//! THE INSTRUMENT ARCHIVES ARE UNTRUSTED INPUT until proven otherwise. Each is SHA-256 pinned and
//! verified before it is opened; its decompressed stream is then listed in full and refused unless
//! every member is a regular file or directory whose path is relative with only normal components,
//! and the members total at most 512 MiB. Only then is a fresh directory created and the same
//! members unpacked into it, with no ownership, setuid/setgid/sticky bits, group/world write or
//! extended attributes carried over, and each member confined to that directory.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const VERSION: &str = "0.28.0";
/// semantic-conventions v1.45.0.
const REGISTRY_COMMIT: &str = "fb30ca17193b551473b1f43c315482918ab6987c";
const REGISTRY_SHA: &str = "aefd780086389034d492f3cbe52e180dd74e6057700ce1663c59d21c8a497818";
/// One pinned Weaver release asset: the platform it serves (`std::env::consts`), its triple and SHA-256.
struct Tool {
    os: &'static str,
    arch: &'static str,
    triple: &'static str,
    sha256: &'static str,
}

const TOOLS: &[Tool] = &[
    Tool {
        os: "linux",
        arch: "x86_64",
        triple: "x86_64-unknown-linux-musl",
        sha256: "69069769ec3509c358ddbfbc29ff9965590fe4f8dd8b03e1c1e1be1ae56122e8",
    },
    Tool {
        os: "linux",
        arch: "aarch64",
        triple: "aarch64-unknown-linux-musl",
        sha256: "55a47e3d6226a372570b65853e56413266c149aaa7716172bdffb0dc8422d544",
    },
    Tool {
        os: "macos",
        arch: "aarch64",
        triple: "aarch64-apple-darwin",
        sha256: "b334b37372325f77374b461fd6a11d38bc050122832eb83a9732fcd6831a5ab1",
    },
    Tool {
        os: "macos",
        arch: "x86_64",
        triple: "x86_64-apple-darwin",
        sha256: "40dd65d72b43bc97041b849203e450b322cd786629af8f926cfd2d05798d9ca4",
    },
];
/// The controller's read-only staging of the pinned Weaver executable and semconv model.
const STAGED: &str = "/opt/busbar-conformance/weaver";
const MAX_CAPTURE: u64 = 16 * 1024 * 1024;
const MAX_DOWNLOAD: u64 = 128 * 1024 * 1024;
/// The declared member sizes an archive may total.
const MAX_UNPACKED: u64 = 512 * 1024 * 1024;
/// The decompressed tar stream (members plus headers and padding): a decompression-bomb bound.
const MAX_TAR_STREAM: u64 = 1024 * 1024 * 1024;
const WEAVER_TIMEOUT: Duration = Duration::from_secs(180);

type Res<T> = Result<T, String>;

fn ctx<E: std::fmt::Display>(what: impl std::fmt::Display) -> impl FnOnce(E) -> String {
    move |error| format!("{what}: {error}")
}

fn digest(path: &Path) -> Res<String> {
    let mut file = File::open(path).map_err(ctx(format!("open {}", path.display())))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).map_err(ctx(format!("read {}", path.display())))?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Every object's keys in sorted order, whatever map the serde_json build uses.
fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

fn write(path: &Path, value: Value) -> Res<()> {
    let text = serde_json::to_string_pretty(&sorted(value)).map_err(ctx("serialise"))?;
    fs::write(path, text + "\n").map_err(ctx(format!("write {}", path.display())))
}

fn read_json(path: &Path) -> Res<Value> {
    let text = fs::read_to_string(path).map_err(ctx(format!("read {}", path.display())))?;
    serde_json::from_str(&text).map_err(ctx(format!("parse {}", path.display())))
}

/// Python-style truthiness, as the evaluation criteria were stated.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn is_number(value: &Value, want: i64) -> bool {
    value.is_number() && value.as_f64() == Some(want as f64)
}

// ---- provisioning ------------------------------------------------------------------------------

/// The SHA-256 pin and the size bound of a downloaded archive.
fn verify_download(target: &Path, expected: &str) -> Res<()> {
    let size = fs::metadata(target)
        .map_err(ctx(format!("stat {}", target.display())))?
        .len();
    if size > MAX_DOWNLOAD {
        return Err("instrument download exceeds 128 MiB".into());
    }
    if digest(target)? != expected {
        return Err("instrument archive checksum mismatch".into());
    }
    Ok(())
}

/// Download `url` (HTTPS only, redirects included) into a new file, then verify its pin.
fn fetch(url: &str, expected: &str, target: &Path) -> Res<()> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(ctx(format!("create {}", target.display())))?;
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "60",
            "--speed-limit",
            "1",
            "--speed-time",
            "60",
            "--max-time",
            "900",
            "--max-filesize",
        ])
        .arg(MAX_DOWNLOAD.to_string())
        .arg("--")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(file)
        .stderr(Stdio::piped())
        .output()
        .map_err(ctx("run curl"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr: String = stderr.trim().chars().take(500).collect();
        return Err(format!("instrument download failed: {stderr}"));
    }
    verify_download(target, expected)
}

#[derive(Clone, Copy)]
enum Compression {
    Gzip,
    Xz,
}

/// Copy at most [`MAX_TAR_STREAM`] bytes; more is refused.
fn bounded_copy(source: &mut impl Read, target: &Path) -> Res<()> {
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(ctx(format!("create {}", target.display())))?;
    let copied = io::copy(&mut source.take(MAX_TAR_STREAM + 1), &mut out)
        .map_err(ctx("decompress instrument archive"))?;
    if copied > MAX_TAR_STREAM {
        return Err(
            "unsafe or oversized instrument archive: decompressed stream exceeds 1 GiB".into(),
        );
    }
    out.flush().map_err(ctx("flush decompressed archive"))
}

/// The archive's tar stream, decompressed into `target`.
fn decompress(archive: &Path, compression: Compression, target: &Path) -> Res<()> {
    match compression {
        Compression::Gzip => {
            let file = File::open(archive).map_err(ctx(format!("open {}", archive.display())))?;
            bounded_copy(&mut flate2::read::MultiGzDecoder::new(file), target)
        }
        Compression::Xz => {
            let mut child = Command::new("xz")
                .args(["--decompress", "--stdout", "--"])
                .arg(archive)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(ctx("xz(1) is required to unpack the pinned Weaver archive"))?;
            let copied = bounded_copy(child.stdout.as_mut().expect("piped stdout"), target);
            if copied.is_err() {
                let _ = child.kill();
            }
            let status = child.wait().map_err(ctx("wait for xz"))?;
            copied?;
            if !status.success() {
                return Err(format!(
                    "xz could not decompress the instrument archive ({status})"
                ));
            }
            Ok(())
        }
    }
}

/// Relative, with only normal (or `.`) components and at least one normal one.
fn confined(path: &Path) -> bool {
    let mut normal = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => normal = true,
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => return false,
        }
    }
    normal
}

/// Whether this member is archive metadata (a pax global header), never unpacked.
fn metadata_only(entry: &tar::Entry<'_, File>) -> bool {
    entry.header().entry_type().is_pax_global_extensions()
}

/// Refuse a member that is not a plain file or directory confined to the destination.
fn check_member(entry: &tar::Entry<'_, File>) -> Res<()> {
    let kind = entry.header().entry_type();
    let path = entry
        .path()
        .map_err(ctx("unsafe instrument archive member name"))?;
    let link = entry
        .link_name()
        .map_err(ctx("unsafe instrument archive link name"))?;
    if !(kind.is_file() || kind.is_dir()) || link.is_some() || !confined(&path) {
        return Err(format!(
            "unsafe or oversized instrument archive: member {:?} ({kind:?})",
            path.display()
                .to_string()
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    Ok(())
}

/// List every member of the tar stream before anything is extracted.
fn validate(tar_path: &Path, limit: u64) -> Res<()> {
    let file = File::open(tar_path).map_err(ctx(format!("open {}", tar_path.display())))?;
    let mut archive = tar::Archive::new(file);
    let mut size: u64 = 0;
    let mut members = 0usize;
    for entry in archive
        .entries()
        .map_err(ctx("unreadable instrument archive"))?
    {
        let entry = entry.map_err(ctx("unreadable instrument archive"))?;
        if metadata_only(&entry) {
            continue;
        }
        check_member(&entry)?;
        size = size.saturating_add(entry.size());
        if size > limit {
            return Err(
                "unsafe or oversized instrument archive: members exceed the size bound".into(),
            );
        }
        members += 1;
    }
    if members == 0 {
        return Err("instrument archive holds no members".into());
    }
    Ok(())
}

/// Unpack a validated tar stream into the fresh `destination`.
fn extract(tar_path: &Path, destination: &Path) -> Res<()> {
    fs::create_dir(destination).map_err(ctx(format!("create {}", destination.display())))?;
    let file = File::open(tar_path).map_err(ctx(format!("open {}", tar_path.display())))?;
    let mut archive = tar::Archive::new(file);
    archive.set_preserve_permissions(false);
    archive.set_preserve_ownerships(false);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(false);
    archive.set_mask(0o022);
    for entry in archive
        .entries()
        .map_err(ctx("unreadable instrument archive"))?
    {
        let mut entry = entry.map_err(ctx("unreadable instrument archive"))?;
        if metadata_only(&entry) {
            continue;
        }
        check_member(&entry)?;
        let unpacked = entry
            .unpack_in(destination)
            .map_err(ctx("unpack instrument archive"))?;
        if !unpacked {
            return Err("unsafe instrument archive: a member escapes its destination".into());
        }
    }
    Ok(())
}

/// Decompress, validate every member, and only then unpack into a new `destination`.
fn unpack(archive: &Path, compression: Compression, destination: &Path, limit: u64) -> Res<()> {
    let stream = archive.with_extension("tar-stream");
    decompress(archive, compression, &stream)?;
    let result = validate(&stream, limit).and_then(|()| extract(&stream, destination));
    let _ = fs::remove_file(&stream);
    result
}

type Fetch<'a> = &'a dyn Fn(&str, &str, &Path) -> Res<()>;

/// The pinned Weaver executable and the official semconv model directory.
fn provision(work: &Path, staged: Option<&Path>, fetch: Fetch<'_>) -> Res<(PathBuf, PathBuf)> {
    if let Some(root) = staged {
        let (tool, registry) = (root.join("weaver"), root.join("registry"));
        let tool_ok = fs::symlink_metadata(&tool).is_ok_and(|m| {
            use std::os::unix::fs::PermissionsExt as _;
            m.file_type().is_file() && m.permissions().mode() & 0o111 != 0
        });
        let registry_ok = fs::symlink_metadata(&registry).is_ok_and(|m| m.file_type().is_dir());
        if !(tool_ok && registry_ok) {
            return Err("controller did not stage the pinned offline Weaver inputs".into());
        }
        return Ok((tool, registry));
    }
    let platform = (std::env::consts::OS, std::env::consts::ARCH);
    let &Tool {
        triple,
        sha256: sha,
        ..
    } = TOOLS
        .iter()
        .find(|tool| (tool.os, tool.arch) == platform)
        .ok_or_else(|| format!("no pinned Weaver {VERSION} build for {platform:?}"))?;
    let archive = work.join("weaver.tar.xz");
    fetch(
        &format!("https://github.com/open-telemetry/weaver/releases/download/v{VERSION}/weaver-{triple}.tar.xz"),
        sha,
        &archive,
    )?;
    unpack(&archive, Compression::Xz, &work.join("tool"), MAX_UNPACKED)?;
    let registry = work.join("semconv.tar.gz");
    fetch(
        &format!("https://codeload.github.com/open-telemetry/semantic-conventions/tar.gz/{REGISTRY_COMMIT}"),
        REGISTRY_SHA,
        &registry,
    )?;
    unpack(
        &registry,
        Compression::Gzip,
        &work.join("registry"),
        MAX_UNPACKED,
    )?;
    Ok((
        work.join("tool")
            .join(format!("weaver-{triple}"))
            .join("weaver"),
        work.join("registry")
            .join(format!("semantic-conventions-{REGISTRY_COMMIT}"))
            .join("model"),
    ))
}

/// Weaver's supported registry dependency mechanism, never policy filters.
fn custom_registry(work: &Path, official: &Path) -> Res<(PathBuf, String)> {
    let directory = work.join("busbar-registry");
    fs::create_dir(&directory).map_err(ctx(format!("create {}", directory.display())))?;
    let extension = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testing/weaver-conformance/registry/busbar.yaml");
    fs::copy(&extension, directory.join("busbar.yaml"))
        .map_err(ctx(format!("copy {}", extension.display())))?;
    // JSON is YAML; its serializer safely quotes the local dependency path.
    write(
        &directory.join("manifest.yaml"),
        json!({
            "schema_url": "https://getbusbar.dev/schemas/otel/1.6.0",
            "description": "Busbar custom dynamic metadata plus official OTel semantic conventions",
            "dependencies": [{"schema_url": "https://opentelemetry.io/schemas/1.45.0",
                              "registry_path": official.to_str().ok_or("non-UTF-8 registry path")?}],
        }),
    )?;
    Ok((directory, digest(&extension)?))
}

// ---- samples -----------------------------------------------------------------------------------

/// One OTLP AnyValue as a Weaver sample value and its declared primitive type, if any.
fn any_value(value: &Value) -> Res<(Value, Option<String>)> {
    let map = match value {
        Value::Null => return Ok((Value::Null, None)),
        Value::Object(map) if map.is_empty() => return Ok((Value::Null, None)),
        Value::Object(map) if map.len() == 1 => map,
        _ => return Err("ambiguous/empty OTLP attribute value".into()),
    };
    let (key, data) = map.iter().next().expect("one entry");
    match (key.as_str(), data) {
        ("stringValue", Value::String(_)) => Ok((data.clone(), Some("string".into()))),
        ("boolValue", Value::Bool(_)) => Ok((data.clone(), Some("boolean".into()))),
        ("intValue", Value::String(text)) => text
            .parse::<i64>()
            .map(|n| (json!(n), Some("int".into())))
            .map_err(|_| "OTLP intValue is not an int64".into()),
        ("intValue", Value::Number(n)) if n.is_i64() || n.is_u64() => n
            .as_i64()
            .map(|n| (json!(n), Some("int".into())))
            .ok_or_else(|| "OTLP intValue is not an int64".into()),
        ("doubleValue", Value::Number(_)) => Ok((data.clone(), Some("double".into()))),
        ("arrayValue", Value::Object(array)) => {
            let empty = Vec::new();
            let items = match array.get("values") {
                None => &empty,
                Some(Value::Array(items)) => items,
                Some(_) => return Err("OTLP arrayValue.values is not a list".into()),
            };
            let elements = items.iter().map(any_value).collect::<Res<Vec<_>>>()?;
            let mut kinds: Vec<&Option<String>> = elements.iter().map(|(_, k)| k).collect();
            kinds.sort();
            kinds.dedup();
            let values = Value::Array(elements.iter().map(|(v, _)| v.clone()).collect());
            match kinds.as_slice() {
                [Some(kind)] if !kind.ends_with("[]") => Ok((values, Some(format!("{kind}[]")))),
                // Weaver permits a value without a declared primitive type. Preserve
                // heterogeneous/null arrays verbatim instead of dropping or coercing them.
                _ => Ok((values, None)),
            }
        }
        _ => Err("OTLP attribute cannot be represented losslessly as a Weaver sample".into()),
    }
}

/// `object[key]`, defaulting when absent; present-but-wrong types are refused.
fn field<'a>(object: &'a Value, key: &str, default: &'a Value) -> Res<&'a Value> {
    match object {
        Value::Object(map) => Ok(map.get(key).unwrap_or(default)),
        _ => Err(format!(
            "malformed OTLP capture: expected an object holding {key:?}"
        )),
    }
}

fn required<'a>(object: &'a Value, key: &str) -> Res<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| format!("malformed OTLP capture: missing {key:?}"))
}

fn list(value: &Value, what: &str) -> Res<Vec<Value>> {
    value
        .as_array()
        .cloned()
        .ok_or_else(|| format!("malformed OTLP capture: {what} is not a list"))
}

fn attributes(values: &Value) -> Res<Vec<Value>> {
    list(values, "attributes")?
        .iter()
        .map(|item| {
            let name = match item.get("key") {
                Some(Value::String(name)) if !name.is_empty() => name,
                _ => return Err("missing OTLP attribute key".to_string()),
            };
            let (value, kind) = any_value(required(item, "value")?)?;
            Ok(json!({"name": name, "value": value, "type": kind}))
        })
        .collect()
}

/// Every span/resource/scope/event/link attribute, preserved without renaming.
fn samples(capture: &Path) -> Res<(Vec<Value>, usize)> {
    let refused = || "missing, indirect, or oversized actual exporter capture".to_string();
    let meta = fs::symlink_metadata(capture).map_err(|_| refused())?;
    if !meta.file_type().is_file() || meta.len() > MAX_CAPTURE {
        return Err(refused());
    }
    let text = fs::read_to_string(capture).map_err(ctx("read actual exporter capture"))?;
    let (empty_object, empty_list, zero) = (json!({}), json!([]), json!(0));
    let mut output = Vec::new();
    let mut spans = 0usize;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let request: Value = serde_json::from_str(line).map_err(ctx("parse OTLP capture line"))?;
        for resource in list(required(&request, "resourceSpans")?, "resourceSpans")? {
            let held = field(&resource, "resource", &empty_object)?;
            output.push(json!({"resource": {"attributes": attributes(field(held, "attributes", &empty_list)?)?}}));
            for scope in list(required(&resource, "scopeSpans")?, "scopeSpans")? {
                // Weaver's JSON form cannot associate a resource/scope with a span;
                // check scope attributes individually instead of discarding them.
                let held = field(&scope, "scope", &empty_object)?;
                for attribute in attributes(field(held, "attributes", &empty_list)?)? {
                    output.push(json!({"attribute": attribute}));
                }
                for span in list(required(&scope, "spans")?, "spans")? {
                    spans += 1;
                    let kind = match field(&span, "kind", &zero)?.as_u64() {
                        Some(0 | 1) => "internal",
                        Some(2) => "server",
                        Some(3) => "client",
                        Some(4) => "producer",
                        Some(5) => "consumer",
                        _ => return Err("OTLP span kind is not 0..=5".into()),
                    };
                    let status = field(&span, "status", &empty_object)?;
                    let code = match field(status, "code", &zero)?.as_u64() {
                        Some(0) => "unset",
                        Some(1) => "ok",
                        Some(2) => "error",
                        _ => return Err("OTLP status code is not 0..=2".into()),
                    };
                    let message = field(status, "message", &Value::Null)?;
                    let message = if message.is_null() {
                        json!("")
                    } else {
                        message.clone()
                    };
                    let events = list(field(&span, "events", &empty_list)?, "events")?
                        .iter()
                        .map(|e| {
                            Ok(json!({"name": required(e, "name")?,
                                      "attributes": attributes(field(e, "attributes", &empty_list)?)?}))
                        })
                        .collect::<Res<Vec<_>>>()?;
                    let links = list(field(&span, "links", &empty_list)?, "links")?
                        .iter()
                        .map(|l| Ok(json!({"attributes": attributes(field(l, "attributes", &empty_list)?)?})))
                        .collect::<Res<Vec<_>>>()?;
                    output.push(json!({"span": {
                        "name": required(&span, "name")?,
                        "kind": kind,
                        "status": {"code": code, "message": message},
                        "attributes": attributes(field(&span, "attributes", &empty_list)?)?,
                        "span_events": events,
                        "span_links": links,
                    }}));
                }
            }
        }
    }
    if spans == 0 {
        return Err("actual exporter capture contains no spans".into());
    }
    Ok((output, spans))
}

// ---- evaluation --------------------------------------------------------------------------------

/// One official `weaver registry live-check` over `sample`, with its report's required shape.
fn evaluate(
    tool: &Path,
    registry: &Path,
    name: &str,
    sample: &[Value],
    evidence: &Path,
) -> Res<Value> {
    let input = evidence.join(format!("{name}-samples.json"));
    write(&input, Value::Array(sample.to_vec()))?;
    let config = evidence.join("weaver.toml");
    // Never inherit a caller's finding filters/config discovery.
    fs::write(&config, "").map_err(ctx("write weaver.toml"))?;
    let directory = evidence.join(name);
    let log =
        File::create(evidence.join(format!("{name}.log"))).map_err(ctx("create Weaver log"))?;
    let mut child = Command::new(tool)
        .args(["registry", "live-check", "--config"])
        .arg(&config)
        .arg("--registry")
        .arg(registry)
        .arg("--input-source")
        .arg(&input)
        .args(["--input-format", "json", "--format", "json", "--output"])
        .arg(&directory)
        .args([
            "--no-stream",
            "--include-unreferenced",
            "--fail-on",
            "violation",
        ])
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(ctx("share Weaver log"))?)
        .stderr(log)
        .spawn()
        .map_err(ctx(format!("run {}", tool.display())))?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(ctx("wait for Weaver"))? {
            break status;
        }
        if started.elapsed() > WEAVER_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{name}: Weaver exceeded {}s",
                WEAVER_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let rc = status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt as _;
        -status.signal().unwrap_or(0)
    });
    let report_path = directory.join("live_check.json");
    let report = read_json(&report_path)?;
    let reported = report
        .get("samples")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let statistics = report.get("statistics").cloned().unwrap_or(Value::Null);
    if reported != sample.len() || !statistics.get("total_entities").is_some_and(truthy) {
        return Err(format!(
            "{name}: Weaver produced incomplete/empty assessment"
        ));
    }
    let levels = required(&statistics, "advice_level_counts")?.clone();
    let types = required(&statistics, "advice_type_counts")?.clone();
    Ok(json!({
        "exit_code": rc,
        "violations": levels.get("violation").cloned().unwrap_or(json!(0)),
        "advice_level_counts": levels,
        "advice_type_counts": types,
        "report_sha256": digest(&report_path)?,
    }))
}

/// Everything after the evidence directories exist; any error is the verdict's reason.
fn assess(
    out: &Path,
    work: &Path,
    evidence: &Path,
    assessment: &mut Map<String, Value>,
) -> Res<(bool, String)> {
    let staged = std::env::var_os("CONFORMANCE_CAPABILITIES").map(|_| Path::new(STAGED));
    let (tool, registry) = provision(work, staged, &fetch)?;
    let (combined, extension_sha) = custom_registry(work, &registry)?;
    assessment.insert("custom_registry_sha256".into(), json!(extension_sha));
    let control = vec![
        json!({"attribute": {"name": "service.name", "value": "busbar-control", "type": "string"}}),
    ];
    let negative = vec![json!({"attribute": {"name": "service.name", "value": 42, "type": "int"}})];
    let control = evaluate(&tool, &combined, "control", &control, evidence)?;
    let negative = evaluate(&tool, &combined, "negative", &negative, evidence)?;
    assessment.insert("control".into(), control.clone());
    assessment.insert("negative".into(), negative.clone());
    if !is_number(&control["exit_code"], 0) || truthy(&control["violations"]) {
        return Err("official service.name control failed".into());
    }
    if !is_number(&negative["exit_code"], 1)
        || !is_number(&negative["advice_type_counts"]["type_mismatch"], 1)
        || !is_number(&negative["violations"], 1)
    {
        return Err("official judge did not identify the planted type_mismatch".into());
    }
    let prior = out
        .parent()
        .ok_or("CONFORMANCE_OUT has no parent")?
        .join("otlp");
    let verdict = read_json(&prior.join("verdict.json"))?;
    if verdict.get("suite") != Some(&json!("otlp"))
        || verdict.get("status") != Some(&json!("pass"))
        || verdict.get("armed") != Some(&json!(true))
    {
        return Err(
            "this invocation's real OTLP exporter/Collector evaluation did not pass".into(),
        );
    }
    let capture = prior.join("work/subject/traces.json");
    let (sample, count) = samples(&capture)?;
    assessment.insert("capture_sha256".into(), json!(digest(&capture)?));
    assessment.insert(
        "source_verdict_sha256".into(),
        json!(digest(&prior.join("verdict.json"))?),
    );
    assessment.insert("spans".into(), json!(count));
    // Keep the base-only result visible: a custom-registry pass is never
    // presented as if custom Busbar fields belonged to official semconv.
    let base = evaluate(&tool, &registry, "official-base-only", &sample, evidence)?;
    assessment.insert("official_base_only".into(), base.clone());
    let subject = evaluate(&tool, &combined, "subject", &sample, evidence)?;
    assessment.insert("subject".into(), subject.clone());
    let pass = is_number(&subject["exit_code"], 0) && is_number(&subject["violations"], 0);
    let reason = format!(
        "{count} actual exported spans; combined OTel + Busbar custom registry: {} violations; \
         base-only OTel registry: {} violations (retained separately); traces only",
        subject["violations"], base["violations"]
    );
    Ok((pass, reason))
}

/// The suite: writes `evidence/assessment.json` and `verdict.json` under `CONFORMANCE_OUT`.
fn run() -> Res<bool> {
    let out = PathBuf::from(std::env::var_os("CONFORMANCE_OUT").ok_or("CONFORMANCE_OUT is unset")?);
    fs::create_dir_all(&out).map_err(ctx("create CONFORMANCE_OUT"))?;
    let out = out.canonicalize().map_err(ctx("resolve CONFORMANCE_OUT"))?;
    let evidence = out.join("evidence");
    fs::create_dir(&evidence).map_err(ctx("create evidence directory"))?;
    let work = out.join("work");
    fs::create_dir(&work).map_err(ctx("create work directory"))?;
    let criteria = "Unmodified official Weaver policies; fail-on violation; all advice retained";
    let mut assessment = Map::new();
    assessment.insert("weaver_version".into(), json!(VERSION));
    assessment.insert("semconv_commit".into(), json!(REGISTRY_COMMIT));
    assessment.insert("scope".into(), json!("Actual exporter span/resource/event/link attributes against official OTel plus declared Busbar custom metadata; no metrics/logs, certification, or full instrumentation coverage claim"));
    assessment.insert("criteria".into(), json!(criteria));
    let (pass, reason) = match assess(&out, &work, &evidence, &mut assessment) {
        Ok((pass, reason)) => (pass, reason),
        Err(error) => (
            false,
            format!("Weaver evaluation unavailable or incomplete: {error}"),
        ),
    };
    let status = if pass { "pass" } else { "fail" };
    assessment.insert("status".into(), json!(status));
    assessment.insert("reason".into(), json!(reason));
    write(&evidence.join("assessment.json"), Value::Object(assessment))?;
    write(
        &out.join("verdict.json"),
        json!({
            "suite": "otel-semconv-weaver", "status": status, "armed": true,
            "standard": "OpenTelemetry semantic conventions plus Busbar custom metadata (exported traces)",
            "plan": format!("{criteria}; positive and invalid-type controls; actual captured exporter spans"),
            "spec_version": format!("Weaver {VERSION}; semantic-conventions v1.45.0 ({REGISTRY_COMMIT})"),
            "reason": reason,
        }),
    )?;
    println!("{reason}");
    Ok(pass)
}

#[test]
#[ignore = "invoked explicitly by testing/weaver-conformance/run.sh"]
fn weaver_conformance() {
    match run() {
        Ok(pass) => assert!(
            pass,
            "the Weaver evaluation did not pass (see verdict.json)"
        ),
        Err(error) => panic!("the Weaver rig could not run: {error}"),
    }
}

// ---- the rig's own targeted tests ----------------------------------------------------------------

/// A fresh scratch directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        let path = std::env::temp_dir().join(format!("weaver-rig-{tag}-{:016x}", hasher.finish()));
        fs::create_dir(&path).expect("a fresh scratch directory");
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn capture(root: &Path, spans: Value) -> PathBuf {
    let path = root.join("traces.json");
    // Collector emits one complete OTLP request per line.
    let request = json!({"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [{"spans": spans}]}]});
    fs::write(&path, request.to_string() + "\n").unwrap();
    path
}

#[test]
fn actual_attribute_names_and_types_survive_without_semantic_rewriting() {
    let scratch = Scratch::new("names");
    let (sample, count) = samples(&capture(
        &scratch.0,
        json!([{"name": "request", "kind": 1, "attributes": [
            {"key": "pool", "value": {"stringValue": "main"}},
            {"key": "service.name", "value": {"intValue": "42"}},
            {"key": "array", "value": {"arrayValue": {"values": [{}, {"boolValue": true}, {"stringValue": "x"}]}}},
        ], "events": [{"name": "event", "attributes": [{"key": "e", "value": {"boolValue": false}}]}]}]),
    ))
    .unwrap();
    assert_eq!(count, 1);
    let span = &sample[1]["span"];
    assert_eq!(
        span["attributes"],
        json!([
            {"name": "pool", "value": "main", "type": "string"},
            {"name": "service.name", "value": 42, "type": "int"},
            {"name": "array", "value": [null, true, "x"], "type": null},
        ])
    );
    assert_eq!(
        span["span_events"][0]["attributes"][0]["value"],
        json!(false)
    );
    assert_eq!(span["kind"], json!("internal"));
    assert_eq!(span["status"], json!({"code": "unset", "message": ""}));
}

#[test]
fn no_spans_is_refused_even_when_resources_exist() {
    let scratch = Scratch::new("nospans");
    let error = samples(&capture(&scratch.0, json!([]))).unwrap_err();
    assert!(error.contains("no spans"), "{error}");
}

#[test]
fn indirect_capture_is_refused() {
    let scratch = Scratch::new("indirect");
    let target = capture(&scratch.0, json!([{"name": "request"}]));
    let link = scratch.0.join("link.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let error = samples(&link).unwrap_err();
    assert!(error.contains("indirect"), "{error}");
}

#[test]
fn ambiguous_or_unsupported_wire_values_cannot_silently_disappear() {
    for value in [
        json!({"intValue": "1", "stringValue": "1"}),
        json!({"bytesValue": "YQ=="}),
        json!({"intValue": 1.5}),
    ] {
        assert!(any_value(&value).is_err(), "{value}");
    }
}

#[test]
fn confined_provision_uses_staged_inputs_without_network() {
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = Scratch::new("staged");
    let tool = scratch.0.join("weaver");
    fs::write(&tool, "instrument").unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o555)).unwrap();
    fs::create_dir(scratch.0.join("registry")).unwrap();
    let forbidden = |_: &str, _: &str, _: &Path| -> Res<()> { panic!("network forbidden") };
    assert_eq!(
        provision(&scratch.0, Some(&scratch.0), &forbidden).unwrap(),
        (tool, scratch.0.join("registry"))
    );
}

#[test]
fn missing_confined_inputs_fail_without_download_fallback() {
    let scratch = Scratch::new("unstaged");
    let forbidden = |_: &str, _: &str, _: &Path| -> Res<()> { panic!("network forbidden") };
    let error = provision(&scratch.0, Some(&scratch.0), &forbidden).unwrap_err();
    assert!(error.contains("pinned offline"), "{error}");
    // A staged symlink is not a staged executable.
    fs::create_dir(scratch.0.join("registry")).unwrap();
    std::os::unix::fs::symlink("/bin/sh", scratch.0.join("weaver")).unwrap();
    let error = provision(&scratch.0, Some(&scratch.0), &forbidden).unwrap_err();
    assert!(error.contains("pinned offline"), "{error}");
}

#[test]
fn empty_official_report_cannot_pass() {
    let scratch = Scratch::new("report");
    fs::create_dir(scratch.0.join("subject")).unwrap();
    write(
        &scratch.0.join("subject/live_check.json"),
        json!({"samples": [], "statistics": {"total_entities": 0}}),
    )
    .unwrap();
    // `true` stands in for Weaver: it exits 0 and leaves the planted report.
    let sample = [json!({"attribute": {"name": "service.name"}})];
    let error = evaluate(
        Path::new("true"),
        Path::new("registry"),
        "subject",
        &sample,
        &scratch.0,
    )
    .unwrap_err();
    assert!(error.contains("incomplete/empty"), "{error}");
}

#[test]
fn a_download_that_does_not_match_its_pin_is_refused() {
    let scratch = Scratch::new("pin");
    let archive = scratch.0.join("weaver.tar.xz");
    fs::write(&archive, b"not the pinned archive").unwrap();
    let error = verify_download(&archive, REGISTRY_SHA).unwrap_err();
    assert_eq!(error, "instrument archive checksum mismatch");
    let pinned = digest(&archive).unwrap();
    verify_download(&archive, &pinned).unwrap();
}

/// One test member: raw name bytes, type, mode, data, link name.
type Member<'a> = (&'a [u8], tar::EntryType, u32, &'a [u8], Option<&'a str>);

/// A gzip tar built member by member, header name bytes written unvalidated.
fn tar_gz(path: &Path, members: &[Member<'_>]) {
    let encoder =
        flate2::write::GzEncoder::new(File::create(path).unwrap(), flate2::Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    for (name, kind, mode, data, link) in members {
        let mut header = tar::Header::new_gnu();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_entry_type(*kind);
        header.set_mode(*mode);
        header.set_size(data.len() as u64);
        if let Some(link) = link {
            header.set_link_name(link).unwrap();
        }
        header.set_cksum();
        builder.append(&header, *data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap();
}

#[test]
fn a_plain_archive_unpacks_without_privileged_mode_bits() {
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = Scratch::new("plain");
    let archive = scratch.0.join("tool.tar.gz");
    tar_gz(
        &archive,
        &[
            (
                b"pax_global_header",
                tar::EntryType::XGlobalHeader,
                0o644,
                b"52 comment=fb30ca17193b551473b1f43c315482918ab6987c\n",
                None,
            ),
            (b"weaver-x/", tar::EntryType::Directory, 0o777, b"", None),
            (
                b"./weaver-x/weaver",
                tar::EntryType::Regular,
                0o6777,
                b"instrument",
                None,
            ),
        ],
    );
    let destination = scratch.0.join("tool");
    unpack(&archive, Compression::Gzip, &destination, MAX_UNPACKED).unwrap();
    let tool = destination.join("weaver-x/weaver");
    assert_eq!(fs::read(&tool).unwrap(), b"instrument");
    let mode = fs::metadata(&tool).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        mode, 0o755,
        "setuid/setgid and group/world write are dropped: {mode:o}"
    );
    assert!(
        !destination.join("pax_global_header").exists(),
        "a pax global header is metadata"
    );
    assert!(
        !scratch.0.join("tool.tar-stream").exists(),
        "the decompressed stream is removed"
    );
}

#[test]
fn an_unsafe_member_refuses_the_whole_archive_before_anything_is_extracted() {
    let ok: Member<'_> = (
        b"weaver-x/weaver",
        tar::EntryType::Regular,
        0o755,
        b"instrument",
        None,
    );
    let cases: [(&str, Member<'_>); 8] = [
        (
            "absolute",
            (b"/etc/evil", tar::EntryType::Regular, 0o644, b"x", None),
        ),
        (
            "parent",
            (
                b"weaver-x/../../evil",
                tar::EntryType::Regular,
                0o644,
                b"x",
                None,
            ),
        ),
        (
            "bare parent",
            (b"..", tar::EntryType::Directory, 0o755, b"", None),
        ),
        (
            "symlink",
            (
                b"weaver-x/link",
                tar::EntryType::Symlink,
                0o777,
                b"",
                Some("/etc/passwd"),
            ),
        ),
        (
            "hardlink",
            (
                b"weaver-x/hard",
                tar::EntryType::Link,
                0o644,
                b"",
                Some("weaver-x/weaver"),
            ),
        ),
        (
            "char device",
            (b"weaver-x/tty", tar::EntryType::Char, 0o666, b"", None),
        ),
        (
            "block device",
            (b"weaver-x/disk", tar::EntryType::Block, 0o666, b"", None),
        ),
        (
            "fifo",
            (b"weaver-x/pipe", tar::EntryType::Fifo, 0o666, b"", None),
        ),
    ];
    for (label, unsafe_member) in cases {
        let scratch = Scratch::new("unsafe");
        let archive = scratch.0.join("tool.tar.gz");
        // The unsafe member comes LAST: validation must list everything before extracting.
        tar_gz(&archive, &[ok, unsafe_member]);
        let destination = scratch.0.join("tool");
        let error = unpack(&archive, Compression::Gzip, &destination, MAX_UNPACKED).unwrap_err();
        assert!(error.contains("unsafe"), "{label}: {error}");
        assert!(
            !destination.exists(),
            "{label}: nothing is extracted from a refused archive"
        );
    }
}

#[test]
fn members_beyond_the_size_bound_refuse_the_archive() {
    let scratch = Scratch::new("size");
    let archive = scratch.0.join("tool.tar.gz");
    tar_gz(
        &archive,
        &[
            (b"a", tar::EntryType::Regular, 0o644, b"0123456789", None),
            (b"b", tar::EntryType::Regular, 0o644, b"0123456789", None),
        ],
    );
    let destination = scratch.0.join("tool");
    let error = unpack(&archive, Compression::Gzip, &destination, 15).unwrap_err();
    assert!(error.contains("oversized"), "{error}");
    assert!(!destination.exists());
    unpack(&archive, Compression::Gzip, &destination, 20).unwrap();
}
