#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Official Weaver checks on this invocation's real Collector-captured plugin spans.

No custom advice policy, finding filter, or severity override. A declared Busbar
registry extends the upstream schema; the base-only result is retained separately.
This evaluates traces/resources only: the plugin does not export metrics or logs.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request

VERSION = "0.28.0"
REGISTRY_COMMIT = "fb30ca17193b551473b1f43c315482918ab6987c"  # semconv v1.45.0
REGISTRY_SHA = "aefd780086389034d492f3cbe52e180dd74e6057700ce1663c59d21c8a497818"
TOOLS = {
    ("Linux", "x86_64"): ("x86_64-unknown-linux-musl", "69069769ec3509c358ddbfbc29ff9965590fe4f8dd8b03e1c1e1be1ae56122e8"),
    ("Linux", "aarch64"): ("aarch64-unknown-linux-musl", "55a47e3d6226a372570b65853e56413266c149aaa7716172bdffb0dc8422d544"),
    ("Darwin", "arm64"): ("aarch64-apple-darwin", "b334b37372325f77374b461fd6a11d38bc050122832eb83a9732fcd6831a5ab1"),
    ("Darwin", "x86_64"): ("x86_64-apple-darwin", "40dd65d72b43bc97041b849203e450b322cd786629af8f926cfd2d05798d9ca4"),
}
MAX_CAPTURE = 16 * 1024 * 1024


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fetch(url, expected, target):
    with urllib.request.urlopen(url, timeout=60) as response, target.open("xb") as stream:
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > 128 * 1024 * 1024:
                raise ValueError("instrument download exceeds 128 MiB")
            stream.write(chunk)
    if digest(target) != expected:
        raise ValueError("instrument archive checksum mismatch")


def unpack(archive, destination):
    destination.mkdir()
    with tarfile.open(archive) as source:
        size = 0
        for member in source.getmembers():
            path = Path(member.name)
            size += member.size
            if (path.is_absolute() or ".." in path.parts or member.issym()
                    or member.islnk() or not (member.isdir() or member.isfile())
                    or size > 512 * 1024 * 1024):
                raise ValueError("unsafe or oversized instrument archive")
        source.extractall(destination)


def provision(work):
    triple, sha = TOOLS[(platform.system(), platform.machine())]
    archive = work / "weaver.tar.xz"
    fetch(f"https://github.com/open-telemetry/weaver/releases/download/v{VERSION}/weaver-{triple}.tar.xz", sha, archive)
    unpack(archive, work / "tool")
    registry = work / "semconv.tar.gz"
    fetch(f"https://codeload.github.com/open-telemetry/semantic-conventions/tar.gz/{REGISTRY_COMMIT}", REGISTRY_SHA, registry)
    unpack(registry, work / "registry")
    return work / "tool" / f"weaver-{triple}" / "weaver", work / "registry" / f"semantic-conventions-{REGISTRY_COMMIT}" / "model"


def custom_registry(work, official):
    """Use Weaver's supported registry dependency mechanism, never policy filters."""
    directory = work / "busbar-registry"
    directory.mkdir()
    extension = Path(__file__).with_name("registry") / "busbar.yaml"
    shutil.copyfile(extension, directory / "busbar.yaml")
    # JSON is YAML; using its serializer safely quotes the local dependency path.
    write(directory / "manifest.yaml", {
        "schema_url": "https://getbusbar.dev/schemas/otel/1.6.0",
        "description": "Busbar custom dynamic metadata plus official OTel semantic conventions",
        "dependencies": [{"schema_url": "https://opentelemetry.io/schemas/1.45.0",
                          "registry_path": str(official)}]})
    return directory, digest(extension)


def any_value(value):
    if not value:
        return None, None
    if len(value) != 1:
        raise ValueError("ambiguous/empty OTLP attribute value")
    key, data = next(iter(value.items()))
    if key == "stringValue" and isinstance(data, str):
        return data, "string"
    if key == "boolValue" and isinstance(data, bool):
        return data, "boolean"
    if key == "intValue" and isinstance(data, (str, int)) and not isinstance(data, bool):
        return int(data), "int"
    if key == "doubleValue" and isinstance(data, (int, float)) and not isinstance(data, bool):
        return data, "double"
    if key == "arrayValue":
        elements = [any_value(item) for item in data.get("values", [])]
        kinds = {kind for _, kind in elements}
        if len(kinds) == 1 and None not in kinds and not next(iter(kinds)).endswith("[]"):
            return [item for item, _ in elements], next(iter(kinds)) + "[]"
        # Weaver permits a value without a declared primitive type. Preserve
        # heterogeneous/null arrays verbatim instead of dropping or coercing them.
        return [item for item, _ in elements], None
    raise ValueError("OTLP attribute cannot be represented losslessly as a Weaver sample")


def attributes(values):
    result = []
    for item in values:
        if not isinstance(item.get("key"), str) or not item["key"]:
            raise ValueError("missing OTLP attribute key")
        value, kind = any_value(item["value"])
        result.append({"name": item["key"], "value": value, "type": kind})
    return result


def samples(capture):
    """Preserve every span/resource/scope/event/link attribute without renaming it."""
    if capture.is_symlink() or not capture.is_file() or capture.stat().st_size > MAX_CAPTURE:
        raise ValueError("missing, indirect, or oversized actual exporter capture")
    output, spans = [], 0
    kinds = {0: "internal", 1: "internal", 2: "server", 3: "client", 4: "producer", 5: "consumer"}
    for line in capture.read_text().splitlines():
        if not line.strip():
            continue
        for resource in json.loads(line)["resourceSpans"]:
            output.append({"resource": {"attributes": attributes(resource.get("resource", {}).get("attributes", []))}})
            for scope in resource["scopeSpans"]:
                # Weaver's JSON form cannot associate a resource/scope with a span;
                # check scope attributes individually instead of discarding them.
                output.extend({"attribute": a} for a in attributes(scope.get("scope", {}).get("attributes", [])))
                for span in scope["spans"]:
                    spans += 1
                    output.append({"span": {
                        "name": span["name"], "kind": kinds[span.get("kind", 0)],
                        "status": {"code": {0: "unset", 1: "ok", 2: "error"}[span.get("status", {}).get("code", 0)],
                                   "message": span.get("status", {}).get("message", "")},
                        "attributes": attributes(span.get("attributes", [])),
                        "span_events": [{"name": e["name"], "attributes": attributes(e.get("attributes", []))}
                                        for e in span.get("events", [])],
                        "span_links": [{"attributes": attributes(link.get("attributes", []))}
                                       for link in span.get("links", [])],
                    }})
    if spans == 0:
        raise ValueError("actual exporter capture contains no spans")
    return output, spans


def evaluate(tool, registry, name, sample, evidence):
    input_file = evidence / f"{name}-samples.json"
    write(input_file, sample)
    config = evidence / "weaver.toml"
    config.write_text("")  # Never inherit a caller's finding filters/config discovery.
    directory = evidence / name
    command = [str(tool), "registry", "live-check", "--config", str(config), "--registry", str(registry),
               "--input-source", str(input_file), "--input-format", "json", "--format", "json",
               "--output", str(directory), "--no-stream", "--include-unreferenced", "--fail-on", "violation"]
    with (evidence / f"{name}.log").open("w") as log:
        rc = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log,
                            stderr=subprocess.STDOUT, timeout=180).returncode
    report_path = directory / "live_check.json"
    report = json.loads(report_path.read_text())
    if len(report.get("samples", [])) != len(sample) or not report.get("statistics", {}).get("total_entities"):
        raise ValueError(f"{name}: Weaver produced incomplete/empty assessment")
    levels = report["statistics"]["advice_level_counts"]
    return {"exit_code": rc, "violations": levels.get("violation", 0),
            "advice_level_counts": levels, "advice_type_counts": report["statistics"]["advice_type_counts"],
            "report_sha256": digest(report_path)}


def main():
    out = Path(os.environ["CONFORMANCE_OUT"]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    evidence = out / "evidence"
    evidence.mkdir()
    work = out / "work"
    work.mkdir()
    assessment = {"weaver_version": VERSION, "semconv_commit": REGISTRY_COMMIT,
                  "scope": "Actual exporter span/resource/event/link attributes against official OTel plus declared Busbar custom metadata; no metrics/logs, certification, or full instrumentation coverage claim",
                  "criteria": "Unmodified official Weaver policies; fail-on violation; all advice retained"}
    status, reason = "fail", "evaluation did not complete"
    try:
        tool, registry = provision(work)
        combined, extension_sha = custom_registry(work, registry)
        assessment["custom_registry_sha256"] = extension_sha
        control = [{"attribute": {"name": "service.name", "value": "busbar-control", "type": "string"}}]
        negative = copy.deepcopy(control)
        negative[0]["attribute"].update(value=42, type="int")
        assessment["control"] = evaluate(tool, combined, "control", control, evidence)
        assessment["negative"] = evaluate(tool, combined, "negative", negative, evidence)
        if assessment["control"]["exit_code"] != 0 or assessment["control"]["violations"]:
            raise ValueError("official service.name control failed")
        neg = assessment["negative"]
        if neg["exit_code"] != 1 or neg["advice_type_counts"].get("type_mismatch") != 1 or neg["violations"] != 1:
            raise ValueError("official judge did not identify the planted type_mismatch")
        prior = out.parent / "otlp"
        verdict = json.loads((prior / "verdict.json").read_text())
        if verdict.get("suite") != "otlp" or verdict.get("status") != "pass" or verdict.get("armed") is not True:
            raise ValueError("this invocation's real OTLP exporter/Collector evaluation did not pass")
        capture = prior / "work/subject/traces.json"
        sample, count = samples(capture)
        assessment.update(capture_sha256=digest(capture), source_verdict_sha256=digest(prior / "verdict.json"), spans=count)
        # Keep the base-only result visible: a custom-registry pass is never
        # presented as if custom Busbar fields belonged to official semconv.
        assessment["official_base_only"] = evaluate(tool, registry, "official-base-only", sample, evidence)
        assessment["subject"] = evaluate(tool, combined, "subject", sample, evidence)
        sub = assessment["subject"]
        status = "pass" if sub["exit_code"] == 0 and sub["violations"] == 0 else "fail"
        reason = (f"{count} actual exported spans; combined OTel + Busbar custom registry: {sub['violations']} violations; "
                  f"base-only OTel registry: {assessment['official_base_only']['violations']} violations (retained separately); traces only")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        reason = f"Weaver evaluation unavailable or incomplete: {type(error).__name__}: {error}"
    assessment.update(status=status, reason=reason)
    write(evidence / "assessment.json", assessment)
    write(out / "verdict.json", {"suite": "otel-semconv-weaver", "status": status, "armed": True,
          "standard": "OpenTelemetry semantic conventions plus Busbar custom metadata (exported traces)",
          "plan": assessment["criteria"] + "; positive and invalid-type controls; actual captured exporter spans",
          "spec_version": f"Weaver {VERSION}; semantic-conventions v1.45.0 ({REGISTRY_COMMIT})", "reason": reason})
    print(reason)
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
