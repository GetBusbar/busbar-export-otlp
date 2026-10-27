#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The 'intact' half of the OTLP conformance suite, stdlib only (run with python3 -I).

  check.py compare  <fixture.jsonl> <traces.json>        every fixture span arrived intact
  check.py bites    <fixture.jsonl> <traces.json>        the comparison catches planted damage
  check.py control  <dir> <service> <signal> <min>       telemetrygen data arrived well-formed

<traces.json> is the collector file exporter's output: one OTLP/JSON request per line.
The expected spans are derived here from the fixture, independently of the sink's encoder, from the
rules in export-otlp/src/proto.rs's header (the documented mapping), then both sides are reduced to
one canonical form and compared exactly.
"""
import copy, json, re, sys

HEX16 = re.compile(r"^[0-9a-fA-F]{16}$")
ATTRS = ["pool", "ingress", "op", "lane", "provider", "model"]


def val(v):
    """A fixture JSON value as the canonical OTLP AnyValue."""
    if isinstance(v, bool):
        return ("bool", v)
    if isinstance(v, str):
        return ("str", v)
    if isinstance(v, int):
        return ("int", v)
    if isinstance(v, float):
        return ("double", v)
    if isinstance(v, list):
        return ("array", [val(x) for x in v])
    return ("str", json.dumps(v, separators=(",", ":")))


def sid(x):
    if isinstance(x, str) and HEX16.match(x) and int(x, 16) != 0:
        return x.lower()
    return None


def kvs(lst):
    out = []
    for kv in lst or []:
        if isinstance(kv, dict) and isinstance(kv.get("key"), str) and "value" in kv:
            out.append((kv["key"], val(kv["value"])))
    return out


def expected(fixture):
    spans = []
    for line in open(fixture, encoding="utf-8"):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not isinstance(r, dict):
            continue
        full = r.get("span") if isinstance(r.get("span"), dict) else None
        src = full if full is not None else r
        t, s = sid(src.get("trace_id")), sid(src.get("span_id"))
        if not t or not s:
            continue
        p = sid(src.get("parent_span_id")) or ""
        if full is not None:
            st = full.get("status") or {}
            err = st.get("code") == "error"
            spans.append(dict(
                trace="0" * 16 + t, span=s, parent=p, name=full.get("name") or "", kind=1,
                start=int(full.get("start_ns") or 0), end=int(full.get("end_ns") or 0),
                attrs=kvs(full.get("attributes")),
                events=[dict(time=int(e.get("time_ns") or 0), name=e.get("name") or "",
                             attrs=kvs(e.get("attributes"))) for e in full.get("events") or []],
                status=(2, st.get("message") or "") if err else (0, "")))
        else:
            start = int(r.get("start") or 0) * 1000
            attrs = [(k, val(r[k])) for k in ATTRS if r.get(k) is not None]
            spans.append(dict(
                trace="0" * 16 + t, span=s, parent=p, name=r.get("name") or "", kind=1,
                start=start, end=start + int(r.get("duration_us") or 0) * 1000,
                attrs=attrs, events=[], status=(0, "")))
    return spans


def anyval(a):
    (k, v), = a.items()
    if k == "stringValue":
        return ("str", v)
    if k == "intValue":
        return ("int", int(v))
    if k == "boolValue":
        return ("bool", v)
    if k == "doubleValue":
        return ("double", float(v))
    if k == "arrayValue":
        return ("array", [anyval(x) for x in v.get("values", [])])
    return (k, v)


def akv(lst):
    return [(kv["key"], anyval(kv["value"])) for kv in lst or []]


def received(path):
    """(resource attrs, scope name, canonical span) for every span in the collector's file."""
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        for rs in json.loads(line).get("resourceSpans", []):
            res = akv(rs.get("resource", {}).get("attributes"))
            for ss in rs.get("scopeSpans", []):
                scope = ss.get("scope", {}).get("name", "")
                for sp in ss.get("spans", []):
                    st = sp.get("status") or {}
                    out.append((res, scope, dict(
                        trace=sp.get("traceId", ""), span=sp.get("spanId", ""),
                        parent=sp.get("parentSpanId", ""), name=sp.get("name", ""),
                        kind=sp.get("kind", 0), start=int(sp.get("startTimeUnixNano", 0)),
                        end=int(sp.get("endTimeUnixNano", 0)), attrs=akv(sp.get("attributes")),
                        events=[dict(time=int(e.get("timeUnixNano", 0)), name=e.get("name", ""),
                                     attrs=akv(e.get("attributes"))) for e in sp.get("events", [])],
                        status=(st.get("code", 0), st.get("message", "")))))
    return out


def compare(fixture, traces):
    want = expected(fixture)
    got = received(traces)
    problems = []
    if not want:
        return ["the fixture holds no span: nothing to compare"]
    for res, scope, _ in got:
        if res != [("service.name", ("str", "busbar"))]:
            problems.append(f"resource is {res}, not service.name=busbar")
            break
    for _, scope, _ in got:
        if scope != "busbar":
            problems.append(f"scope name is {scope!r}, not 'busbar'")
            break
    by = {(s["trace"], s["span"]): s for _, _, s in got}
    if len(by) != len(got):
        problems.append("a span arrived more than once")
    for w in want:
        g = by.pop((w["trace"], w["span"]), None)
        if g is None:
            problems.append(f"span {w['span']} ({w['name']}) never arrived")
            continue
        for k in w:
            if w[k] != g[k]:
                problems.append(f"span {w['name']}: {k} arrived as {g[k]!r}, sent {w[k]!r}")
    for (t, s), g in by.items():
        problems.append(f"unexpected span {s} ({g['name']}) arrived")
    return problems


def bites(fixture, traces):
    """Damage the received spans in ways a lossy exporter would; every one must be caught."""
    lines = [json.loads(l) for l in open(traces, encoding="utf-8") if l.strip()]
    if compare(fixture, traces):
        return ["the undamaged file does not compare clean; cannot test the comparison"]

    def spans(doc):
        for rs in doc["resourceSpans"]:
            for ss in rs["scopeSpans"]:
                for sp in ss["spans"]:
                    yield rs, ss, sp

    def first(doc, pred):
        return next(x for x in spans(doc) if pred(x[2]))

    muts = {
        "a dropped attribute": lambda d: first(d, lambda s: len(s.get("attributes", [])) > 1)[2]["attributes"].pop(0),
        "a changed attribute type": lambda d: first(d, lambda s: s.get("attributes"))[2]["attributes"][0]["value"].update({"intValue": "1"}) or first(d, lambda s: s.get("attributes"))[2]["attributes"][0]["value"].pop("stringValue", None),
        "a shifted timestamp": lambda d: first(d, lambda s: True)[2].update(startTimeUnixNano=str(int(first(d, lambda s: True)[2]["startTimeUnixNano"]) + 1)),
        "a changed span id": lambda d: first(d, lambda s: True)[2].update(spanId="ffffffffffffffff"),
        "a lost parent": lambda d: first(d, lambda s: s.get("parentSpanId"))[2].pop("parentSpanId"),
        "a lost event": lambda d: first(d, lambda s: s.get("events"))[2]["events"].pop(),
        "a lost resource": lambda d: first(d, lambda s: True)[0].pop("resource"),
        "a lost span": lambda d: first(d, lambda s: True)[1]["spans"].pop(0),
    }
    import tempfile, os
    missed = []
    for name, mut in muts.items():
        doc = copy.deepcopy(lines)
        mut(doc[0] if name != "a lost event" and name != "a lost parent" else next(d for d in doc if any(
            (s.get("events") if name == "a lost event" else s.get("parentSpanId")) for _, _, s in spans(d))))
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("\n".join(json.dumps(d) for d in doc) + "\n")
        try:
            if not compare(fixture, f.name):
                missed.append(name)
        finally:
            os.unlink(f.name)
    return [f"the comparison did not catch: {m}" for m in missed]


def control(directory, service, signal, minimum):
    path = f"{directory}/{signal}.json"
    key = {"traces": "resourceSpans", "metrics": "resourceMetrics", "logs": "resourceLogs"}[signal]
    inner = {"traces": ("scopeSpans", "spans"), "metrics": ("scopeMetrics", "metrics"),
             "logs": ("scopeLogs", "logRecords")}[signal]
    n, problems = 0, []
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        for r in json.loads(line).get(key, []):
            svc = dict(akv(r.get("resource", {}).get("attributes"))).get("service.name")
            if svc != ("str", service):
                continue
            for sc in r.get(inner[0], []):
                for it in sc.get(inner[1], []):
                    if signal == "metrics":
                        pts = 0
                        for kind in ("gauge", "sum", "histogram"):
                            pts += len(it.get(kind, {}).get("dataPoints", []))
                        n += pts
                    else:
                        n += 1
                        if signal == "traces":
                            if not re.fullmatch(r"[0-9a-f]{32}", it.get("traceId", "")) or not re.fullmatch(r"[0-9a-f]{16}", it.get("spanId", "")):
                                problems.append("a span without well-formed ids")
                            if int(it["endTimeUnixNano"]) < int(it["startTimeUnixNano"]):
                                problems.append("a span that ends before it starts")
                        if signal == "logs" and not it.get("timeUnixNano"):
                            problems.append("a log record without a timestamp")
    if n < int(minimum):
        problems.append(f"{signal} for service {service}: {n} arrived, at least {minimum} sent")
    return problems


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    fn = {"compare": compare, "bites": bites, "control": control}[cmd]
    problems = fn(*args)
    for p in problems:
        print("FAIL:", p)
    if not problems:
        print(f"ok: {cmd} {' '.join(args[1:])}")
    sys.exit(1 if problems else 0)
