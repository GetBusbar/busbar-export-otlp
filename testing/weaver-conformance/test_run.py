#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("weaver_rig", Path(__file__).with_name("run.py"))
rig = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rig)


class Samples(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def capture(self, spans):
        path = self.root / "traces.json"
        rig.write(path, {"resourceSpans": [{"resource": {"attributes": []}, "scopeSpans": [{"spans": spans}]}]})
        # Collector emits one complete OTLP request per line.
        path.write_text(json.dumps(json.loads(path.read_text())) + "\n")
        return path

    def test_actual_attribute_names_and_types_survive_without_semantic_rewriting(self):
        sample, count = rig.samples(self.capture([{"name": "request", "kind": 1, "attributes": [
            {"key": "pool", "value": {"stringValue": "main"}},
            {"key": "service.name", "value": {"intValue": "42"}},
            {"key": "array", "value": {"arrayValue": {"values": [{}, {"boolValue": True}, {"stringValue": "x"}]}}},
        ], "events": [{"name": "event", "attributes": [{"key": "e", "value": {"boolValue": False}}]}]}]))
        self.assertEqual(count, 1)
        span = sample[1]["span"]
        self.assertEqual(span["attributes"], [
            {"name": "pool", "value": "main", "type": "string"},
            {"name": "service.name", "value": 42, "type": "int"},
            {"name": "array", "value": [None, True, "x"], "type": None}])
        self.assertEqual(span["span_events"][0]["attributes"][0]["value"], False)

    def test_no_spans_is_refused_even_when_resources_exist(self):
        with self.assertRaisesRegex(ValueError, "no spans"):
            rig.samples(self.capture([]))

    def test_indirect_capture_is_refused(self):
        target = self.capture([{"name": "request"}])
        link = self.root / "link.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "indirect"):
            rig.samples(link)

    def test_ambiguous_or_unsupported_wire_values_cannot_silently_disappear(self):
        for value in [{"intValue": "1", "stringValue": "1"}, {"bytesValue": "YQ=="}, {"intValue": 1.5}]:
            with self.assertRaises(ValueError):
                rig.any_value(value)

    def test_empty_official_report_cannot_pass(self):
        report = self.root / "subject"
        report.mkdir()
        rig.write(report / "live_check.json", {"samples": [], "statistics": {"total_entities": 0}})
        with patch.object(rig.subprocess, "run") as run:
            run.return_value.returncode = 0
            with self.assertRaisesRegex(ValueError, "incomplete/empty"):
                rig.evaluate(Path("weaver"), Path("registry"), "subject", [{"attribute": {"name": "service.name"}}], self.root)


if __name__ == "__main__":
    unittest.main()
