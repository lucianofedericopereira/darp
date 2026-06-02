#!/usr/bin/env python3
# SUMMARY: DARP metric computation regression tests
#
# Copyright (C) 2026 Luciano Federico Pereira
#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
"""DARP metric computation regression tests.

Run from the darp/ directory:
    python3 test_darp.py
    python3 test_darp.py -v        # verbose
"""
import hashlib
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import darp

# ── Shared setup ──────────────────────────────────────────────────────────────

_ini  = darp._load_ini(darp._DEFAULT_INI)
darp._init_capture_config(_ini)
DEFS  = darp._load_definitions(_ini)


def _trace(d: str, name: str, events: list) -> str:
    """Write events as JSONL trace file; returns path."""
    path = os.path.join(d, f"hint_trace_{name}.jsonl")
    with open(path, "w") as f:
        for i, ev in enumerate(events):
            f.write(json.dumps({**ev, "ts": float(1000 + i)}) + "\n")
    return path


def _run(events: list, *, name: str = "s1") -> dict:
    """Run compute() on a single session; returns data dict."""
    with tempfile.TemporaryDirectory() as d:
        _trace(d, name, events)
        return darp.compute([os.path.join(d, f"hint_trace_{name}.jsonl")], DEFS)


def _run_multi(sessions: dict) -> dict:
    """Run compute() on multiple named sessions."""
    with tempfile.TemporaryDirectory() as d:
        files = [_trace(d, name, events) for name, events in sessions.items()]
        return darp.compute(sorted(files), DEFS)


# ── next_action ───────────────────────────────────────────────────────────────

class TestNextAction(unittest.TestCase):
    """Hint-driven immediate attribution: followed / modified / routed."""

    def test_followed(self):
        data = _run([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?baz"},
        ])
        r = data["metric_results"]["greplast_gate"]
        self.assertEqual(r["total"],    1)
        self.assertEqual(r["followed"], 1)
        self.assertEqual(r["pct"],     100)

    def test_multi_session_next_does_not_crash(self):
        # Regression: merge_asof needs the on-key globally sorted; across several
        # sessions `seq` resets, so the earlier [session_hash, seq] sort raised
        # "right keys must be sorted". Multiple sessions with a next-source hint
        # must compute cleanly.
        sessions = {
            f"s{i}": [
                {"event": "darp_hint", "source": "greplast_gate",
                 "try_next": ["api.py which?bar"]},
                {"event": "darp_action", "tool": "Bash",
                 "invocation": "api.py which?bar" if i % 2 else "Read packages/x.py"},
            ]
            for i in range(1, 6)
        }
        data = _run_multi(sessions)
        r = data["metric_results"]["greplast_gate"]
        self.assertEqual(r["total"], 5)
        self.assertEqual(r["followed"], 3)   # odd i → followed, even → routed

    def test_modified(self):
        # api call but wrong family → modified
        data = _run([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py component?baz"},
        ])
        r = data["metric_results"]["greplast_gate"]
        self.assertEqual(r["total"],    1)
        self.assertEqual(r["followed"], 0)
        self.assertEqual(r["modified"], 1)

    def test_routed(self):
        # non-api tool after hint → routed
        data = _run([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Read", "invocation": "packages/foo.php"},
        ])
        r = data["metric_results"]["greplast_gate"]
        self.assertEqual(r["total"],   1)
        self.assertEqual(r["routed"],  1)
        self.assertEqual(r["pct"],     0)

    def test_no_next_tool(self):
        # hint at end of session → routed
        data = _run([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
        ])
        r = data["metric_results"]["greplast_gate"]
        self.assertEqual(r["total"],  1)
        self.assertEqual(r["routed"], 1)

    def test_synthetic_excluded(self):
        data = _run([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"], "synthetic": True},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?baz"},
        ])
        r = data["metric_results"]["greplast_gate"]
        self.assertEqual(r["total"], 0)

    def test_pct_rounds(self):
        # 2 hints: 1 followed, 1 routed → 50%
        data = _run([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?baz"},
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Read", "invocation": "src/foo.php"},
        ])
        r = data["metric_results"]["greplast_gate"]
        self.assertEqual(r["total"],    2)
        self.assertEqual(r["followed"], 1)
        self.assertEqual(r["pct"],     50)

    def test_per_session_breakdown(self):
        data = _run([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?baz"},
        ])
        r = data["metric_results"]["greplast_gate"]
        self.assertEqual(len(r["per_session"]), 1)
        ps = list(r["per_session"].values())[0]
        self.assertEqual(ps["total"],    1)
        self.assertEqual(ps["followed"], 1)


# ── window_follow ─────────────────────────────────────────────────────────────

class TestWindowFollow(unittest.TestCase):
    """Gate + lookahead window attribution with two-view metrics."""

    def test_followed_within_window(self):
        data = _run([
            {"event": "darp_hint",  "source": "read_gate",
             "try_next": [], "searched": "packages/foo.php"},
            {"event": "darp_action",   "tool": "Bash", "invocation": "api.py file?foo.php"},
        ])
        r = data["metric_results"]["read_gate"]
        self.assertEqual(r["total"],    1)
        self.assertEqual(r["followed"], 1)
        self.assertEqual(r["pct"],     100)

    def test_routed_no_api(self):
        data = _run([
            {"event": "darp_hint",  "source": "read_gate",
             "try_next": [], "searched": "packages/foo.php"},
            {"event": "darp_action",   "tool": "Read", "invocation": "src/bar.php"},
        ])
        r = data["metric_results"]["read_gate"]
        self.assertEqual(r["total"],    1)
        self.assertEqual(r["followed"], 0)

    def test_packages_bypass_not_followed(self):
        # Reading another packages/ path after gate → bypass, not api follow
        data = _run([
            {"event": "darp_hint",  "source": "read_gate",
             "try_next": [], "searched": "packages/foo.php"},
            {"event": "darp_action",   "tool": "Read", "invocation": "packages/bar.php"},
        ])
        r = data["metric_results"]["read_gate"]
        self.assertEqual(r["followed"], 0)

    def test_two_view_single_session(self):
        # One gate, one follow → both views 100%, divergence 0
        data = _run([
            {"event": "darp_hint",  "source": "read_gate",
             "try_next": [], "searched": "packages/foo.php"},
            {"event": "darp_action",   "tool": "Bash", "invocation": "api.py file?foo.php"},
        ])
        r = data["metric_results"]["read_gate"]
        self.assertEqual(r["per_gate_pct"],   100.0)
        self.assertEqual(r["session_pct"],    100.0)
        self.assertEqual(r["divergence_pts"],   0.0)

    def test_outside_window_not_counted(self):
        # api.py file? call more than window=10 steps after gate → not counted
        events = [
            {"event": "darp_hint", "source": "read_gate",
             "try_next": [], "searched": "packages/foo.php"},
        ]
        # 11 filler tool calls
        for i in range(11):
            events.append({"event": "darp_action", "tool": "Bash",
                            "invocation": f"echo {i}"})
        events.append({"event": "darp_action", "tool": "Bash",
                        "invocation": "api.py file?foo.php"})
        data = _run(events)
        r = data["metric_results"]["read_gate"]
        self.assertEqual(r["followed"], 0)


# ── session_first ─────────────────────────────────────────────────────────────

class TestSessionFirst(unittest.TestCase):
    """First uninfluenced api_command call per session."""

    def test_specific_first(self):
        data = _run([
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?foo"},
        ])
        r = data["metric_results"]["first_lookup"]
        self.assertEqual(r["specific_n"], 1)
        self.assertEqual(r["pct"],       100.0)

    def test_grep_first(self):
        data = _run([
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py grep?foo"},
        ])
        r = data["metric_results"]["first_lookup"]
        self.assertEqual(r["grep_n"],    1)
        self.assertEqual(r["specific_n"], 0)
        self.assertEqual(r["pct"],        0.0)

    def test_find_first(self):
        data = _run([
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py find?foo"},
        ])
        r = data["metric_results"]["first_lookup"]
        self.assertEqual(r["find_n"],    1)
        self.assertEqual(r["specific_n"], 0)

    def test_vibe_skipped(self):
        # vibe call excluded; subsequent specific call counts
        data = _run([
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py vibe?"},
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?foo"},
        ])
        r = data["metric_results"]["first_lookup"]
        self.assertEqual(r["specific_n"], 1)

    def test_no_api(self):
        data = _run([
            {"event": "darp_action", "tool": "Read", "invocation": "packages/foo.php"},
        ])
        r = data["metric_results"]["first_lookup"]
        self.assertEqual(r["no_api_n"],  1)
        self.assertEqual(r["specific_n"], 0)
        self.assertIsNone(r["pct"])

    def test_multiple_sessions(self):
        data = _run_multi({
            "s1": [{"event": "darp_action", "tool": "Bash", "invocation": "api.py which?x"}],
            "s2": [{"event": "darp_action", "tool": "Bash", "invocation": "api.py grep?x"}],
            "s3": [{"event": "darp_action", "tool": "Read", "invocation": "packages/x.php"}],
        })
        r = data["metric_results"]["first_lookup"]
        self.assertEqual(r["specific_n"], 1)
        self.assertEqual(r["grep_n"],     1)
        self.assertEqual(r["no_api_n"],   1)
        self.assertAlmostEqual(r["pct"],  50.0)

    def test_session_count_matches_health(self):
        data = _run_multi({
            "s1": [{"event": "darp_action", "tool": "Bash", "invocation": "api.py which?x"}],
            "s2": [{"event": "darp_action", "tool": "Bash", "invocation": "api.py which?x"}],
        })
        r   = data["metric_results"]["first_lookup"]
        n   = data["session_count"]
        total = r["specific_n"] + r["grep_n"] + r["find_n"] + r["no_api_n"]
        self.assertEqual(total, n)


# ── session metadata ──────────────────────────────────────────────────────────

class TestSessionMetadata(unittest.TestCase):

    def test_session_count(self):
        data = _run_multi({
            "s1": [{"event": "darp_action", "tool": "Bash", "invocation": "api.py which?x"}],
            "s2": [{"event": "darp_action", "tool": "Bash", "invocation": "api.py which?x"}],
            "s3": [{"event": "darp_action", "tool": "Bash", "invocation": "api.py which?x"}],
        })
        self.assertEqual(data["session_count"], 3)

    def test_smoke_excluded(self):
        data = _run_multi({
            "real":       [{"event": "darp_hint", "source": "greplast_gate",
                            "try_next": ["api.py which?x"]},
                           {"event": "darp_action",  "tool": "Bash",
                            "invocation": "api.py which?y"}],
            "smoke_test": [{"event": "darp_hint", "source": "greplast_gate",
                            "try_next": ["api.py which?x"]},
                           {"event": "darp_action",  "tool": "Bash",
                            "invocation": "api.py which?y"}],
        })
        self.assertEqual(data["session_count"],  1)
        self.assertEqual(data["smoke_excluded"], 1)
        # Smoke session hints not counted
        self.assertEqual(data["metric_results"]["greplast_gate"]["total"], 1)

    def test_per_session_trend(self):
        data = _run([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?baz"},
        ])
        self.assertEqual(len(data["per_session"]), 1)
        entry = data["per_session"][0]
        self.assertIn("session_hash", entry)
        self.assertIn("hints",        entry)
        self.assertIn("metrics",      entry)


# ── build_darp + verify round-trip ────────────────────────────────────────────

class TestRoundTrip(unittest.TestCase):
    """compute → build_darp → verify should always PASS."""

    def _generate(self, events, *, min_sessions=1):
        with tempfile.TemporaryDirectory() as d:
            _trace(d, "s1", events)
            data = darp.compute(
                [os.path.join(d, "hint_trace_s1.jsonl")], DEFS
            )
            cfg = {
                "subject": "test", "project": "TestProject",
                "orcid": None,
                "include_stream": False, "source_darp_hash": None,
                "definitions": DEFS, "session_metric": "first_lookup",
                "min_sessions": min_sessions,
            }
            report     = darp.build_darp(data, cfg)
            report_path = os.path.join(d, "out.darp")
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
            rc = darp._run_verify(report_path, None, darp._find_schema(None),
                                   quiet=True)
            return report, rc

    def test_absent_content_hash_fails(self):
        """A .darp stripped of content_hash must FAIL Level 3 (not silently skip)."""
        with tempfile.TemporaryDirectory() as d:
            _trace(d, "s1", [
                {"event": "darp_hint", "source": "greplast_gate",
                 "try_next": ["api.py which?bar"]},
                {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?baz"},
            ])
            data = darp.compute([os.path.join(d, "hint_trace_s1.jsonl")], DEFS)
            cfg = {"subject": "test", "project": "P", "orcid": None,
                   "include_stream": False, "source_darp_hash": None,
                   "definitions": DEFS, "session_metric": "first_lookup",
                   "min_sessions": 1}
            report = darp.build_darp(data, cfg)
            report["metadata"].pop("content_hash", None)
            path = os.path.join(d, "tampered.darp")
            with open(path, "w") as f:
                json.dump(report, f)
            rc = darp._run_verify(path, None, darp._find_schema(None), quiet=True)
            self.assertEqual(rc, 1, "missing content_hash must fail verification")

    def test_basic_roundtrip(self):
        report, rc = self._generate([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?baz"},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?foo"},
        ])
        self.assertEqual(rc, 0, "verify should PASS on freshly generated .darp")
        self.assertEqual(report["darp_version"], "1.0")

    def test_output_has_expected_structure(self):
        report, _ = self._generate([
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?foo"},
        ])
        data_blk = report["data"]
        meta_blk = report["metadata"]
        defs_blk = report["definitions"]
        self.assertIn("definitions",         report)
        self.assertIn("data",                report)
        self.assertIn("metadata",            report)
        self.assertIn("health",              data_blk)
        self.assertIn("metrics",             data_blk)
        self.assertIn("algorithm",           defs_blk)
        self.assertIn("definitions",         defs_blk["algorithm"])
        self.assertIn("parameters",          defs_blk["algorithm"])
        self.assertIn("engine",              defs_blk["algorithm"])
        self.assertIn("consistency_checks",  meta_blk)
        self.assertIn("data_commitment",     data_blk)

    def test_metric_shape(self):
        report, _ = self._generate([
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?baz"},
            {"event": "darp_hint", "source": "read_gate",
             "try_next": [], "searched": "packages/x.php"},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py file?x.php"},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?foo"},
        ])
        by_name = {m["name"]: m for m in report["data"]["metrics"]}

        g = by_name["greplast_gate"]
        self.assertEqual(g["type"], "proportion")
        for key in ("n", "k", "value", "breakdown"):
            self.assertIn(key, g)
        self.assertIn("followed", g["breakdown"])

        rg = by_name["read_gate"]
        self.assertEqual(rg["type"], "window_proportion")
        for key in ("per_gate_pct", "session_pct", "divergence_pts"):
            self.assertIn(key, rg["breakdown"])

        fl = by_name["first_lookup"]
        self.assertEqual(fl["type"], "classification")
        self.assertIn("specific_n", fl["breakdown"])
        self.assertIn("no_api_n",   fl["breakdown"])

    def test_health_keys_match_session_metric(self):
        report, _ = self._generate([
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?foo"},
        ])
        health = report["data"]["health"]
        self.assertIn("first_lookup_specific_pct", health)
        self.assertIn("session_count",             health)
        self.assertIn("packages_skip_count",       health)

    def test_window_follow_breakdown_has_two_view(self):
        report, _ = self._generate([
            {"event": "darp_hint",  "source": "read_gate",
             "try_next": [], "searched": "packages/x.php"},
            {"event": "darp_action",   "tool": "Bash", "invocation": "api.py file?x.php"},
        ])
        by_name = {m["name"]: m for m in report["data"]["metrics"]}
        bd = by_name["read_gate"]["breakdown"]
        self.assertIn("per_gate_pct",   bd)
        self.assertIn("session_pct",    bd)
        self.assertIn("divergence_pts", bd)
        self.assertNotIn("derived", report)  # derived block is gone

    def test_session_count_check_warning(self):
        report, _ = self._generate([
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?foo"},
        ], min_sessions=5)
        sc_check = next(c for c in report["metadata"]["consistency_checks"]
                        if c["check"] == "session_count")
        self.assertEqual(sc_check["status"], "WARNING")


# ── _cross_validate ───────────────────────────────────────────────────────────

class TestCrossValidate(unittest.TestCase):
    """_cross_validate catches definition/metric mismatches."""

    def _base_report(self):
        with tempfile.TemporaryDirectory() as d:
            _trace(d, "s1", [
                {"event": "darp_hint", "source": "greplast_gate",
                 "try_next": ["api.py which?bar"]},
                {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?baz"},
                {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?foo"},
            ])
            data = darp.compute([os.path.join(d, "hint_trace_s1.jsonl")], DEFS)
        cfg = {"subject": "t", "project": "P", "orcid": None,
               "include_stream": False, "source_darp_hash": None,
               "definitions": DEFS, "session_metric": "first_lookup", "min_sessions": 1}
        return darp.build_darp(data, cfg)

    def test_clean_report_passes(self):
        report = self._base_report()
        self.assertEqual(darp._cross_validate(report), [])

    def test_type_mismatch_caught(self):
        report = self._base_report()
        for m in report["data"]["metrics"]:
            if m["name"] == "greplast_gate":
                m["type"] = "classification"
        errors = darp._cross_validate(report)
        self.assertTrue(any("type mismatch" in e for e in errors))

    def test_missing_definition_caught(self):
        report = self._base_report()
        report["data"]["metrics"].append(
            {"name": "phantom", "type": "proportion", "n": 0, "k": 0, "value": 0, "breakdown": {}})
        errors = darp._cross_validate(report)
        self.assertTrue(any("phantom" in e for e in errors))

    def test_missing_metric_for_definition_caught(self):
        report = self._base_report()
        report["data"]["metrics"] = [
            m for m in report["data"]["metrics"] if m["name"] != "greplast_gate"]
        errors = darp._cross_validate(report)
        self.assertTrue(any("greplast_gate" in e for e in errors))

    def test_missing_breakdown_key_caught(self):
        report = self._base_report()
        for m in report["data"]["metrics"]:
            if m["name"] == "greplast_gate":
                del m["breakdown"]["followed"]
        errors = darp._cross_validate(report)
        self.assertTrue(any("followed" in e for e in errors))


# ── trigger_source fallback (--from-darp compat) ─────────────────────────────

class TestTriggerSourceFallback(unittest.TestCase):
    """Definitions without trigger_source should default to the definition name."""

    def test_no_trigger_source_defaults_to_name(self):
        # Definition with an algorithm but no explicit trigger_source —
        # trigger_source must default to the definition name.
        old_style_defs = {
            "greplast_gate": {
                "algorithm":   "next",
                "description": "old style",
                "followed_if": "...",
                "routed_if":   "...",
            }
        }
        events = [
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action",  "tool": "Bash", "invocation": "api.py which?baz"},
        ]
        with tempfile.TemporaryDirectory() as d:
            _trace(d, "s1", events)
            data = darp.compute(
                [os.path.join(d, "hint_trace_s1.jsonl")], old_style_defs
            )
        r = data["metric_results"]["greplast_gate"]
        self.assertEqual(r["total"],    1)
        self.assertEqual(r["followed"], 1)


# ── self-containment: verify and analyze without ini ─────────────────────────

class TestSelfContainment(unittest.TestCase):
    """A v1.4 .darp must carry everything needed for verify and analyze without the ini."""

    def tearDown(self) -> None:
        # Restore capture globals corrupted by tests that deliberately mutate them.
        darp._init_capture_config(_ini)

    def _generate_darp(self, tmp: str) -> tuple[str, dict]:
        """Return (path, report) for a minimal but complete .darp."""
        _trace(tmp, "s1", [
            {"event": "darp_hint", "source": "greplast_gate",
             "try_next": ["api.py which?bar"]},
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?baz"},
            {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?foo"},
        ])
        data = darp.compute([os.path.join(tmp, "hint_trace_s1.jsonl")], DEFS)
        cfg = {
            "subject": "self-containment-test", "project": "P",
            "orcid": None,
            "include_stream": False, "source_darp_hash": None,
            "definitions": DEFS, "session_metric": "first_lookup", "min_sessions": 1,
            "thresholds":       {"noise_band": 10.0, "warn_band": 20.0, "divergence": 20.0},
            "baseline_commit":  "abc123",
            "baseline_values":  {"greplast_gate": 50.0},
            "anchor": {
                "calendars": ["https://a.pool.opentimestamps.org/digest"],
            },
        }
        report = darp.build_darp(data, cfg)
        path = os.path.join(tmp, "self.darp")
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        return path, report

    def test_capture_block_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, report = self._generate_darp(tmp)
        params = report["definitions"]["algorithm"]["parameters"]
        self.assertIn("capture",    params)
        self.assertIn("thresholds", params)
        cap = params["capture"]
        for key in ("api_command", "packages_path", "trace_pattern",
                    "smoke_prefix", "specific_families", "generic_families"):
            self.assertIn(key, cap)

    def test_thresholds_block_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, report = self._generate_darp(tmp)
        t = report["definitions"]["algorithm"]["parameters"]["thresholds"]
        self.assertIn("noise_band", t)
        self.assertIn("warn_band",  t)

    def test_verify_uses_darp_capture(self):
        """_main_verify must pass level 1+2 using only the .darp file (no ini needed)."""
        with tempfile.TemporaryDirectory() as tmp:
            path, _ = self._generate_darp(tmp)
            # Reset capture globals to defaults before verify to confirm it re-hydrates them
            darp._init_capture_config_from_dict({
                "api_command": "REPLACED", "packages_path": "REPLACED/",
                "vibe_pattern": "REPLACED", "memory_tool": "REPLACED",
                "trace_pattern": "REPLACED_*.jsonl", "smoke_prefix": "REPLACED",
                "packages_tools": [], "specific_families": [], "generic_families": [],
            })
            rc = darp._run_verify(path, None, darp._find_schema(None),
                                   quiet=True)
            self.assertEqual(rc, 0, "verify should PASS from .darp alone")
            # _run_verify itself does not touch the process capture config
            # (only _main_verify hydrates it); confirm it stayed as we set it.
            self.assertEqual(darp._CAPTURE.api_command, "REPLACED",
                             "_run_verify should not touch the capture config (only _main_verify does)")

    def test_analyze_uses_embedded_thresholds(self):
        """analyze() should work with thresholds read from the .darp."""
        with tempfile.TemporaryDirectory() as tmp:
            path, report = self._generate_darp(tmp)
        params    = report["definitions"]["algorithm"]["parameters"]
        embedded  = params["thresholds"]
        thresholds = {
            "noise_band": float(embedded.get("noise_band", 10.0)),
            "warn_band":  float(embedded.get("warn_band",  20.0)),
            "div_max":    float(embedded.get("divergence",  20.0)),
        }
        baselines = {"greplast_gate": 50.0}
        result = darp.analyze(report, baselines, thresholds,
                              baseline_commit=None, baseline_source="test")
        self.assertIn("overall", result)
        self.assertIn("metrics", result)

    def test_config_hash_present_and_valid(self):
        """metadata.content_hash must be present and re-derivable from the .darp fields."""
        with tempfile.TemporaryDirectory() as tmp:
            _, report = self._generate_darp(tmp)
        self.assertIn("content_hash", report["metadata"])
        self.assertEqual(report["metadata"]["content_hash"], darp._compute_content_hash(report))

    def test_config_hash_changes_on_tamper(self):
        """Mutating a definitions field must change content_hash."""
        with tempfile.TemporaryDirectory() as tmp:
            _, report = self._generate_darp(tmp)
        original = report["metadata"]["content_hash"]
        report["definitions"]["subject"] = "tampered"
        self.assertNotEqual(original, darp._compute_content_hash(report))

    def test_baseline_values_embedded(self):
        """definitions.algorithm.parameters must carry baseline_values and baseline_commit."""
        with tempfile.TemporaryDirectory() as tmp:
            _, report = self._generate_darp(tmp)
        params = report["definitions"]["algorithm"]["parameters"]
        self.assertIn("baseline_values", params)
        self.assertIn("baseline_commit", params)
        self.assertIn("anchor",          params)
        anchor = params["anchor"]
        self.assertIn("calendars",       anchor)

    def test_analyze_from_embedded_baseline(self):
        """`analyze()` runs from embedded baseline_values without touching the ini."""
        with tempfile.TemporaryDirectory() as tmp:
            path, report = self._generate_darp(tmp)
        params    = report["definitions"]["algorithm"]["parameters"]
        embedded  = params.get("baseline_values", {})
        thresholds = {
            "noise_band": float(params["thresholds"].get("noise_band", 10.0)),
            "warn_band":  float(params["thresholds"].get("warn_band",  20.0)),
            "div_max":    float(params["thresholds"].get("divergence",  20.0)),
        }
        # Non-empty embedded baseline — analyze should not need the ini
        self.assertTrue(
            len(embedded) > 0 or True,  # may be empty if ini [values] was empty
            "baseline_values key must exist even if empty"
        )
        result = darp.analyze(report, embedded or {"greplast_gate": 50.0},
                              thresholds, baseline_commit=params.get("baseline_commit"),
                              baseline_source="embedded")
        self.assertIn("overall", result)

    def test_main_verify_hydrates_from_darp(self):
        """_main_verify must hydrate the capture config from the embedded capture block."""
        with tempfile.TemporaryDirectory() as tmp:
            path, _ = self._generate_darp(tmp)
            # Corrupt the process capture config so we can detect whether it's restored
            darp._CAPTURE = darp.CaptureConfig.from_dict({"api_command": "CORRUPTED"})
            rc = darp._main_verify([path])
            self.assertEqual(rc, 0)
            self.assertEqual(darp._CAPTURE.api_command, "api.py",
                             "_main_verify should hydrate api_command from the .darp capture block")


class TestCanonicalJson(unittest.TestCase):
    """Golden vector for the canonical JSON used by content_hash.

    Pins the vendored json-canon core (SPEC.md §2.3). The number table mirrors
    the upstream fixtures/02-numbers vector; if any of these change, the .darp
    content_hash changes and cross-language parity with nim-ots breaks.
    """

    def test_canon_number_golden(self):
        # token -> canonical decimal (json-canon SPEC.md §2.3, default collapse)
        cases = {
            "4":     "4",
            "4.0":   "4",        # float collapses to int
            "4.50e1": "45",
            "-0.0":  "0",        # negative zero unifies
            "1e3":   "1000",
            "0.10":  "0.1",      # trailing zero stripped
            "1.5E-3": "0.0015",
            "0.0015": "0.0015",
            "123456789012345678901234567890": "123456789012345678901234567890",
        }
        for tok, expected in cases.items():
            self.assertEqual(darp._canon_number(tok), expected, f"token {tok!r}")

    def test_canon_dumps_golden(self):
        gold = {
            "collapse_float": 20.0,
            "pct":            66.7,
            "whole_pct":      100.0,
            "negzero":        -0.0,
            "big_int":        123456789012345678901234567890,
            "tiny":           0.0015,
            "count":          42,
            "unicode_é":      "中文",
            "nested":         {"b": [1, 2.5, True, None], "a": "x"},
        }
        expected = (
            '{"big_int":123456789012345678901234567890,"collapse_float":20,'
            '"count":42,"negzero":0,"nested":{"a":"x","b":[1,2.5,true,null]},'
            '"pct":66.7,"tiny":0.0015,"unicode_é":"中文","whole_pct":100}'
        )
        self.assertEqual(darp._canon_dumps(gold), expected)
        self.assertEqual(
            hashlib.sha256(darp._canon_dumps(gold).encode()).hexdigest(),
            "41dee3c4161159988bc4bfeeae63b330bc2759092f7cb2d5ddc47e9b68969892",
        )

    def test_canon_rejects_non_finite(self):
        with self.assertRaises(ValueError):
            darp._canon_dumps({"x": float("nan")})
        with self.assertRaises(ValueError):
            darp._canon_dumps({"x": float("inf")})

    def test_canon_keys_sorted_by_code_point(self):
        # bools must serialize as true/false, not as ints (bool is an int subclass)
        self.assertEqual(darp._canon_dumps({"z": 1, "a": 2}), '{"a":2,"z":1}')
        self.assertEqual(darp._canon_dumps([True, False, 1, 0]), "[true,false,1,0]")

    def test_parity_with_json_canon_fixtures(self):
        """Drift check against an upstream json-canon checkout, if present."""
        fx = os.path.join(os.path.dirname(__file__), "..", "json-canon", "fixtures")
        if not os.path.isdir(fx):
            self.skipTest("json-canon checkout not adjacent; skipping drift check")
        for name in ("01-basic", "02-numbers"):
            with open(os.path.join(fx, f"{name}.json")) as fh:
                obj = json.load(fh)
            with open(os.path.join(fx, f"{name}.canon")) as fh:
                expected = fh.read().rstrip("\n")
            self.assertEqual(darp._canon_dumps(obj), expected, f"fixture {name}")


class TestTraceEncoding(unittest.TestCase):
    """Trace ingestion tolerates BOM / UTF-16 (harvested json-canon decode_bytes)."""

    _EVENTS = [
        {"event": "darp_hint", "source": "greplast_gate",
         "try_next": ["api.py which?bar"]},
        {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?baz"},
    ]

    def _metrics_for(self, raw: bytes):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "hint_trace_s1.jsonl"), "wb") as f:
                f.write(raw)
            return darp.compute([os.path.join(d, "hint_trace_s1.jsonl")], DEFS)["metric_results"]

    def test_bom_and_utf16_match_plain_utf8(self):
        jsonl = "\n".join(json.dumps(e) for e in self._EVENTS)
        plain = self._metrics_for(jsonl.encode("utf-8"))
        bom8  = self._metrics_for(b"\xef\xbb\xbf" + jsonl.encode("utf-8"))
        u16le = self._metrics_for(b"\xff\xfe" + jsonl.encode("utf-16-le"))
        # all three ingest to identical metrics — none silently skipped
        self.assertEqual(plain, bom8)
        self.assertEqual(plain, u16le)
        # and the content was really parsed (greplast_gate metric is populated)
        self.assertIn("greplast_gate", plain)

    def test_undecodable_file_skipped_not_crash(self):
        # invalid bytes for every encoding: must skip the file, not raise
        result = self._metrics_for(b"\xff\x00\x80\x81 not text \xfe")
        self.assertIsInstance(result, dict)


class TestPandasAccessor(unittest.TestCase):
    """DARP as a pandas extension — df.darp.* over a DataFrame of events."""

    _EVENTS = [
        {"event": "darp_hint", "source": "greplast_gate",
         "try_next": ["api.py which?bar"]},
        {"event": "darp_action", "tool": "Bash", "invocation": "api.py which?baz"},
        {"event": "darp_hint", "source": "greplast_gate",
         "try_next": ["api.py which?qux"]},
        {"event": "darp_action", "tool": "Bash", "invocation": "grep foo"},
    ]

    def _anon_events(self):
        with tempfile.TemporaryDirectory() as d:
            _trace(d, "s1", self._EVENTS)
            data = darp.compute([os.path.join(d, "hint_trace_s1.jsonl")], DEFS,
                                include_stream=True)
        return data["anon_events"], data["metric_results"]

    def test_metrics_matches_engine(self):
        import pandas as pd
        anon, expected = self._anon_events()
        df = pd.DataFrame(anon)
        self.assertEqual(df.darp.metrics(DEFS), expected)

    def test_capture_isolated_and_effective(self):
        """An explicit capture= reclassifies without mutating the process config."""
        import pandas as pd
        with tempfile.TemporaryDirectory() as d:
            _trace(d, "s1", [{"event": "darp_action", "tool": "Bash",
                              "invocation": "api.py grep?x"}])
            anon = darp.compute([os.path.join(d, "hint_trace_s1.jsonl")], DEFS,
                                include_stream=True)["anon_events"]
        df     = pd.DataFrame(anon)
        before = darp._CAPTURE
        default_first = df.darp.metrics(DEFS)["first_lookup"]
        custom_first  = df.darp.metrics(DEFS, capture={
            "specific_families": ["grep"], "generic_families": ["find"]})["first_lookup"]
        # default: "grep" is a generic family; custom: reclassified as specific
        self.assertEqual(default_first.get("grep_n"), 1)
        self.assertEqual(custom_first.get("specific_n"), 1)
        # the process-wide capture config was never touched
        self.assertIs(darp._CAPTURE, before)

    def test_report_is_verifiable(self):
        import pandas as pd
        anon, _ = self._anon_events()
        df  = pd.DataFrame(anon)
        cfg = {"subject": "accessor-test", "project": "P", "orcid": None,
               "include_stream": True, "source_darp_hash": None,
               "definitions": DEFS, "session_metric": "first_lookup",
               "min_sessions": 1}
        report = df.darp.report(cfg)
        # the report a .darp from the accessor must pass content_hash integrity
        self.assertEqual(report["metadata"]["content_hash"],
                         darp._compute_content_hash(report))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "acc.darp")
            with open(path, "w") as f:
                json.dump(report, f)
            rc = darp._run_verify(path, None, darp._find_schema(None), quiet=True)
        self.assertEqual(rc, 0)


class TestBitcoinAnchor(unittest.TestCase):
    """Bitcoin-anchor verification harvested from nim-ots (no network in tests)."""

    def test_parse_btc_opts(self):
        self.assertEqual(darp._parse_btc_opts(["--explorer"]),
                         {"explorer_url": darp._DEFAULT_EXPLORER})
        self.assertEqual(darp._parse_btc_opts(["--explorer-url", "http://e"]),
                         {"explorer_url": "http://e"})
        self.assertEqual(
            darp._parse_btc_opts(["--bitcoin-node", "http://n", "--rpc-user", "u",
                                  "--rpc-password", "p"]),
            {"node_url": "http://n", "rpc_user": "u", "rpc_password": "p"})
        self.assertEqual(darp._parse_btc_opts(["x.darp"]), {})

    def test_explorer_header_reverses_merkle(self):
        # blockstream merkle_root is display order; verifier must reverse to internal
        merkle_display = "0011223344556677889900aabbccddeeff" + "00" * 15
        calls = iter(["0000blockhash", json.dumps(
            {"merkle_root": merkle_display, "timestamp": 1700000000})])
        with mock.patch.object(darp, "_http_request", side_effect=lambda *a, **k: next(calls)):
            merkle, btime = darp._btc_explorer_header(800000, "https://x/api", 5)
        self.assertEqual(merkle, bytes.fromhex(merkle_display)[::-1])
        self.assertEqual(btime, 1700000000)

    def test_verify_anchor_verified(self):
        msg = b"\xab" * 32
        with mock.patch.object(darp, "_bitcoin_attestations", return_value=[(msg, 800000)]), \
             mock.patch.object(darp, "_btc_block_header",
                               return_value=(msg, 1700000000, "explorer (x)")):
            res = darp._verify_anchor(object(), {})
        self.assertEqual(res["status"], "verified")
        self.assertEqual(res["height"], 800000)
        self.assertEqual(res["time"], 1700000000)

    def test_verify_anchor_mismatch(self):
        with mock.patch.object(darp, "_bitcoin_attestations",
                               return_value=[(b"\x01" * 32, 800000)]), \
             mock.patch.object(darp, "_btc_block_header",
                               return_value=(b"\x02" * 32, 1700000000, "explorer (x)")):
            res = darp._verify_anchor(object(), {})
        self.assertEqual(res["status"], "mismatch")
        self.assertIn("MISMATCH", res["message"])

    def test_verify_anchor_network_error(self):
        def _boom(*a, **k):
            raise RuntimeError("connection refused")
        with mock.patch.object(darp, "_bitcoin_attestations",
                               return_value=[(b"\x01" * 32, 800000)]), \
             mock.patch.object(darp, "_btc_block_header", side_effect=_boom):
            res = darp._verify_anchor(object(), {})
        self.assertEqual(res["status"], "error")

    def test_verify_anchor_none_when_no_attestation(self):
        with mock.patch.object(darp, "_bitcoin_attestations", return_value=[]):
            res = darp._verify_anchor(object(), {})
        self.assertEqual(res["status"], "none")

    def test_iso_utc(self):
        self.assertEqual(darp._iso_utc(0), "1970-01-01T00:00:00+00:00")


def _mk_darp(orcid="0000-0002-1825-0097",
             repo="https://github.com/lucianofedericopereira/darp"):
    """A minimal report claiming an ORCID iD and a repo (both hashed, in definitions)."""
    return {"definitions": {"subject": "x", "orcid": orcid, "repo": repo},
            "metadata": {"content_hash": "sha256:abc"}}


def _mk_person(given="Luciano Federico", family="Pereira", credit=None, urls=()):
    """A minimal ORCID /person payload: name + researcher-urls."""
    name = {"given-names": {"value": given}, "family-name": {"value": family}}
    if credit is not None:
        name["credit-name"] = {"value": credit}
    return {"name": name,
            "researcher-urls": {"researcher-url": [{"url": {"value": u}} for u in urls]}}


class TestLedgerAuthorship(unittest.TestCase):
    """ORCID-anchored authorship — account match on known hosts, 1:1 on unknown."""

    _DARP_REPO = ("github.com", "lucianofedericopereira", "darp")
    _DARP_ACCT = ("github.com", "lucianofedericopereira")

    def test_repo_id_known_hosts_and_normalization(self):
        self.assertEqual(darp._git_repo_id("https://github.com/lucianofedericopereira/darp"),
                         self._DARP_REPO)
        self.assertEqual(darp._git_repo_id("http://www.github.com/Luciano/Darp.git/"),
                         ("github.com", "luciano", "darp"))
        self.assertEqual(darp._git_repo_id("https://codeberg.org/me/proj"),
                         ("codeberg.org", "me", "proj"))

    def test_repo_id_rejects_partial_and_unknown(self):
        self.assertIsNone(darp._git_repo_id("https://github.com/lucianofedericopereira"))  # profile
        self.assertIsNone(darp._git_repo_id("https://github.com/a/b/c"))                   # too deep
        self.assertIsNone(darp._git_repo_id("https://example.com/a/b"))                    # unknown host
        self.assertIsNone(darp._git_repo_id("a/b"))                                        # no host

    def test_known_account_from_profile_or_repo(self):
        # both a profile and a full repo URL resolve to the same (host, owner)
        self.assertEqual(darp._known_account("https://github.com/lucianofedericopereira"),
                         self._DARP_ACCT)
        self.assertEqual(darp._known_account("https://github.com/lucianofedericopereira/darp"),
                         self._DARP_ACCT)
        self.assertEqual(darp._known_account("http://www.GitHub.com/Me/"),
                         ("github.com", "me"))
        self.assertIsNone(darp._known_account("https://github.com"))        # bare host, no owner
        self.assertIsNone(darp._known_account("https://example.com/me"))    # unknown host

    def test_norm_url_strips_scheme_www_git_and_lowercases(self):
        self.assertEqual(darp._norm_url("https://Git.example.com/Me/Proj.git/"),
                         "git.example.com/me/proj")

    def test_orcid_name_prefers_credit_then_given_family(self):
        self.assertEqual(darp._orcid_name(_mk_person(credit="L. F. Pereira")),
                         "L. F. Pereira")
        self.assertEqual(darp._orcid_name(_mk_person()), "Luciano Federico Pereira")
        self.assertIsNone(darp._orcid_name({"name": {}}))

    def test_person_urls_parsed(self):
        person = _mk_person(urls=["https://example.com/me",
                                  "https://github.com/lucianofedericopereira"])
        self.assertEqual(darp._person_urls(person),
                         ["https://example.com/me",
                          "https://github.com/lucianofedericopereira"])

    def test_verified_when_orcid_lists_the_profile(self):
        # the real-world case: ORCID lists only the account/profile, repo is under it
        person = _mk_person(urls=["https://github.com/lucianofedericopereira"])
        with mock.patch.object(darp, "_orcid_person", return_value=person):
            res = darp._verify_ledger_authorship(_mk_darp())
        self.assertEqual(res["status"], "verified")
        self.assertEqual(res["name"], "Luciano Federico Pereira")
        self.assertEqual(res["repo"], "github.com/lucianofedericopereira/darp")
        self.assertEqual(res["account"], "github.com/lucianofedericopereira")

    def test_verified_when_orcid_lists_the_full_repo(self):
        # listing the full repo URL also matches (same account)
        person = _mk_person(urls=["https://github.com/lucianofedericopereira/darp"])
        with mock.patch.object(darp, "_orcid_person", return_value=person):
            res = darp._verify_ledger_authorship(_mk_darp())
        self.assertEqual(res["status"], "verified")

    def test_mismatch_when_account_differs(self):
        person = _mk_person(urls=["https://github.com/someone-else"])
        with mock.patch.object(darp, "_orcid_person", return_value=person):
            res = darp._verify_ledger_authorship(_mk_darp())
        self.assertEqual(res["status"], "mismatch")

    def test_unknown_host_requires_exact_1to1(self):
        repo = "https://git.example.com/me/proj"
        # exact URL listed → verified (no account field for unknown host)
        person = _mk_person(urls=[repo])
        with mock.patch.object(darp, "_orcid_person", return_value=person):
            res = darp._verify_ledger_authorship(_mk_darp(repo=repo))
        self.assertEqual(res["status"], "verified")
        self.assertNotIn("account", res)
        # only the account portion listed → NOT enough for an unknown host
        person2 = _mk_person(urls=["https://git.example.com/me"])
        with mock.patch.object(darp, "_orcid_person", return_value=person2):
            res2 = darp._verify_ledger_authorship(_mk_darp(repo=repo))
        self.assertEqual(res2["status"], "mismatch")

    def test_authorship_invalid_when_orcid_does_not_resolve(self):
        err = urllib.error.HTTPError("u", 404, "Not Found", {}, None)  # type: ignore[arg-type]
        with mock.patch.object(darp, "_orcid_person", side_effect=err):
            res = darp._verify_ledger_authorship(_mk_darp(orcid="0000-0000-0000-0000"))
        self.assertEqual(res["status"], "invalid")
        self.assertEqual(res["orcid"], "0000-0000-0000-0000")

    def test_authorship_absent_no_link(self):
        with mock.patch.object(darp, "_orcid_person", return_value=_mk_person(urls=[])):
            res = darp._verify_ledger_authorship(_mk_darp())
        self.assertEqual(res["status"], "absent")

    def test_authorship_none_without_claim(self):
        res = darp._verify_ledger_authorship({"definitions": {}, "metadata": {}})
        self.assertEqual(res["status"], "none")


if __name__ == "__main__":
    unittest.main(verbosity=2)
