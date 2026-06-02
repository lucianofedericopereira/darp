#!/usr/bin/env python3
# SUMMARY: DARP toolkit — capture, analyze, verify and anchor behavioral measurement artifacts
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
"""
================================================================================
DARP — Diff-Anchored Reporting Proof  |  Complete Toolkit  v1.0.0
================================================================================

USAGE
-----
  python3 darp.py [generate flags]           # generate .darp from traces (default)
  python3 darp.py analyze  <file.darp>       # compare against baseline
  python3 darp.py verify   <file.darp>       # validate schema, arithmetic, hash
  python3 darp.py cite     <file.darp>       # print citation (CFF / BibTeX / APA)
  python3 darp.py stamp    <file.darp>       # Bitcoin timestamp via OpenTimestamps
  python3 darp.py status   <file.darp>       # show anchor status
  python3 darp.py upgrade  <file.darp>       # upgrade OTS proof after BTC confirms

DESIGN PRINCIPLE: THREE IMMUTABLE BLOCKS
-----------------------------------------
A .darp file has three blocks:

  definitions   — who, what, and how: subject, identity, algorithm config.
                  Produced by CAPTURE. Never modified.
  data          — measurement results: health, metrics, trend, data_commitment.
                  Produced by CAPTURE. Never modified.
  metadata      — proof chain: content_hash (covers definitions+data), consistency
                  checks, generator. ANCHOR appends timestamp (stamp) here only.

content_hash = SHA256(canonical {definitions, data}) is what OTS commits to.
Because only metadata grows after generation, content_hash stays stable through
the full stamp → upgrade workflow.

Authorship is not a login. definitions holds a claimed `orcid`; metadata holds
the paper's `repo` (a full host/owner/repo URL). One public read of the ORCID
record (`verify --verify-authorship`) confirms three things: the iD resolves, the
author's name, and the repo's ownership. On a known host the repo's account
(host/owner) must be listed, so one profile link covers every repo under it; on
an unknown host the record must list the exact repo URL, one-to-one. Only you can
add that link, and only you can push under that account. No token, no secret,
no login.

The four logical layers:

  CAPTURE   — compute + build_darp          record what happened
  ANALYZE   — analyze + _main_analyze       what it means (baseline-dependent)
  VERIFY    — _rederive + _run_verify       is the capture internally consistent?
  ANCHOR    — _cmd_stamp + ledger/OTS       prove it existed at this point in time

PORTABILITY
-----------
All project-specific values live in darp.ini. To adapt for a new project:
  1. Copy darp/ into the new project
  2. Edit darp.ini: set [project], [capture], [paths], [subject]
  3. Edit darp.ini: set [baseline] commit and [values] percentages
  4. Run: python3 darp.py

GENERATE FLAGS
--------------
  --config FILE       Alternative .ini file (default: darp.ini next to this script)
  --no-stream         Omit anonymized event stream
  --stream            Embed anonymized event stream
  --out DIR           Output directory override
  --trace-dir DIR     Directory containing hint_trace_*.jsonl files
  --subject NAME      Report subject label
  --snapshot LABEL    Append label to filename
  --from-darp FILE    Replay from embedded stream in a prior .darp
  --sessions N:M      Slice sessions N to M (Python slice semantics)

ANALYZE FLAGS
-------------
  python3 darp.py analyze <file.darp> [flags]
  --baseline-ini FILE      ini file (default: darp.ini)
  --baseline-darp FILE     another .darp as baseline source
  --baseline-values STR    inline comma-separated key=value pairs
  --baseline-commit HASH   override commit hash for provenance display
  --out FILE|DIR           write JSON output
  --quiet                  only print failures

VERIFY FLAGS
------------
  python3 darp.py verify <file.darp> [flags]
  --traces DIR     Directory containing hint_trace_*.jsonl (enables Level 4+5)
  --schema FILE    Path to darp.schema.json (default: auto-locate)
  --verify-anchor      Re-check the embedded Bitcoin anchor against the chain (L6)
  --verify-authorship  Walk ORCID → darp-ledger and match content_hash (L7)
  --quiet              Only print failures

  Level 1: schema validation
  Level 2: arithmetic re-derivation (consistency checks)
  Level 3: content_hash integrity (always runs)
  Level 4: source hash against trace files (requires --traces)
  Level 5: full metric replay against trace files (requires --traces)
  Level 6: Bitcoin anchor — merkle root of the attested block (--verify-anchor)
  Level 7: ORCID-anchored authorship — the repo's owner is on your ORCID (--verify-authorship)

ANCHOR
------
  python3 darp.py stamp   <file.darp>
  python3 darp.py status  <file.darp> [--proof]
  python3 darp.py upgrade <file.darp> [backend flags]

  stamp:   submits content_hash to OpenTimestamps calendars; embeds proofs in
           metadata.timestamp. Works on any .darp (stream not required).
  status:  shows anchor + ORCID/ledger id; --proof dumps each proof's tree.
  upgrade: upgrades pending OTS proofs after Bitcoin confirms (~1-2 hours), then
           independently verifies the merkle root of the attested block before
           marking it confirmed. Runs in-process via the opentimestamps library
           (no `ots` binary): apt install python3-opentimestamps

  Bitcoin backend (upgrade / verify --verify-anchor) — default tries a local
  node then a public explorer; override with:
    --bitcoin-node URL [--rpc-user U] [--rpc-password P]   Bitcoin Core JSON-RPC
    --explorer | --explorer-url URL                        Esplora/blockstream

  ORCID-anchored authorship (login-free, one public read):
    1. set [project] orcid = <your iD> and [project] repo = <full repo URL>
    2. on your ORCID record, add a link proving you own the repo:
       - known host (github.com gitlab.com bitbucket.org codeberg.org
         gitea.com gitee.com): your profile (https://<host>/<owner>)
         suffices — it covers every repo under your account
       - any other host: add the exact repo URL (matched one-to-one)
    3. publish the report (and the paper that cites the repo) in that repo
  `verify --verify-authorship` reads your ORCID record once and checks the iD,
  the author's name, and that definitions.repo's owner is an account you list. Only
  you can add that link, and only you can push under that account.

================================================================================
"""
from __future__ import annotations

__version__          = "1.0.0"
_DARP_FORMAT_VERSION = "1.0"

import base64
import configparser
import glob
import hashlib
import json
import math
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

try:
    import pandas as pd
except ImportError:
    print("ERROR: darp.py requires pandas. Install with:\n"
          "  sudo apt-get install python3-pandas   # Debian/Ubuntu\n"
          "  pip install pandas                    # pip",
          file=__import__("sys").stderr)
    __import__("sys").exit(1)

# ── Config ────────────────────────────────────────────────────────────────────

_HERE        = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_INI = os.path.join(_HERE, "darp.ini")


def _load_ini(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(path)
    return cfg


def _resolve(path: str, base: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(base, path))


# ── Capture constants (defaults; overridden by darp.ini [capture]/[families]) ─

@dataclass(frozen=True)
class CaptureConfig:
    """All project-specific capture/classification settings, threaded explicitly
    through the engine so it carries no module-level mutable state. Built from the
    ini ([capture]) for the CLI, or from a .darp's embedded `capture` block for
    verify/replay, or passed directly to the pandas accessor for full isolation.
    The classification helpers live here so config and behavior travel together.
    """
    api_command:       str
    packages_path:     str
    vibe_pattern:      str
    memory_tool:       str
    trace_pattern:     str
    smoke_prefix:      str
    specific_families: frozenset[str]
    generic_families:  frozenset[str]
    packages_tools:    frozenset[str]
    api_endpoint_re:   "re.Pattern[str]"
    packages_path_re:  "re.Pattern[str]"
    trace_id_re:       "re.Pattern[str]"

    @staticmethod
    def _compile(api_command: str, packages_path: str, trace_pattern: str
                 ) -> tuple["re.Pattern[str]", "re.Pattern[str]", "re.Pattern[str]"]:
        api_re = re.compile(rf'{re.escape(api_command)}\s+["\']?([a-z]+)[?\s"]', re.IGNORECASE)
        pkg_re = re.compile(re.escape(packages_path), re.IGNORECASE)
        parts  = trace_pattern.split("*", 1)
        trace_re = re.compile(
            rf'{re.escape(parts[0])}(.+){re.escape(parts[1])}$' if len(parts) == 2
            else rf'{re.escape(trace_pattern)}$')
        return api_re, pkg_re, trace_re

    @classmethod
    def build(cls, *, api_command: str, packages_path: str, vibe_pattern: str,
              memory_tool: str, trace_pattern: str, smoke_prefix: str,
              specific_families: Any, generic_families: Any,
              packages_tools: Any) -> "CaptureConfig":
        api_re, pkg_re, trace_re = cls._compile(api_command, packages_path, trace_pattern)
        return cls(api_command, packages_path, vibe_pattern, memory_tool,
                   trace_pattern, smoke_prefix,
                   frozenset(specific_families), frozenset(generic_families),
                   frozenset(packages_tools), api_re, pkg_re, trace_re)

    @classmethod
    def default(cls) -> "CaptureConfig":
        return cls.build(
            api_command="api.py", packages_path="packages/", vibe_pattern="vibe",
            memory_tool="mcp__ccd_session__search_session_transcripts",
            trace_pattern="hint_trace_*.jsonl", smoke_prefix="smoke",
            specific_families={"which", "component", "model", "docs", "discover", "frontend", "ls"},
            generic_families={"grep", "find"},
            packages_tools={"Read", "Glob", "Grep"})

    @classmethod
    def from_ini(cls, ini: configparser.ConfigParser) -> "CaptureConfig":
        d = cls.default()

        def g(key: str, fb: str) -> str:
            return ini.get("capture", key, fallback=fb).strip()

        spec = g("specific_families", ",".join(sorted(d.specific_families)))
        gen  = g("generic_families",  ",".join(sorted(d.generic_families)))
        pkg  = g("packages_tools",    ",".join(sorted(d.packages_tools)))
        return cls.build(
            api_command   = g("api_command",   d.api_command),
            packages_path = g("packages_path", d.packages_path),
            vibe_pattern  = g("vibe_pattern",  d.vibe_pattern),
            memory_tool   = g("memory_tool",   d.memory_tool),
            trace_pattern = g("trace_pattern", d.trace_pattern),
            smoke_prefix  = g("smoke_prefix",  d.smoke_prefix),
            specific_families = [f.strip() for f in spec.split(",") if f.strip()],
            generic_families  = [f.strip() for f in gen.split(",")  if f.strip()],
            packages_tools    = [t.strip() for t in pkg.split(",")  if t.strip()])

    @classmethod
    def from_dict(cls, capture: dict[str, Any]) -> "CaptureConfig":
        d = cls.default()
        return cls.build(
            api_command   = capture.get("api_command",   d.api_command),
            packages_path = capture.get("packages_path", d.packages_path),
            vibe_pattern  = capture.get("vibe_pattern",  d.vibe_pattern),
            memory_tool   = capture.get("memory_tool",   d.memory_tool),
            trace_pattern = capture.get("trace_pattern", d.trace_pattern),
            smoke_prefix  = capture.get("smoke_prefix",  d.smoke_prefix),
            specific_families = capture.get("specific_families", sorted(d.specific_families)),
            generic_families  = capture.get("generic_families",  sorted(d.generic_families)),
            packages_tools    = capture.get("packages_tools",    sorted(d.packages_tools)))

    def embed_dict(self) -> dict[str, Any]:
        """The capture block embedded under algorithm.parameters in a .darp."""
        return {
            "api_command":       self.api_command,
            "packages_path":     self.packages_path,
            "vibe_pattern":      self.vibe_pattern,
            "memory_tool":       self.memory_tool,
            "trace_pattern":     self.trace_pattern,
            "smoke_prefix":      self.smoke_prefix,
            "packages_tools":    sorted(self.packages_tools),
            "specific_families": sorted(self.specific_families),
            "generic_families":  sorted(self.generic_families),
        }

    # ── classification helpers ────────────────────────────────────────────────
    def endpoint_family(self, invocation: str) -> str | None:
        m = self.api_endpoint_re.search(invocation)
        return m.group(1).lower() if m else None

    def is_api_call(self, invocation: str) -> bool:
        return self.api_command in invocation

    def is_packages_bypass(self, event: dict[str, Any]) -> bool:
        if event.get("tool", "") not in self.packages_tools:
            return False
        return self.packages_path_re.search(event.get("invocation", "")) is not None

    def session_id_from_path(self, path: str) -> str:
        base = os.path.basename(path)
        m = self.trace_id_re.match(base)
        return m.group(1) if m else base

    def classify_outcome(self, row: "pd.Series[Any]") -> str:
        if pd.isna(row.get("is_api_call_next")):
            return "routed"
        if str(row.get("tool_next", "")) == self.memory_tool:
            return "memory"
        if row.get("is_api_call_next"):
            families = row.get("try_next_families") or []
            if isinstance(families, list) and row.get("api_family_next") in families:
                return "followed"
            return "modified"
        return "routed"


# Process-wide default capture config (the CLI/tests set this via
# _init_capture_config*). Engine functions accept an explicit `cap=` and fall
# back to this only when none is passed — so a library caller (e.g. the pandas
# accessor) can stay fully isolated by passing its own CaptureConfig.
_CAPTURE: CaptureConfig = CaptureConfig.default()


# ── Source field map (defaults; overridden by darp.ini [source]) ──────────────

_DEFAULT_SOURCE_MAP: dict[str, Any] = {
    "event_field":      "event",       # field holding the event type discriminator
    "hint_value":       "darp_hint",    # event_field value that means a hint fired
    "action_value":     "darp_action", # event_field value that means a tool was called
    "ts_field":         "ts",          # timestamp field (Unix seconds float)
    "ts_scale":         1.0,           # multiply raw ts by this (e.g. 1e-9 for nanoseconds)
    "source_field":     "source",      # hint source name (matched against trigger_source)
    "synthetic_field":  "synthetic",   # bool; true → excluded from metrics
    "try_next_field":   "try_next",    # list of suggested invocation strings
    "tool_field":       "tool",        # action tool name
    "invocation_field": "invocation",  # full invocation string
}


def _load_source_map(ini: configparser.ConfigParser) -> dict[str, Any]:
    """Load [source] field-mapping overrides, falling back to _DEFAULT_SOURCE_MAP."""
    sm = dict(_DEFAULT_SOURCE_MAP)
    if ini.has_section("source"):
        for key in sm:
            raw = ini.get("source", key, fallback=None)
            if raw is not None:
                sm[key] = float(raw.strip()) if key == "ts_scale" else raw.strip()
    return sm


def _get_field(obj: Any, path: str, default: Any = None) -> Any:
    """Dotted-path accessor: 'a.b.c' → obj['a']['b']['c']."""
    for part in path.split("."):
        if not isinstance(obj, dict):
            return default
        obj = obj.get(part, default)
    return obj


def _normalize_event(ev: dict[str, Any], sm: dict[str, Any]) -> dict[str, Any] | None:
    """Map an external trace event to canonical DARP field names.

    Returns a new dict with canonical fields ('event', 'ts', 'source', …) plus
    any extra fields from the original preserved for echo_dedup and other uses.
    Returns None if the event is not a hint or action.
    """
    evt_raw = _get_field(ev, sm["event_field"])
    if evt_raw == sm["hint_value"]:
        canonical_event = "hint"
    elif evt_raw == sm["action_value"]:
        canonical_event = "action"
    else:
        return None

    ts = float(_get_field(ev, sm["ts_field"], 0) or 0) * float(sm["ts_scale"])

    # Start with original fields so echo_dedup_field and any other extra keys survive.
    out = {k: v for k, v in ev.items()}
    out["event"] = canonical_event
    out["ts"]    = ts

    if canonical_event == "hint":
        out["source"]    = _get_field(ev, sm["source_field"])
        out["synthetic"] = _get_field(ev, sm["synthetic_field"], False)
        out["try_next"]  = _get_field(ev, sm["try_next_field"], []) or []
    else:
        out["tool"]       = _get_field(ev, sm["tool_field"])
        out["invocation"] = _get_field(ev, sm["invocation_field"], "") or ""

    return out


def _init_capture_config(ini: configparser.ConfigParser) -> None:
    """Set the process-wide capture config from darp.ini [capture]."""
    global _CAPTURE
    _CAPTURE = CaptureConfig.from_ini(ini)


def _init_capture_config_from_dict(capture: dict[str, Any]) -> None:
    """Set the process-wide capture config from a .darp's embedded capture block."""
    global _CAPTURE
    _CAPTURE = CaptureConfig.from_dict(capture)



def _load_definitions(ini: configparser.ConfigParser) -> dict[str, dict[str, str]]:
    """Load metric definitions from [definition.XXX] sections in darp.ini.

    Reads ALL keys in each section — both human-readable prose fields
    (description, followed_if, routed_if, notes, type) and computation config
    (algorithm, trigger_source, window, echo_dedup, divergence_max, …).
    The algorithm field drives dispatch in _METRIC_TYPES.
    """
    defs: dict[str, dict[str, str]] = {}
    for section in ini.sections():
        if not section.startswith("definition."):
            continue
        name = section[len("definition."):]
        entry: dict[str, str] = {
            key: ini.get(section, key, raw=True).strip()
            for key in ini.options(section)
        }
        if entry:
            defs[name] = entry
    if not defs:
        print(
            "ERROR: no [definition.XXX] sections found in darp.ini.\n"
            "       Add a [definition.your_metric_name] section for each metric you capture.\n"
            "       See the bundled darp.ini for examples.",
            file=sys.stderr,
        )
        sys.exit(1)
    return defs



# BOM table (longest signature first — UTF-32-LE shares a prefix with UTF-16-LE).
_BOMS = [
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xef\xbb\xbf",     "utf-8"),
    (b"\xff\xfe",         "utf-16-le"),
    (b"\xfe\xff",         "utf-16-be"),
]


def _decode_bytes(data: bytes) -> str:
    """Decode JSON bytes, detecting and stripping a BOM (harvested from
    json-canon's decode_bytes). Trace exporters — especially on Windows — emit
    UTF-16 or UTF-8-with-BOM; a plain .decode('utf-8') crashes on the former and
    json rejects the latter as a stray BOM, which would otherwise make compute()
    silently skip the whole file (dropping a session from the metrics)."""
    for sig, enc in _BOMS:
        if data.startswith(sig):
            return data[len(sig):].decode(enc)
    text = data.decode("utf-8")
    return text[1:] if text[:1] == "﻿" else text


def _json_load(path: str) -> Any:
    with open(path, "rb") as fh:
        return json.loads(_decode_bytes(fh.read()))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_prefixed(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


# ── Canonical JSON ────────────────────────────────────────────────────────────
# Vendored from json-canon (github.com/lucianofedericopereira/json-canon, SPEC.md
# §2.3). `_canon_number` is copied verbatim from its numbers.py — it is the
# cross-language byte-identical core, so a .darp content_hash equals what the Nim
# `ots canon -j --exclude /metadata` (or a future Nim DARP) computes for the same
# {definitions, data}. Parity with the upstream fixtures is pinned by the golden
# vector in test_darp.py; do not edit this without updating that test.
#
# DARP hashes native dicts (not JSON text), so only the number/string core is
# vendored — not the upstream JSON/JSON5 parser. Numbers reach `_canon_number`
# via str(int) (exact) and repr(float) (shortest round-trip, identical to what
# json.dumps emits), then canonicalize identically. Default collapses 20.0 -> 20.

def _canon_number(tok: str) -> str:
    """Normalize a JSON number token to its canonical decimal string.

    Pure string/integer operations — the token is never parsed into a binary
    float, so big integers survive intact. Collapses int/float (4.0 -> 4).
    """
    s = tok.strip()
    neg = s[0] == "-"
    if s[0] in "+-":
        s = s[1:]

    mant, _e, exp_s = s.replace("E", "e").partition("e")
    E = int(exp_s) if exp_s else 0

    if "." in mant:
        I, _, F = mant.partition(".")
    else:
        I, F = mant, ""

    combined = I + F
    point_exp = E - len(F)

    combined = combined.lstrip("0")
    if combined == "":
        return "0"

    stripped = combined.rstrip("0")
    point_exp += len(combined) - len(stripped)
    combined = stripped

    sign = "-" if neg else ""

    if point_exp >= 0:
        return sign + combined + "0" * point_exp

    k = -point_exp
    if k < len(combined):
        return sign + combined[:-k] + "." + combined[-k:]
    return sign + "0." + "0" * (k - len(combined)) + combined


_CANON_ESC = {
    '"': '\\"', "\\": "\\\\",
    "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r",
}


def _canon_str(s: str) -> str:
    out = ['"']
    for ch in s:
        e = _CANON_ESC.get(ch)
        if e is not None:
            out.append(e)
        elif ch < "\x20":
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canon_write(val: Any, out: list[str]) -> None:
    if val is True:
        out.append("true")
    elif val is False:
        out.append("false")
    elif val is None:
        out.append("null")
    elif isinstance(val, int):
        out.append(_canon_number(str(val)))
    elif isinstance(val, float):
        if not math.isfinite(val):
            raise ValueError(f"non-finite number ({val}) cannot be canonicalized")
        out.append(_canon_number(repr(val)))
    elif isinstance(val, str):
        out.append(_canon_str(val))
    elif isinstance(val, (list, tuple)):
        out.append("[")
        for i, item in enumerate(val):
            if i:
                out.append(",")
            _canon_write(item, out)
        out.append("]")
    elif isinstance(val, dict):
        out.append("{")
        for i, key in enumerate(sorted(val.keys())):
            if i:
                out.append(",")
            out.append(_canon_str(key))
            out.append(":")
            _canon_write(val[key], out)
        out.append("}")
    else:
        raise ValueError(f"cannot canonicalize {type(val).__name__}")


def _canon_dumps(val: Any) -> str:
    """Canonical JSON string for a native Python object (json-canon SPEC.md §2)."""
    out: list[str] = []
    _canon_write(val, out)
    return "".join(out)


def _compute_content_hash(darp: dict[str, Any]) -> str:
    """Re-derive content_hash from a .darp dict.

    Hashes canonical JSON of {"definitions": definitions_block, "data": data_block}.
    This is what OTS and ORCID commit to.
    """
    fields = {"definitions": darp.get("definitions", {}), "data": darp.get("data", {})}
    return _sha256_prefixed(_canon_dumps(fields).encode())


def _hash_session_id(sid: str) -> str:
    return _sha256(sid.encode())[:12]


def _anonymize_event(ev: dict[str, Any], session_hash: str, ts_zero: float,
                     cap: CaptureConfig) -> dict[str, Any] | None:
    evt = ev.get("event")
    if evt not in ("hint", "action"):
        return None
    out: dict[str, Any] = {
        "session_hash": session_hash,
        "event":        evt,
        "ts_offset_s":  round(ev.get("ts", 0) - ts_zero, 2),
    }
    if evt == "hint":
        try_next = ev.get("try_next", [])
        out.update({
            "source":            ev.get("source"),
            "synthetic":         ev.get("synthetic", False),
            "try_next_families": sorted({f for cmd in try_next if (f := cap.endpoint_family(cmd))}),
            "tool":              None,
            "is_api_call":       None,
            "api_family":        None,
            "is_pkg_bypass":     None,
        })
    else:
        inv    = ev.get("invocation", "")
        is_api = cap.is_api_call(inv)
        out.update({
            "source":            None,
            "synthetic":         None,
            "try_next_families": None,
            "tool":              ev.get("tool"),
            "is_api_call":       is_api,
            "api_family":        cap.endpoint_family(inv) if is_api else None,
            "is_pkg_bypass":     cap.is_packages_bypass(ev),
        })
    return out


# ── Slice helpers ─────────────────────────────────────────────────────────────

def _parse_slice(s: str) -> tuple[int | None, int | None]:
    try:
        if ":" not in s:
            n = int(s)
            return (n, n + 1)
        left, right = s.split(":", 1)
        return (int(left) if left.strip() else None, int(right) if right.strip() else None)
    except ValueError:
        print(f"ERROR: --sessions must be N, N:M, N:, or :M — got: {s!r}", file=sys.stderr)
        sys.exit(1)


# ── Echo dedup (raw-trace pre-processing for window metrics) ─────────────────

def _preprocess_read_gate_echoes(
    events: list[dict[str, Any]],
    source: str,
    field: str = "searched",
    strip_prefix: str = "Read ",
) -> list[dict[str, Any]]:
    """Remove the immediately-following tool_call if it echoes the hinted path.

    The hint event field that carries the path and the prefix to strip before
    matching are configurable per-definition via echo_dedup_field /
    echo_dedup_strip_prefix so the tool is not tied to one project's hook format.
    """
    skip: set[int] = set()
    for i, ev in enumerate(events):
        if ev.get("event") != "hint" or ev.get("source") != source:
            continue
        hinted = str(_get_field(ev, field, "")).replace(strip_prefix, "").strip()
        if not hinted:
            continue
        for j in range(i + 1, len(events)):
            if events[j].get("event") == "action":
                if hinted in events[j].get("invocation", ""):
                    skip.add(j)
                break
    return [ev for k, ev in enumerate(events) if k not in skip]


# ── Metric type primitives ────────────────────────────────────────────────────

_EMPTY_DF_COLS = [
    "session_hash", "event", "source", "synthetic", "try_next_families",
    "tool", "is_api_call", "api_family", "is_pkg_bypass", "ts_offset_s", "seq",
]

def _events_to_df(anon_events: list[dict[str, Any]]) -> pd.DataFrame:
    if not anon_events:
        return pd.DataFrame(columns=_EMPTY_DF_COLS)
    df = pd.DataFrame(anon_events)
    for col in _EMPTY_DF_COLS:
        if col not in df.columns:
            df[col] = pd.NA
    df["seq"] = df.groupby("session_hash").cumcount()
    return df


def _next_tool_df(hints: pd.DataFrame, tools: pd.DataFrame) -> pd.DataFrame:
    """Pair each hint with its immediately next tool call in the same session."""
    if hints.empty or tools.empty:
        for col in ("is_api_call", "api_family", "tool", "is_pkg_bypass"):
            hints = hints.copy()
            hints[f"{col}_next"] = pd.NA
        return hints
    h = hints[["session_hash", "seq", "try_next_families"]].copy()
    h["seq_fwd"] = h["seq"] + 0.5
    t = (tools[["session_hash", "seq", "is_api_call", "api_family", "tool", "is_pkg_bypass"]]
         .copy()
         .rename(columns={
             "is_api_call":   "is_api_call_next",
             "api_family":    "api_family_next",
             "tool":          "tool_next",
             "is_pkg_bypass": "is_pkg_bypass_next",
         }))
    t["seq"] = t["seq"].astype(float)          # match dtype for merge_asof
    # merge_asof requires each frame globally sorted by its on-key (not by the
    # `by` key): with multiple sessions, seq resets per session, so sorting by
    # [session_hash, seq] leaves the seq column non-monotonic and pandas raises
    # "keys must be sorted". Sort by the on-key alone; `by` handles the grouping.
    merged = pd.merge_asof(
        h.sort_values("seq_fwd"),
        t.sort_values("seq"),
        left_on="seq_fwd", right_on="seq",
        by="session_hash", direction="forward",
        suffixes=("", "_t"),
    )
    return merged.drop(columns=["seq_fwd", "seq_t"])


def _compute_next(df: pd.DataFrame, config: dict[str, Any],
                  cap: CaptureConfig) -> dict[str, Any]:
    """Immediate-next-tool attribution: followed / modified / routed / memory."""
    source = config["trigger_source"]
    hints  = df[(df.event == "hint") &
                (df.source == source) &
                (df.synthetic != True)].copy()
    if hints.empty:
        return {"total": 0, "followed": 0, "modified": 0, "routed": 0,
                "memory": 0, "pct": 0, "per_session": {}}

    merged = _next_tool_df(hints, df[df.event == "action"])
    merged["outcome"] = merged.apply(cap.classify_outcome, axis=1)

    totals = merged["outcome"].value_counts()
    total  = int(len(merged))
    fol    = int(totals.get("followed", 0))

    per_session: dict[str, Any] = {}
    for sid, grp in merged.groupby("session_hash"):
        t = len(grp)
        f = int((grp["outcome"] == "followed").sum())
        per_session[sid] = {"total": t, "followed": f,
                             "pct": int(100 * f // t) if t else None}

    return {
        "total":       total,
        "followed":    fol,
        "modified":    int(totals.get("modified", 0)),
        "routed":      int(totals.get("routed", 0)),
        "memory":      int(totals.get("memory", 0)),
        "pct":         int(100 * fol // total) if total else 0,
        "per_session": per_session,
    }


def _compute_window(df: pd.DataFrame, config: dict[str, Any],
                    cap: CaptureConfig) -> dict[str, Any]:
    """Lookahead window attribution with per-gate% / per-session% two-view."""
    source      = config["trigger_source"]
    window      = int(config.get("window", 10))
    file_family = config.get("file_family", "file")
    div_max     = float(config.get("divergence_max", 20.0))

    hints = df[(df.event == "hint") &
               (df.source == source) &
               (df.synthetic != True)][["session_hash", "seq"]].copy()
    hints = hints.rename(columns={"seq": "hint_seq"})

    empty: dict[str, Any] = {
        "total": 0, "followed": 0, "modified": 0, "routed": 0, "memory": 0, "pct": 0,
        "per_gate_pct": None, "session_pct": None, "divergence_pts": None,
        "divergence_max": div_max, "per_session": {},
    }
    if hints.empty:
        return empty

    tools = (df[df.event == "action"]
               [["session_hash", "seq", "is_api_call", "api_family", "is_pkg_bypass"]]
               .rename(columns={"seq": "tool_seq"}))

    within = pd.merge(hints, tools, on="session_hash")
    within = within[(within.tool_seq > within.hint_seq) &
                    (within.tool_seq <= within.hint_seq + window)].copy()

    within["is_api"]    = (within.is_api_call == True) & (within.api_family == file_family)
    within["is_bypass"] = within.is_pkg_bypass == True

    # Each tool attributed to earliest gate only
    deduped = (within.sort_values(["session_hash", "hint_seq", "tool_seq"])
                     .drop_duplicates(subset=["session_hash", "tool_seq"], keep="first"))

    gate_groups   = deduped.groupby(["session_hash", "hint_seq"])
    gate_has_api  = gate_groups["is_api"].any()
    gate_has_byp  = gate_groups["is_bypass"].any()
    n_api    = int(gate_has_api.sum())
    # bypass only counts when the gate had no api call in the window (mutually exclusive)
    n_bypass = int((gate_has_byp & ~gate_has_api).sum())
    rg_tot   = n_api + n_bypass
    total    = len(hints)

    # Two-view percentages use 1-decimal rounding because they are diverging
    # ratios compared against each other (divergence_max). The headline `pct`
    # and per-session `pct` below intentionally use integer floor instead — a
    # different statistic (followed / total hints), so the two never need to match.
    per_gate_pct = round(100 * n_api / rg_tot, 1)                          if rg_tot > 0               else None
    sess_with_api = int(deduped[deduped.is_api]["session_hash"].nunique())
    sess_with_gate = int(hints["session_hash"].nunique())
    session_pct  = round(100 * sess_with_api / sess_with_gate, 1)          if sess_with_gate > 0        else None
    divergence   = (round(abs(per_gate_pct - session_pct), 1)
                    if per_gate_pct is not None and session_pct is not None else None)

    per_session: dict[str, Any] = {}
    for sid in hints["session_hash"].unique():
        sid_hints  = hints[hints.session_hash == sid]
        sid_deduped = deduped[deduped.session_hash == sid]
        t = len(sid_hints)
        f = int(sid_deduped.groupby("hint_seq")["is_api"].any().sum()) if not sid_deduped.empty else 0
        per_session[sid] = {"total": t, "followed": f,
                             "pct": int(100 * f // t) if t else None}

    return {
        "total":          total,
        "followed":       n_api,
        "modified":       0,
        "routed":         total - rg_tot,
        "memory":         0,
        "pct":            int(100 * n_api // total) if total else 0,
        "per_gate_pct":   per_gate_pct,
        "session_pct":    session_pct,
        "divergence_pts": divergence,
        "divergence_max": div_max,
        "per_session":    per_session,
    }


def _compute_first(df: pd.DataFrame, config: dict[str, Any],
                   cap: CaptureConfig) -> dict[str, Any]:
    """Session-level: classify the first uninfluenced API call in each session."""
    api = df[(df.event == "action") &
             (df.is_api_call == True) &
             (df.api_family.notna()) &
             (df.api_family != cap.vibe_pattern)].copy()

    first = (api.sort_values("seq")
                .groupby("session_hash")
                .first()
                .reset_index()[["session_hash", "api_family"]])

    # "other" = made an API call but family not in specific or generic lists
    first["fls_type"] = "other"
    first.loc[first.api_family.isin(cap.specific_families), "fls_type"] = "specific"
    for _fam in cap.generic_families:
        first.loc[first.api_family == _fam, "fls_type"] = _fam

    all_sessions = df["session_hash"].unique()
    sessions_set = set(first["session_hash"])
    # no_api = sessions that made zero non-vibe API calls
    n_no_api     = sum(1 for s in all_sessions if s not in sessions_set)
    counts       = first["fls_type"].value_counts().to_dict()
    n_spec       = counts.get("specific", 0)
    n_other      = counts.get("other", 0)
    generic_n    = {fam: counts.get(fam, 0) for fam in sorted(cap.generic_families)}
    fls_tot      = n_spec + sum(generic_n.values())
    pct          = round(100 * n_spec / fls_tot, 1) if fls_tot else None

    fam_map = first.set_index("session_hash")["api_family"].to_dict()
    per_session = {sid: {"family": fam_map.get(sid)} for sid in all_sessions}

    return {
        "pct":        pct,
        "specific_n": n_spec,
        **{f"{fam}_n": generic_n[fam] for fam in sorted(cap.generic_families)},
        "other_n":    n_other,
        "no_api_n":   n_no_api,
        "per_session": per_session,
    }


def _compute_rate(df: pd.DataFrame, config: dict[str, Any],
                  cap: CaptureConfig) -> dict[str, Any]:
    """Fraction of sessions containing at least one hint of the configured source."""
    source   = config["trigger_source"]
    relevant = df[(df.event == "hint") &
                  (df.source == source) &
                  (df.synthetic != True)]
    n_with   = int(relevant["session_hash"].nunique())
    n_total  = int(df["session_hash"].nunique())
    pct      = round(100 * n_with / n_total, 1) if n_total else None
    return {"total": n_total, "followed": n_with, "modified": 0, "routed": 0,
            "memory": 0, "pct": pct or 0.0, "sessions_with": n_with,
            "per_session": {}}


_MetricFn = Callable[[pd.DataFrame, dict[str, Any], "CaptureConfig"], dict[str, Any]]

# Single source of truth for every behavioral property of a primitive.
# Adding a new primitive means adding one entry here — nowhere else.
_PRIMITIVES: dict[str, dict[str, Any]] = {
    #          fn               abstract_type          needs_trigger  has_divergence  is_session_level  required_breakdown: list → static keys; str → param key to look up in .darp parameters
    "next":   {"fn": _compute_next,   "abstract_type": "proportion",       "needs_trigger": True,  "has_divergence": False, "is_session_level": False, "required_breakdown": ["followed"]},
    "window": {"fn": _compute_window, "abstract_type": "window_proportion", "needs_trigger": True,  "has_divergence": True,  "is_session_level": False, "required_breakdown": ["followed", "routed", "per_gate_pct", "session_pct", "divergence_pts"]},
    "first":  {"fn": _compute_first,  "abstract_type": "classification",   "needs_trigger": False, "has_divergence": False, "is_session_level": True,  "required_breakdown": "classification_categories"},
    "rate":   {"fn": _compute_rate,   "abstract_type": "proportion",       "needs_trigger": True,  "has_divergence": False, "is_session_level": False, "required_breakdown": ["followed"]},
}


def _load_algo_map(ini: configparser.ConfigParser) -> dict[str, str]:
    """Load researcher alias → internal primitive map from [algorithms] section."""
    if not ini.has_section("algorithms"):
        return {}
    return {k.strip(): v.strip() for k, v in ini.items("algorithms") if v.strip()}


def _resolve_algo(alias: str, algo_map: dict[str, str]) -> str:
    """Resolve a researcher-defined alias to an internal primitive key."""
    return algo_map.get(alias, alias)


# ── Core dispatcher ───────────────────────────────────────────────────────────

def _run_metrics(anon_events: list[dict[str, Any]], definitions: dict[str, Any],
                 session_summaries: list[dict[str, Any]], source_hash: str | None,
                 skip_api_count: int, synthetic_excluded: int,
                 include_stream: bool, session_metric: str,
                 dates_by_session: dict[str, str | None] | None = None,
                 algo_map: dict[str, str] | None = None,
                 cap: CaptureConfig | None = None) -> dict[str, Any]:
    cap   = cap or _CAPTURE
    df    = _events_to_df(anon_events)
    _amap = algo_map or {}

    metric_results: dict[str, dict[str, Any]] = {}
    for name, defn in definitions.items():
        alias = defn.get("algorithm")
        if not alias:
            print(f"WARNING: definition '{name}' missing 'algorithm' — skipped", file=sys.stderr)
            continue
        dtype = _resolve_algo(alias, _amap)
        meta  = _PRIMITIVES.get(dtype)
        if meta is None:
            print(f"WARNING: definition '{name}' algorithm '{alias}' → unknown primitive '{dtype}' — skipped", file=sys.stderr)
            continue
        if meta["needs_trigger"] and "trigger_source" not in defn:
            defn = {**defn, "trigger_source": name}
        metric_results[name] = meta["fn"](df, defn, cap)

    # Hint counts per session from the DataFrame
    hints_df = df[(df.event == "hint") & (df.synthetic != True)]
    hint_counts = hints_df.groupby("session_hash").size().to_dict()

    sm_result  = metric_results.get(session_metric, {})
    fam_by_sid = {sid: v.get("family")
                  for sid, v in sm_result.get("per_session", {}).items()}

    per_session = []
    for summary in session_summaries:
        if summary.get("smoke"):
            continue
        sid = summary["id_hash"]
        entry: dict[str, Any] = {
            "date":                 (dates_by_session or {}).get(sid),
            "session_hash":         sid,
            "session_first_family": fam_by_sid.get(sid),
            "hints":                hint_counts.get(sid, 0),
            "metrics":              {},
        }
        for name, result in metric_results.items():
            ps = result.get("per_session", {}).get(sid)
            if ps and "total" in ps:
                entry["metrics"][name] = ps
        per_session.append(entry)

    total_hints = len(hints_df)
    smoke_excluded = sum(1 for s in session_summaries if s.get("smoke"))
    session_count  = len([s for s in session_summaries if not s.get("smoke")])

    return {
        "metric_results":     metric_results,
        "per_session":        per_session,
        "session_summaries":  session_summaries,
        "source_hash":        source_hash,
        "session_count":      session_count,
        "smoke_excluded":     smoke_excluded,
        "synthetic_excluded": synthetic_excluded,
        "skip_api_count":     skip_api_count,
        "anon_events":        anon_events if include_stream else [],
        "total_hints":        total_hints,
        "session_metric":     session_metric,
    }


# ── Compute (from trace files) ────────────────────────────────────────────────

def compute(trace_files: list[str], definitions: dict[str, Any],
            include_stream: bool = False,
            session_metric: str = "first_lookup",
            algo_map: dict[str, str] | None = None,
            source_map: dict[str, Any] | None = None,
            cap: CaptureConfig | None = None) -> dict[str, Any]:
    cap               = cap or _CAPTURE
    hasher            = hashlib.sha256()
    all_anon_events:   list[dict[str, Any]] = []
    session_summaries: list[dict[str, Any]] = []
    dates_by_session:  dict[str, str | None] = {}
    synthetic_excluded = skip_api_count = 0

    echo_dedup_configs = [
        {
            "source":       defn.get("trigger_source", name),
            "field":        defn.get("echo_dedup_field",        "searched"),
            "strip_prefix": defn.get("echo_dedup_strip_prefix", "Read "),
        }
        for name, defn in definitions.items()
        if defn.get("echo_dedup", "").lower() in ("true", "1", "yes")
    ]

    for path in sorted(trace_files):
        try:
            with open(path, "rb") as _fh:
                raw = _fh.read()
            hasher.update(raw)
            _sm     = source_map or _DEFAULT_SOURCE_MAP
            events  = [n for line in _decode_bytes(raw).splitlines()
                       if line.strip()
                       for n in [_normalize_event(json.loads(line), _sm)]
                       if n is not None]
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue

        sid      = cap.session_id_from_path(path)
        sid_hash = _hash_session_id(sid)
        is_smoke = sid.startswith(cap.smoke_prefix)
        ts_zero  = next((e.get("ts", 0) for e in events), 0)

        session_date   = (datetime.fromtimestamp(ts_zero, tz=timezone.utc).strftime("%Y-%m-%d")
                          if ts_zero and not is_smoke else None)
        raw_hint_count = sum(1 for e in events
                             if e.get("event") == "hint" and not e.get("synthetic"))
        session_summaries.append({
            "id_hash":    sid_hash,
            "hint_count": raw_hint_count,
            "smoke":      is_smoke,
            "date":       session_date,
        })
        if is_smoke:
            continue

        dates_by_session[sid_hash] = session_date

        for cfg in echo_dedup_configs:
            events = _preprocess_read_gate_echoes(
                events, cfg["source"], cfg["field"], cfg["strip_prefix"]
            )

        session_had_api = False
        seq = 0
        for ev in events:
            anon = _anonymize_event(ev, sid_hash, ts_zero, cap)
            if anon is not None:
                anon["seq"] = seq
                seq += 1
                if anon.get("event") == "hint" and anon.get("synthetic"):
                    synthetic_excluded += 1
                all_anon_events.append(anon)
            if ev.get("event") == "action":
                inv = ev.get("invocation", "")
                if cap.is_api_call(inv):
                    session_had_api = True
                elif not session_had_api and cap.is_packages_bypass(ev):
                    skip_api_count += 1

    return _run_metrics(all_anon_events, definitions, session_summaries,
                        hasher.hexdigest(), skip_api_count, synthetic_excluded,
                        include_stream, session_metric, dates_by_session,
                        algo_map=algo_map, cap=cap)


# ── Compute (from embedded stream) ───────────────────────────────────────────

def compute_anon(events: list[dict[str, Any]], definitions: dict[str, Any],
                 session_slice: tuple[int | None, int | None] | None = None,
                 include_stream: bool = True,
                 session_metric: str = "first_lookup",
                 algo_map: dict[str, str] | None = None,
                 cap: CaptureConfig | None = None) -> dict[str, Any]:
    cap = cap or _CAPTURE
    if session_slice is not None:
        ordered = list(dict.fromkeys(e.get("session_hash") for e in events))
        start, stop = session_slice
        keep   = set(ordered[start:stop])
        events = [e for e in events if e.get("session_hash") in keep]

    # Add seq per session
    seqs: dict[str, int] = {}
    events_seq = []
    for ev in events:
        sid = ev.get("session_hash", "unknown")
        ev2 = dict(ev)
        ev2["seq"] = seqs.get(sid, 0)
        seqs[sid]  = ev2["seq"] + 1
        events_seq.append(ev2)

    hint_counts: dict[str, int] = {}
    for ev in events_seq:
        if ev.get("event") == "hint" and not ev.get("synthetic"):
            sid = ev.get("session_hash")
            hint_counts[sid] = hint_counts.get(sid, 0) + 1

    session_summaries = [
        {"id_hash": sid, "hint_count": hint_counts.get(sid, 0), "smoke": False, "date": None}
        for sid in dict.fromkeys(e.get("session_hash", "") for e in events_seq)
    ]

    return _run_metrics(events_seq, definitions, session_summaries,
                        None, 0, 0, include_stream, session_metric,
                        algo_map=algo_map, cap=cap)


# ── pandas accessor ───────────────────────────────────────────────────────────
# DARP as a pandas extension, alongside the CLI: a thin shell over the same
# engine (`compute_anon` → `build_darp`). The DataFrame rows must already be in
# DARP's anonymized-event schema (columns: event, session_hash, plus per-event
# fields like source/invocation/ts) — i.e. what the embedded stream of a .darp
# contains. Capture/classification config is passed explicitly per call (via
# `capture=`), built into a CaptureConfig and threaded through `cap=`, so the
# accessor never mutates the process-wide config and two DataFrames with
# different configs don't interfere.

def _df_to_events(df: Any) -> list[dict[str, Any]]:
    """DataFrame rows → event dicts, dropping scalar-NaN cells (absent fields)."""
    events: list[dict[str, Any]] = []
    for rec in df.to_dict("records"):
        events.append({k: v for k, v in rec.items()
                       if not (isinstance(v, float) and math.isnan(v))})
    return events


@pd.api.extensions.register_dataframe_accessor("darp")
class _DarpAccessor:
    """`df.darp.metrics(defs)` / `df.darp.report(cfg)` over a DataFrame of events."""

    def __init__(self, pandas_obj: Any) -> None:
        self._df = pandas_obj

    def metrics(self, definitions: dict[str, Any], *,
                capture: dict[str, Any] | None = None,
                session_metric: str = "first_lookup",
                algo_map: dict[str, str] | None = None) -> dict[str, Any]:
        """Re-derive the raw metric_results from the events in this DataFrame."""
        cap  = CaptureConfig.from_dict(capture) if capture is not None else _CAPTURE
        data = compute_anon(_df_to_events(self._df), definitions,
                            session_metric=session_metric, algo_map=algo_map, cap=cap)
        return data["metric_results"]

    def report(self, cfg: dict[str, Any], *,
               capture: dict[str, Any] | None = None) -> dict[str, Any]:
        """Build a full .darp dict from the events in this DataFrame and `cfg`.

        `cfg` takes the same keys as build_darp's (subject, definitions,
        include_stream, …); definitions/session_metric/algo_map are also read
        from it to run the engine.
        """
        cap  = CaptureConfig.from_dict(capture) if capture is not None else _CAPTURE
        data = compute_anon(_df_to_events(self._df), cfg["definitions"],
                            session_metric=cfg.get("session_metric", "first_lookup"),
                            algo_map=cfg.get("algo_map"), cap=cap)
        return build_darp(data, cfg, cap=cap)


# ── Report assembly ───────────────────────────────────────────────────────────

def build_darp(data: dict[str, Any], cfg: dict[str, Any],
               cap: CaptureConfig | None = None) -> dict[str, Any]:
    cap         = cap or _CAPTURE
    now         = datetime.now(timezone.utc).isoformat(timespec="seconds")
    script_path = os.path.abspath(__file__)
    try:
        with open(script_path, "rb") as fh:
            script_hash = _sha256_prefixed(fh.read())
    except OSError:
        script_hash = "unavailable"

    format_version = cfg.get("format_version", _DARP_FORMAT_VERSION)
    subject        = cfg["subject"]
    project        = cfg.get("project")
    orcid          = cfg.get("orcid")
    repo           = cfg.get("repo")
    artifacts      = cfg.get("artifacts") or []
    links          = cfg.get("links") or {}
    citation       = cfg.get("citation")
    license_       = cfg.get("license")
    include_stream = cfg["include_stream"]
    source_darp_hash = cfg.get("source_darp_hash")
    definitions      = cfg["definitions"]
    sm               = cfg.get("session_metric", "first_lookup")
    min_sessions     = cfg.get("min_sessions", 5)

    metric_results = data["metric_results"]
    n              = data["session_count"]
    sm_result      = metric_results.get(sm, {})

    health = {
        f"{sm}_specific_pct": sm_result.get("pct"),
        f"{sm}_specific_n":   sm_result.get("specific_n", 0),
        **{f"{sm}_{fam}_n":   sm_result.get(f"{fam}_n", 0) for fam in sorted(cap.generic_families)},
        f"{sm}_other_n":      sm_result.get("other_n", 0),
        f"{sm}_no_api_n":     sm_result.get("no_api_n", 0),
        "packages_skip_count": data["skip_api_count"],
        "session_count":       n,
    }

    metrics: list[dict[str, Any]] = []
    checks:  list[dict[str, Any]] = []

    algo_map = cfg.get("algo_map", {})
    for name in sorted(metric_results):
        result = metric_results[name]
        defn   = definitions.get(name, {})
        dtype  = _resolve_algo(defn.get("algorithm", ""), algo_map)
        meta   = _PRIMITIVES.get(dtype, {})
        atype  = meta.get("abstract_type", dtype)

        if meta.get("is_session_level"):
            n_val = (result.get("specific_n", 0) +
                     sum(result.get(f"{fam}_n", 0) for fam in cap.generic_families) +
                     result.get("other_n", 0) +
                     result.get("no_api_n", 0))
            k_val = result.get("specific_n", 0)
            bd: dict[str, Any] = {
                "specific_n": result.get("specific_n", 0),
                **{f"{fam}_n": result.get(f"{fam}_n", 0) for fam in sorted(cap.generic_families)},
                "other_n":    result.get("other_n", 0),
                "no_api_n":   result.get("no_api_n", 0),
            }
        elif meta.get("has_divergence"):
            n_val = result.get("total", 0)
            k_val = result.get("followed", 0)
            pg    = result.get("per_gate_pct")
            sess  = result.get("session_pct")
            div   = result.get("divergence_pts")
            dmax  = float(result.get("divergence_max", 20.0))
            bd    = {
                "followed":       k_val,
                "routed":         result.get("routed", 0),
                "per_gate_pct":   pg,
                "session_pct":    sess,
                "divergence_pts": div,
                "divergence_max": dmax,
            }
            if div is not None:
                checks.append({
                    "check":    f"{name}_divergence",
                    "metric":   name,
                    "detail":   f"per-gate {pg}% vs session {sess}% diverge by {div} pts",
                    "expected": f"divergence <= {dmax} pts",
                    "observed": f"{div} pts",
                    "status":   "WARNING" if div > dmax else "PASS",
                })
        else:
            n_val = result.get("total", 0)
            k_val = result.get("followed", 0)
            bd    = {
                "followed": k_val,
                "modified": result.get("modified", 0),
                "routed":   result.get("routed", 0),
                "memory":   result.get("memory", 0),
            }

        metrics.append({
            "name":      name,
            "type":      atype,
            "n":         n_val,
            "k":         k_val if n_val > 0 else None,
            "value":     result.get("pct") if meta.get("is_session_level") else result.get("pct", 0),
            "breakdown": bd,
        })

    checks.append({
        "check":    "session_count",
        "metric":   "all",
        "detail":   f"{n} sessions included (smoke excluded: {data['smoke_excluded']})",
        "expected": f">= {min_sessions} sessions for reportable signal",
        "observed": str(n),
        "status":   "PASS" if n >= min_sessions else "WARNING",
    })

    fls_sum = (sm_result.get("specific_n", 0) +
               sum(sm_result.get(f"{fam}_n", 0) for fam in cap.generic_families) +
               sm_result.get("other_n", 0) +
               sm_result.get("no_api_n", 0))
    checks.append({
        "check":    "session_first_coverage",
        "metric":   f"{sm}_specific",
        "detail": (
            f"{sm_result.get('specific_n', 0)} specific-first, "
            + ", ".join(f"{sm_result.get(f'{fam}_n', 0)} {fam}-first"
                        for fam in sorted(cap.generic_families))
            + f", {sm_result.get('other_n', 0)} other-first"
            + f", {sm_result.get('no_api_n', 0)} no-api sessions"
        ),
        "expected": f"{sm} totals == session_count",
        "observed": f"{fls_sum} == {n}",
        "status":   "PASS" if fls_sum == n else "WARNING",
    })

    # ── Assemble algorithm block ──────────────────────────────────────────────
    algo_block: dict[str, Any] = {
        "engine": {"name": "pandas", "version": pd.__version__, "language": "python"},
        "parameters": {
            "session_metric":            sm,
            "min_sessions":              min_sessions,
            "classification_categories": (
                ["specific_n"]
                + [f"{f}_n" for f in sorted(cap.generic_families)]
                + ["other_n", "no_api_n"]
            ),
            "capture": {
                "api_command":       cap.api_command,
                "packages_path":     cap.packages_path,
                "vibe_pattern":      cap.vibe_pattern,
                "memory_tool":       cap.memory_tool,
                "trace_pattern":     cap.trace_pattern,
                "smoke_prefix":      cap.smoke_prefix,
                "packages_tools":    sorted(cap.packages_tools),
                "specific_families": sorted(cap.specific_families),
                "generic_families":  sorted(cap.generic_families),
            },
            "algorithm_map":   algo_map,
            "source_map":      cfg.get("source_map", _DEFAULT_SOURCE_MAP),
            "thresholds":      cfg.get("thresholds", {}),
            "baseline_commit": cfg.get("baseline_commit"),
            "baseline_values": cfg.get("baseline_values", {}),
            "anchor":          cfg.get("anchor", {}),
        },
        "definitions": definitions,
    }

    # ── Assemble definitions block ────────────────────────────────────────────
    definitions_block: dict[str, Any] = {"subject": subject}
    if project:      definitions_block["project"]      = project
    if orcid:        definitions_block["orcid"]        = orcid
    if repo:         definitions_block["repo"]         = repo
    if artifacts:    definitions_block["artifacts"]    = artifacts
    if links:        definitions_block["links"]        = links
    if citation:     definitions_block["citation"]     = citation
    if license_:     definitions_block["license"]      = license_
    definitions_block["algorithm"] = algo_block

    # ── Derive measurement_period from session dates ──────────────────────────
    session_dates = [
        s.get("date") for s in data["session_summaries"]
        if s.get("date") and not s.get("smoke")
    ]
    if session_dates:
        measurement_period: dict[str, Any] = {
            "from": min(session_dates),
            "to":   max(session_dates),
        }
    else:
        measurement_period = {"from": None, "to": None}

    # ── Determine source_hash with prefix ────────────────────────────────────
    raw_source_hash = data["source_hash"]
    if raw_source_hash is not None:
        prefixed_source_hash: str | None = f"sha256:{raw_source_hash}"
    else:
        prefixed_source_hash = None

    if source_darp_hash is not None:
        prefixed_source_darp_hash: str | None = f"sha256:{source_darp_hash}"
    else:
        prefixed_source_darp_hash = None

    source_type        = cfg.get("source_type", "files")
    source_description = cfg.get("source_description", "")

    # ── Assemble data block ───────────────────────────────────────────────────
    data_block: dict[str, Any] = {
        "generated_at":     now,
        "measurement_period": measurement_period,
        "health":           health,
        "metrics":          metrics,
        "trend":            data["per_session"],
        "data_commitment": {
            "source_type":        source_type,
            "source_description": source_description,
            "session_count":      n,
            "smoke_excluded":     data["smoke_excluded"],
            "synthetic_excluded": data["synthetic_excluded"],
            "event_count":        data["total_hints"],
            "source_hash":        prefixed_source_hash,
            "source_darp_hash":   prefixed_source_darp_hash,
            "sessions":           data["session_summaries"],
            "reproducibility": {
                "included": include_stream,
                **({"events": data["anon_events"]} if include_stream else {}),
            },
        },
    }

    # ── Compute hashes (canonical JSON, see _canon_dumps) ─────────────────────
    config_hash   = _sha256_prefixed(_canon_dumps(definitions_block).encode())
    document_hash = _sha256_prefixed(_canon_dumps(data_block).encode())

    # content_hash covers both blocks (what OTS/ORCID commit to)
    _content_fields = {"definitions": definitions_block, "data": data_block}
    content_hash = _sha256_prefixed(_canon_dumps(_content_fields).encode())

    # ── Assemble metadata block ───────────────────────────────────────────────
    metadata_block: dict[str, Any] = {
        "config_hash":        config_hash,
        "document_hash":      document_hash,
        "content_hash":       content_hash,
        "consistency_checks": checks,
        "generator": {
            "version":     __version__,
            "script":      os.path.basename(script_path),
            "script_hash": script_hash,
        },
        "timestamp":    None,
    }
    # NB: the authorship repo lives in definitions.repo (hashed), not here — it is
    # half of the orcid+repo claim and must be tamper-evident. metadata holds only
    # post-generation, append-only data (hashes, timestamp/OTS proofs, checks).

    out: dict[str, Any] = {
        "$schema":      f"darp:{format_version}",
        "darp_version": format_version,
        "definitions":  definitions_block,
        "data":         data_block,
        "metadata":     metadata_block,
    }
    return out


# ══════════════════════════════════════════════════════════════════════════════
# ANALYZE LAYER
# ══════════════════════════════════════════════════════════════════════════════

def _load_ini_baseline(path: str) -> tuple[dict[str, float], str | None]:
    cfg = configparser.ConfigParser()
    cfg.read(path)
    values: dict[str, float] = {}
    if cfg.has_section("values"):
        for k, v in cfg.items("values"):
            v = v.strip()
            if v:
                try:
                    values[k] = float(v)
                except ValueError:
                    pass
    commit = None
    if cfg.has_section("baseline"):
        commit = cfg.get("baseline", "commit", fallback="").strip() or None
    return values, commit


def _load_darp_baseline(path: str) -> dict[str, float]:
    try:
        d = _json_load(path)
        metrics = d.get("data", {}).get("metrics", [])
        return {m["name"]: float(m["value"])
                for m in metrics if "value" in m and m["value"] is not None}
    except (OSError, json.JSONDecodeError, KeyError):
        return {}


def _parse_inline_baseline(s: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for part in s.split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            try:
                out[k.strip()] = float(v.strip())
            except ValueError:
                pass
    return out


def _load_thresholds(ini_path: str) -> dict[str, float]:
    cfg = configparser.ConfigParser()
    cfg.read(ini_path)
    return {
        "noise_band": float(cfg.get("thresholds", "noise_band", fallback="10.0")),
        "warn_band":  float(cfg.get("thresholds", "warn_band",  fallback="20.0")),
        "div_max":    float(cfg.get("thresholds", "divergence",  fallback="20.0")),
    }


def _anomaly_status(delta: float, noise: float, warn: float) -> str:
    if abs(delta) < noise:
        return "PASS"
    return "WARNING" if abs(delta) < warn else "FAIL"


def analyze(darp: dict[str, Any], baselines: dict[str, float], thresholds: dict[str, float],
            baseline_commit: str | None, baseline_source: str) -> dict[str, Any]:
    metrics_out = []
    checks_out  = []
    overall     = "PASS"

    noise = thresholds["noise_band"]
    warn  = thresholds["warn_band"]
    dmax  = thresholds["div_max"]

    data_blk = darp.get("data", {})
    defs_blk = darp.get("definitions", {})
    algo     = defs_blk.get("algorithm", {})
    params   = algo.get("parameters", {})
    defs     = algo.get("definitions", {})
    sm       = params.get("session_metric", "first_lookup")
    _amap    = params.get("algorithm_map", {})
    tvm_list = [n for n, d in defs.items()
                if _PRIMITIVES.get(_resolve_algo(d.get("algorithm", ""), _amap), {}).get("has_divergence")]

    hk      = f"{sm}_specific_pct"
    health  = data_blk.get("health", {})
    fls_pct = health.get(hk)
    fls_bl  = baselines.get(hk)
    if fls_pct is not None and fls_bl is not None:
        delta   = round(fls_pct - fls_bl, 1)
        status  = _anomaly_status(delta, noise, warn)
        in_band = abs(delta) < noise
        detail  = (f"{hk} within noise band ({delta:+.1f} pts from {fls_bl}%)"
                   if in_band else f"{hk} moved {delta:+.1f} pts from baseline {fls_bl}%")
        metrics_out.append({"name": hk, "pct": fls_pct,
                             "baseline": fls_bl, "delta": delta, "status": status,
                             "source": "health"})
        checks_out.append({"check": "anomaly_threshold", "metric": hk,
                            "delta": delta, "status": status, "detail": detail})
        if status != "PASS" and overall == "PASS":
            overall = status
        if status == "FAIL":
            overall = "FAIL"
    elif fls_pct is not None:
        metrics_out.append({"name": hk, "pct": fls_pct,
                             "baseline": None, "delta": None, "status": "NO_BASELINE",
                             "source": "health"})

    for m in data_blk.get("metrics", []):
        name = m["name"]
        pct  = m.get("value", 0)
        bl   = baselines.get(name)
        if bl is None:
            metrics_out.append({"name": name, "pct": pct, "baseline": None,
                                 "delta": None, "status": "NO_BASELINE"})
            continue
        delta   = round(pct - bl, 1)
        status  = _anomaly_status(delta, noise, warn)
        in_band = abs(delta) < noise
        detail  = (f"{name} within noise band ({delta:+.1f} pts from {bl}%)"
                   if in_band else f"{name} moved {delta:+.1f} pts from baseline {bl}%")
        metrics_out.append({"name": name, "pct": pct, "baseline": bl,
                             "delta": delta, "status": status})
        checks_out.append({"check": "anomaly_threshold", "metric": name,
                            "delta": delta, "status": status, "detail": detail})
        if status != "PASS" and overall == "PASS":
            overall = status
        if status == "FAIL":
            overall = "FAIL"

    metrics_by_name = {m["name"]: m for m in data_blk.get("metrics", [])}
    for tvm in tvm_list:
        bd   = metrics_by_name.get(tvm, {}).get("breakdown", {})
        pg   = bd.get("per_gate_pct")
        sess = bd.get("session_pct")
        if pg is None or sess is None:
            continue
        div   = round(abs(pg - sess), 1)
        dmax_ = float(defs.get(tvm, {}).get("divergence_max", dmax))
        status = "WARNING" if div > dmax_ else "PASS"
        checks_out.append({
            "check":  f"{tvm}_divergence",
            "metric": tvm,
            "delta":  div,
            "status": status,
            "detail": f"per-gate {pg}% vs session {sess}% diverge by {div} pts",
        })
        if status != "PASS" and overall == "PASS":
            overall = status

    defs_info = darp.get("definitions", {})
    return {
        "subject":      defs_info.get("subject"),
        "generated_at": data_blk.get("generated_at"),
        "sessions":     data_blk.get("data_commitment", {}).get("session_count"),
        "baseline": {
            "commit": baseline_commit,
            "source": baseline_source,
        },
        "metrics": metrics_out,
        "checks":  checks_out,
        "overall": overall,
    }


_STATUS_ICON: dict[str, str] = {"PASS": "✓", "WARNING": "⚠", "FAIL": "✗"}

def _icon(status: str) -> str:
    return _STATUS_ICON.get(status, "?")


def _print_analysis(result: dict[str, Any], quiet: bool) -> None:
    print(f"\nDARPfile: {result['subject']} @ {result['generated_at']}")
    print(f"Sessions: {result['sessions']}")
    bl = result["baseline"]
    commit_str = f" @ {bl['commit'][:12]}" if bl["commit"] else ""
    print(f"Baseline: {bl['source']}{commit_str}\n")

    print("── Metrics ──")
    for m in result["metrics"]:
        if m["baseline"] is None:
            print(f"  {'?':1} {m['name']:<20} {m['pct']:>3}%  (no baseline)")
        else:
            delta_str = f"{m['delta']:+.1f} pts"
            print(f"  {_icon(m['status'])} {m['name']:<20} {m['pct']:>3}%  "
                  f"(baseline {m['baseline']}%, {delta_str})")

    print("\n── Checks ──")
    for c in result["checks"]:
        if not quiet or c["status"] != "PASS":
            print(f"  [{_icon(c['status'])}] {c['check']}/{c['metric']}: {c['detail']}")

    print(f"\n{result['overall']}  ({'all checks pass' if result['overall'] == 'PASS' else 'see above'})\n")


# ══════════════════════════════════════════════════════════════════════════════
# VERIFY LAYER
# ══════════════════════════════════════════════════════════════════════════════

_ROUNDING_TOL  = 0.2
_KNOWN_VERSIONS = {_DARP_FORMAT_VERSION}
_V1_0_REQUIRED  = [
    "darp_version", "definitions", "data", "metadata",
]


def _find_schema(override: str | None) -> str | None:
    if override:
        return override
    candidate = os.path.join(_HERE, "darp.schema.json")
    return candidate if os.path.isfile(candidate) else None


def _field_presence_check(darp: dict[str, Any]) -> list[str]:
    missing = [f for f in _V1_0_REQUIRED if f not in darp]
    return [f"missing required field: {f}" for f in missing]


def _cross_validate(darp: dict[str, Any]) -> list[str]:
    """Enforce metric.type against algorithm.definitions and validate breakdown keys."""
    errors: list[str] = []
    data_blk = darp.get("data", {})
    defs_blk = darp.get("definitions", {})
    algo     = defs_blk.get("algorithm", {})
    defs     = algo.get("definitions", {})
    params   = algo.get("parameters", {})
    _amap        = params.get("algorithm_map", {})
    metric_names = {m.get("name") for m in data_blk.get("metrics", [])}

    for metric in data_blk.get("metrics", []):
        name = metric.get("name", "")
        if name not in defs:
            errors.append(f"metric '{name}': no matching algorithm.definition")
            continue
        raw_algo      = defs[name].get("algorithm", "")
        primitive     = _resolve_algo(raw_algo, _amap)
        meta          = _PRIMITIVES.get(primitive, {})
        expected_type = meta.get("abstract_type", primitive)
        actual_type   = metric.get("type")
        if actual_type is None:
            errors.append(f"metric '{name}': missing 'type' field")
            continue
        if actual_type != expected_type:
            errors.append(
                f"metric '{name}': type mismatch — "
                f"definition algorithm='{raw_algo}' (→ '{expected_type}') "
                f"but metric has '{actual_type}'"
            )
            continue
        rb  = meta.get("required_breakdown", [])
        req = params.get(rb, []) if isinstance(rb, str) else rb
        bd = metric.get("breakdown", {})
        for key in req:
            if key not in bd:
                errors.append(f"metric '{name}' ({actual_type}): breakdown missing '{key}'")

    for def_name in defs:
        if def_name not in metric_names:
            errors.append(f"definition '{def_name}' has no entry in metrics[]")

    return errors


def _validate_schema(darp: dict[str, Any], schema_path: str | None) -> list[str]:
    version = darp.get("darp_version", "")
    errors: list[str] = []

    if version not in _KNOWN_VERSIONS:
        errors.append(f"unrecognised darp_version: {version!r} (known: {sorted(_KNOWN_VERSIONS)})")

    if schema_path:
        try:
            import jsonschema
            schema_errs = [
                e.message for e in sorted(
                    jsonschema.Draft7Validator(_json_load(schema_path)).iter_errors(darp), key=str
                )
            ]
            if schema_errs:
                return errors + schema_errs
        except ImportError:
            print("WARNING: jsonschema not installed — falling back to field-presence check",
                  file=sys.stderr)
            errs = _field_presence_check(darp)
            if errs:
                return errors + errs
        except (OSError, json.JSONDecodeError) as e:
            print(f"WARNING: cannot read schema file {schema_path}: {e} — falling back to field-presence check",
                  file=sys.stderr)
            errs = _field_presence_check(darp)
            if errs:
                return errors + errs
    else:
        errs = _field_presence_check(darp)
        if errs:
            return errors + errs

    return errors + _cross_validate(darp)


def _close(a: float | None, b: float | None, tol: float = _ROUNDING_TOL) -> bool:
    if a is None or b is None:
        return a == b
    return abs(a - b) <= tol


def _rederive_checks(darp: dict[str, Any]) -> list[dict[str, Any]]:
    data_blk = darp.get("data", {})
    meta_blk = darp.get("metadata", {})
    defs_blk = darp.get("definitions", {})
    algo     = defs_blk.get("algorithm", {})
    params   = algo.get("parameters", {})
    defs     = algo.get("definitions", {})
    sm       = params.get("session_metric", "first_lookup")
    _amap    = params.get("algorithm_map", {})
    tvm_list = [name for name, d in defs.items()
                if _PRIMITIVES.get(_resolve_algo(d.get("algorithm", ""), _amap), {}).get("has_divergence")]
    metrics_by_name = {m["name"]: m for m in data_blk.get("metrics", [])}
    dc      = data_blk.get("data_commitment", {})
    stored  = {(c["check"], c["metric"]): c for c in meta_blk.get("consistency_checks", [])}
    results = []

    for tvm in tvm_list:
        bd   = metrics_by_name.get(tvm, {}).get("breakdown", {})
        pg   = bd.get("per_gate_pct")
        sess = bd.get("session_pct")
        if pg is None or sess is None:
            continue
        div_max      = float(defs.get(tvm, {}).get("divergence_max", 20.0))
        computed_div = round(abs(pg - sess), 1)
        exp_status   = "WARNING" if computed_div > div_max else "PASS"
        key          = (f"{tvm}_divergence", tvm)
        sc           = stored.get(key, {})
        stored_obs_str = sc.get("observed", "")
        try:
            stored_obs = float(stored_obs_str.replace(" pts", "").strip())
        except ValueError:
            stored_obs = None
        match = _close(computed_div, stored_obs) and exp_status == sc.get("status")
        results.append({
            "check":            f"{tvm}_divergence",
            "metric":           tvm,
            "detail":           f"re-derived {computed_div} pts (stored: {stored_obs_str})",
            "rederived_status": exp_status,
            "stored_status":    sc.get("status", "—"),
            "match":            match,
        })

    _thresh = params.get("thresholds", {})
    noise   = float(_thresh.get("noise_band", 10.0))
    warn    = float(_thresh.get("warn_band",  20.0))

    for name, m in metrics_by_name.items():
        bl  = m.get("baseline")
        pct = m.get("value")
        if bl is None or pct is None:
            continue
        computed_delta = round(pct - bl, 1)
        exp_status     = _anomaly_status(computed_delta, noise, warn)
        stored_delta   = m.get("delta")
        key            = ("anomaly_threshold", name)
        sc             = stored.get(key, {})
        match = _close(computed_delta, stored_delta) and exp_status == sc.get("status")
        results.append({
            "check":            "anomaly_threshold",
            "metric":           name,
            "detail":           f"re-derived delta {computed_delta:+.1f} pts from baseline {bl}% "
                                f"(stored: {stored_delta:+.1f})",
            "rederived_status": exp_status,
            "stored_status":    sc.get("status", "—"),
            "match":            match,
        })

    n         = dc.get("session_count", 0)
    min_s     = int(params.get("min_sessions", 5))
    exp_status = "PASS" if n >= min_s else "WARNING"
    key        = ("session_count", "all")
    sc         = stored.get(key, {})
    match = (exp_status == sc.get("status") and str(n) == sc.get("observed", ""))
    results.append({
        "check":            "session_count",
        "metric":           "all",
        "detail":           f"{n} sessions (smoke excluded: {dc.get('smoke_excluded', 0)})",
        "rederived_status": exp_status,
        "stored_status":    sc.get("status", "—"),
        "match":            match,
    })

    health = data_blk.get("health")
    if health is not None:
        cats    = params.get("classification_categories", [])
        fls_sum = sum(health.get(f"{sm}_{cat}", 0) for cat in cats)
        exp_status = "PASS" if fls_sum == n else "WARNING"
        key        = ("session_first_coverage", f"{sm}_specific")
        sc         = stored.get(key, {})
        match = exp_status == sc.get("status")
        results.append({
            "check":            "session_first_coverage",
            "metric":           f"{sm}_specific",
            "detail":           f"session_first sum {fls_sum} vs session_count {n}",
            "rederived_status": exp_status,
            "stored_status":    sc.get("status", "—"),
            "match":            match,
        })

    return results


def _recompute_hash(trace_dir: str) -> str:
    h = hashlib.sha256()
    for path in sorted(glob.glob(os.path.join(trace_dir, _CAPTURE.trace_pattern))):
        with open(path, "rb") as f:
            h.update(f.read())
    return h.hexdigest()


def _replay_metrics(darp: dict[str, Any], trace_dir: str) -> list[dict[str, Any]]:
    defs_blk    = darp.get("definitions", {})
    algo        = defs_blk.get("algorithm", {})
    params      = algo.get("parameters", {})
    definitions = algo.get("definitions", {})
    sm          = params.get("session_metric", "first_lookup")
    data_blk    = darp.get("data", {})

    trace_files = sorted(glob.glob(os.path.join(trace_dir, _CAPTURE.trace_pattern)))
    _amap       = params.get("algorithm_map", {})
    _smap       = params.get("source_map", _DEFAULT_SOURCE_MAP)
    data        = compute(trace_files, definitions, session_metric=sm, algo_map=_amap, source_map=_smap)

    stored_metrics = {m["name"]: m for m in data_blk.get("metrics", [])}
    results: list[dict[str, Any]] = []
    for name, result in sorted(data["metric_results"].items()):
        computed_pct = result.get("pct", 0)
        stored       = stored_metrics.get(name, {})
        stored_pct   = stored.get("value")
        match        = stored_pct is not None and abs(computed_pct - stored_pct) <= 1
        results.append({
            "metric": name,
            "detail": f"computed {computed_pct}% (stored {stored_pct}%)",
            "match":  match,
        })

    sc        = data["session_count"]
    stored_sc = data_blk.get("data_commitment", {}).get("session_count")
    results.append({
        "metric": "session_count",
        "detail": f"computed {sc} (stored {stored_sc})",
        "match":  sc == stored_sc,
    })
    return results


def _verify_icon(ok: bool) -> str:
    return _icon("PASS" if ok else "FAIL")


def _run_verify(darp_path: str, traces_dir: str | None, schema_path: str | None,
                quiet: bool) -> int:
    try:
        darp: Any = _json_load(darp_path)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR  cannot read {darp_path}: {e}")
        return 1

    fail = 0

    def emit(ok: bool, label: str, detail: str) -> None:
        nonlocal fail
        if not ok:
            fail += 1
        if not ok or not quiet:
            print(f"  [{_verify_icon(ok)}] {label}: {detail}")

    defs_blk  = darp.get("definitions", {})
    meta_blk  = darp.get("metadata", {})
    data_blk  = darp.get("data", {})
    orcid_val = defs_blk.get("orcid", "—")
    orcid_str = f"orcid.org/{orcid_val}" if orcid_val != "—" else "—"
    print(f"\nDARPfile: {os.path.basename(darp_path)}")
    print(f"Subject:  {defs_blk.get('subject', '?')}")
    print(f"Project:  {defs_blk.get('project', '—')}  ORCID: {orcid_str}")
    print(f"At:       {data_blk.get('generated_at', '?')}")
    print(f"Sessions: {data_blk.get('data_commitment', {}).get('session_count', '?')}")

    print("\n── Level 1: Schema validation ──")
    schema_errors = _validate_schema(darp, schema_path)
    if schema_errors:
        for err in schema_errors:
            emit(False, "schema", err)
    else:
        emit(True, "schema", "all required fields present and typed correctly")

    print("\n── Level 2: Arithmetic re-derivation ──")
    for r in _rederive_checks(darp):
        ok = r["match"]
        status_match = ("status match" if r["rederived_status"] == r["stored_status"]
                        else f"status mismatch: re-derived {r['rederived_status']} vs stored {r['stored_status']}")
        emit(ok, f"{r['check']}/{r['metric']}", f"{r['detail']} — {status_match}")

    print("\n── Level 3: Config integrity ──")
    stored_content_hash = meta_blk.get("content_hash")
    if stored_content_hash:
        computed_content_hash = _compute_content_hash(darp)
        cfg_match = computed_content_hash == stored_content_hash
        emit(cfg_match, "content_hash",
             f"header fields consistent ({computed_content_hash[7:23]}…)" if cfg_match
             else f"MISMATCH — stored {stored_content_hash[7:23]}… re-derived {computed_content_hash[7:23]}…")
    else:
        emit(False, "content_hash", "absent — a valid .darp always carries content_hash")

    if traces_dir:
        print("\n── Level 4: Source hash ──")
        # build_darp always stores source_hash "sha256:"-prefixed (or null); strip
        # to the bare hex for comparison with the recomputed digest.
        stored_hash_raw = data_blk.get("data_commitment", {}).get("source_hash") or ""
        stored_hash     = stored_hash_raw[7:] if stored_hash_raw.startswith("sha256:") else ""
        computed_hash   = _recompute_hash(traces_dir)
        match = computed_hash == stored_hash
        emit(match, "source_hash",
             f"match ({computed_hash[:16]}…)" if match
             else f"MISMATCH — stored {stored_hash[:16]}… computed {computed_hash[:16]}…")
        if not match:
            print(f"        note: re-hashes every {_CAPTURE.trace_pattern} in {traces_dir}; "
                  "a capture generated with --sessions covers only a subset, so a "
                  "mismatch here is expected unless --traces points at the same slice.")

        print("\n── Level 5: Metric replay ──")
        for r in _replay_metrics(darp, traces_dir):
            emit(r["match"], r["metric"], r["detail"])

    print(f"\n{'PASS' if fail == 0 else 'FAIL'}  ({fail} failure(s))\n")
    return 0 if fail == 0 else 1


# ══════════════════════════════════════════════════════════════════════════════
# ANCHOR LAYER
# ══════════════════════════════════════════════════════════════════════════════

_OTS_CALENDARS_DEFAULT = [
    "https://a.pool.opentimestamps.org/digest",
    "https://b.pool.opentimestamps.org/digest",
    "https://c.pool.opentimestamps.org/digest",
]


def _load_anchor_config(ini: configparser.ConfigParser) -> list[str]:
    """Return the OTS calendar URLs from ini [anchor], falling back to defaults."""
    raw = ini.get("anchor", "calendars", fallback="").strip()
    return [u.strip() for u in raw.split(",") if u.strip()] or _OTS_CALENDARS_DEFAULT


def _load_anchor_timeout(ini: configparser.ConfigParser) -> int:
    """Network timeout (s) shared by OTS calendars, Bitcoin backend, and ORCID read."""
    return ini.getint("anchor", "timeout_s", fallback=15)


def _load_links(ini_path: str) -> dict[str, str]:
    """Free-form [links] section → {description: url}, descriptions case-preserved.

    Each line is `<free-text description> = <url>`. Read with a case-preserving
    parser (the default lowercases keys) so descriptions keep their capitalization.
    """
    cp = configparser.ConfigParser()
    cp.optionxform = str  # type: ignore[assignment]   # keep description case
    cp.read(ini_path, encoding="utf-8")
    if not cp.has_section("links"):
        return {}
    return {desc: url.strip() for desc, url in cp.items("links") if url.strip()}


def _load_citation(ini: configparser.ConfigParser,
                   orcid: str | None) -> dict[str, Any] | None:
    """[citation] section → a Citation File Format (CFF 1.2.0) object, or None.

    Embeds the same vocabulary as a standalone CITATION.cff so any tool can render
    APA / BibTeX / MLA. The author is built from given/family names plus the
    project ORCID; scalar CFF fields are copied through when present.
    """
    if not ini.has_section("citation"):
        return None

    def g(key: str) -> str:
        return ini.get("citation", key, fallback="").strip()

    title = g("title")
    if not title:
        return None
    cff: dict[str, Any] = {
        "cff-version": "1.2.0",
        "message":     g("message") or "If you use this artifact, please cite it as below.",
        "title":       title,
        "type":        g("type") or "software",
    }
    given, family = g("given_names"), g("family_names")
    if given or family:
        author: dict[str, str] = {}
        if given:  author["given-names"]  = given
        if family: author["family-names"] = family
        if orcid:  author["orcid"]        = f"https://orcid.org/{orcid}"
        cff["authors"] = [author]
    for ini_key, cff_key in (("version", "version"), ("doi", "doi"),
                             ("date_released", "date-released"), ("url", "url")):
        val = g(ini_key)
        if val:
            cff[cff_key] = val
    return cff


# ── ORCID-anchored authorship (login-free, one public read) ───────────────────
#
# Identity is NOT proven by logging in. The report ALWAYS carries the repo in
# the ini (definitions.repo = host/owner/repo). One public read of the ORCID API's
# `/person` endpoint validates three things at once:
#
#   1. the ORCID iD resolves          (a 404 means the number is invalid)
#   2. the author name                (read authoritatively from the record)
#   3. that the repo is the author's  (the goal: does the ORCID profile match
#                                      the user who owns the repo?)
#
#   report: definitions.orcid = Y,  definitions.repo = https://github.com/owner/repo
#        |
#        v  GET <orcid_api>/Y/person   (public, no token)
#   name = "…"   researcher-urls = [ …, https://github.com/owner, … ]
#        |
#        v
# Match rule, by host of definitions.repo:
#   • KNOWN host (github/gitlab/…): the repo's ACCOUNT (host, owner) must equal
#     an account the record lists. Listing your profile `host/owner` once
#     covers every repo under it — only you control that account, so a repo
#     under it is yours. A listed full repo URL matches too (same account).
#   • UNKNOWN host (self-hosted, no trusted account/repo shape): the record
#     must list the definitions.repo URL itself, one-to-one.
# The known-host allowlist (_KNOWN_GIT_HOSTS) is what lets us trust the flat
# `host/owner/...` shape enough to match at the account level; off the allowlist
# we fall back to a literal one-to-one URL match. A bare host (no owner) never matches.
# Only you can add that ORCID link and only you can push under that account →
# the match is proof of authorship.

_ORCID_PUB_API   = "https://pub.orcid.org/v3.0"   # public read API (sandbox: pub.sandbox.orcid.org/v3.0)
_KNOWN_GIT_HOSTS = frozenset({
    "github.com", "gitlab.com", "bitbucket.org",   # major global providers
    "codeberg.org", "gitea.com", "gitee.com",      # open-source / regional hosts
})  # all share the flat host/owner/repo URL shape


def _strip_url(ref: str) -> str:
    """Bare `host/path…` form of a URL: drop scheme, www., query, fragment, slash."""
    s = ref.strip()
    s = re.sub(r"^[a-zA-Z][\w+.-]*://", "", s)            # drop scheme
    s = re.sub(r"^www\.", "", s, flags=re.IGNORECASE)     # drop www.
    return s.split("?", 1)[0].split("#", 1)[0].rstrip("/")


def _git_repo_id(ref: str) -> tuple[str, str, str] | None:
    """Normalize a repo reference to (host, owner, repo) for a KNOWN host, else None.

    Only the exact `host/owner/repo` shape on an allowlisted host is accepted;
    profile URLs, extra path segments, and unknown hosts return None (no guessing).
    """
    parts = _strip_url(ref).split("/")
    if len(parts) != 3:
        return None
    host, owner, repo = parts[0].lower(), parts[1].lower(), parts[2].lower()
    if repo.endswith(".git"):
        repo = repo[:-4]
    if host not in _KNOWN_GIT_HOSTS or not owner or not repo:
        return None
    return (host, owner, repo)


def _known_account(ref: str) -> tuple[str, str] | None:
    """(host, owner) account for a KNOWN-host URL — profile OR repo — else None.

    The owner is the git USER that owns the repo; this matches it exactly (not a
    substring of the URL). `github.com/me` and `github.com/me/proj` both yield
    ('github.com', 'me'). A bare host (`github.com`) has no user → None.
    """
    parts = _strip_url(ref).split("/")
    if len(parts) < 2:
        return None
    host, owner = parts[0].lower(), parts[1].lower()
    if host not in _KNOWN_GIT_HOSTS or not owner:
        return None
    return (host, owner)


def _norm_url(ref: str) -> str:
    """Lowercased bare URL for exact one-to-one comparison (drops a trailing `.git`)."""
    s = _strip_url(ref).lower()
    return s[:-4] if s.endswith(".git") else s


def _orcid_person(orcid_id: str, api_base: str = _ORCID_PUB_API,
                  timeout: int = 15) -> dict[str, Any]:
    """Public-read `<api_base>/<id>/person` — name + researcher-urls in one GET.

    Raises urllib HTTPError 404 if the iD does not resolve (invalid record).
    """
    url = f"{api_base.rstrip('/')}/{orcid_id}/person"
    return json.loads(_http_request(url, headers={"Accept": "application/json"},
                                    timeout=timeout))


def _orcid_name(person: dict[str, Any]) -> str | None:
    """Author display name from a /person payload (credit-name, else given+family)."""
    name   = person.get("name") or {}
    credit = (name.get("credit-name") or {}).get("value")
    if credit:
        return credit
    given  = (name.get("given-names") or {}).get("value") or ""
    family = (name.get("family-name") or {}).get("value") or ""
    return f"{given} {family}".strip() or None


def _person_urls(person: dict[str, Any]) -> list[str]:
    """The researcher-url values listed on an ORCID /person payload."""
    rus = (person.get("researcher-urls") or {}).get("researcher-url", [])
    return [v for ru in rus if (v := (ru.get("url") or {}).get("value"))]


def _verify_ledger_authorship(darp: dict[str, Any], api_base: str = _ORCID_PUB_API,
                              timeout: int = 15) -> dict[str, Any]:
    """Validate the report's ORCID iD, author name, and repo ownership in one read.

    The repo is always in definitions.repo. For a KNOWN host the repo's account
    (host, owner) must be listed on the record (a profile link suffices); for an
    UNKNOWN host the record must list the repo URL itself, one-to-one.

    Returns {"status": "verified"|"mismatch"|"absent"|"invalid"|"error"|"none", ...};
    the resolved author "name" is included once the record is fetched.
    """
    orcid_id = darp.get("definitions", {}).get("orcid")
    repo     = darp.get("definitions", {}).get("repo")
    if not orcid_id or not repo:
        return {"status": "none",
                "message": "report has no definitions.orcid / definitions.repo to match"}
    try:
        person = _orcid_person(orcid_id, api_base, timeout)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "invalid", "orcid": orcid_id,
                    "message": f"ORCID iD {orcid_id} does not resolve (no such record)"}
        return {"status": "error", "message": f"ORCID lookup failed: HTTP {e.code}"}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"status": "error", "message": f"ORCID lookup failed: {e}"}

    name     = _orcid_name(person)
    urls     = _person_urls(person)
    repo_id  = _git_repo_id(repo)

    if repo_id:                                   # KNOWN host → match the account
        repo_str = "/".join(repo_id)
        want     = (repo_id[0], repo_id[1])
        acct_str = "/".join(want)
        accounts = {a for u in urls if (a := _known_account(u))}
        if not accounts:
            return {"status": "absent", "orcid": orcid_id, "name": name,
                    "message": f"ORCID {orcid_id} ({name or '?'}) lists no known-host "
                               f"account; add {acct_str} (or {repo_str})"}
        if want not in accounts:
            shown = ", ".join("/".join(a) for a in sorted(accounts))
            return {"status": "mismatch", "orcid": orcid_id, "name": name,
                    "repo": repo_str,
                    "message": f"repo account {acct_str} is not among the accounts "
                               f"ORCID {orcid_id} ({name or '?'}) lists ({shown})"}
        return {"status": "verified", "orcid": orcid_id, "name": name,
                "repo": repo_str, "account": acct_str}

    # UNKNOWN host → the record must list this exact repo URL (one-to-one with the ini)
    repo_norm = _norm_url(repo)
    listed    = {_norm_url(u) for u in urls}
    if not listed:
        return {"status": "absent", "orcid": orcid_id, "name": name,
                "message": f"ORCID {orcid_id} ({name or '?'}) lists no researcher-url; "
                           f"add {repo} (unknown host needs an exact one-to-one link)"}
    if repo_norm not in listed:
        return {"status": "mismatch", "orcid": orcid_id, "name": name, "repo": repo,
                "message": f"{repo} is not listed on ORCID {orcid_id} ({name or '?'}); "
                           f"an unknown host needs an exact one-to-one researcher-url"}
    return {"status": "verified", "orcid": orcid_id, "name": name, "repo": repo}


def _calendar_base(url: str) -> str:
    """Normalize a calendar URL to the base RemoteCalendar expects (it appends /digest)."""
    base = url.strip().rstrip("/")
    if base.endswith("/digest"):
        base = base[: -len("/digest")]
    return base


def _cmd_stamp(darp_path: str) -> int:
    if not os.path.isfile(darp_path):
        print(f"ERROR: {darp_path} not found", file=sys.stderr)
        return 1

    # Stamping is an ots operation: submit the digest to the calendars in-process
    # via the opentimestamps library (no external `ots` binary).
    try:
        from opentimestamps.calendar import RemoteCalendar
    except ImportError:
        print("ERROR: stamp requires the opentimestamps Python library.\n"
              "  Debian/Ubuntu:  sudo apt-get install python3-opentimestamps\n"
              "  pip:            pip install opentimestamps", file=sys.stderr)
        return 1

    _ini                  = _load_ini(_DEFAULT_INI)
    timeout_s             = int(_ini.get("anchor", "timeout_s", fallback="15"))
    ots_calendars         = _load_anchor_config(_ini)

    try:
        darp = _json_load(darp_path)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read {darp_path}: {e}", file=sys.stderr)
        return 1

    print("Pre-stamp verify...")
    schema_path = _find_schema(None)
    verify_rc   = _run_verify(darp_path, None, schema_path, quiet=True)
    if verify_rc != 0:
        print("ERROR: verify failed — fix issues before stamping.", file=sys.stderr)
        return 1
    print()

    content_hash_str = darp.get("metadata", {}).get("content_hash", "")
    if not content_hash_str or not content_hash_str.startswith("sha256:"):
        print("ERROR: metadata.content_hash missing or not prefixed — regenerate .darp", file=sys.stderr)
        return 1

    content_hash_hex = content_hash_str.split(":")[1]
    digest_bytes = bytes.fromhex(content_hash_hex)
    now          = datetime.now(timezone.utc).isoformat(timespec="seconds")
    darp_name    = os.path.basename(darp_path)

    print(f"File:           {darp_name}")
    print(f"content_hash:   {content_hash_str}")
    print(f"At:             {now}")
    print()
    print("Submitting to OpenTimestamps calendars...")

    ots_proofs: list[dict[str, Any]] = []
    any_success = False

    for url in ots_calendars:
        try:
            ts        = RemoteCalendar(_calendar_base(url)).submit(digest_bytes, timeout=timeout_s)
            proof_b64 = base64.b64encode(_serialize_proof(ts)).decode()
            ots_proofs.append({"calendar": url, "status": "submitted", "proof_b64": proof_b64})
            any_success = True
            print(f"  [✓] {url}")
        except Exception as e:
            ots_proofs.append({"calendar": url, "status": "failed"})
            print(f"  [✗] {url}  ({e})", file=sys.stderr)

    if not any_success:
        print("\nERROR: All calendar servers failed. Check network and retry.", file=sys.stderr)
        return 1

    timestamp = {
        "status":       "pending",
        "stamped_at":   now,
        "block_height": None,
        "ots_proofs":   ots_proofs,
    }

    darp["metadata"]["timestamp"] = timestamp

    with open(darp_path, "w", encoding="utf-8") as f:
        json.dump(darp, f, indent=2)
        f.write("\n")

    # Write sha256 file for CLI compat
    sha256_out = darp_path + ".ots.sha256"
    with open(sha256_out, "w", encoding="utf-8") as f:
        f.write(content_hash_hex + "\n")

    print(f"\nUpdated: {darp_path}")
    print(f"Saved:   {sha256_out}")
    print()
    print("Status: PENDING — Bitcoin confirmation takes ~1-2 hours.")
    print(f"  python3 darp.py upgrade {darp_path}")
    return 0


def _dump_proof_trees(darp: dict[str, Any]) -> None:
    """Print each stored OTS proof as a commitment-op tree (like `ots info`)."""
    import importlib.util
    if importlib.util.find_spec("opentimestamps") is None:
        print("\n(opentimestamps not installed — cannot dump proof structure)")
        return
    meta = darp.get("metadata", {})
    content_hash_str = meta.get("content_hash", "")
    if not content_hash_str.startswith("sha256:"):
        return
    digest = bytes.fromhex(content_hash_str.split(":")[1])
    print(f"\nProof structure (content_hash {content_hash_str[7:23]}…):")
    for proof in meta.get("timestamp", {}).get("ots_proofs", []):
        if "proof_b64" not in proof:
            continue
        print(f"\n  {proof.get('calendar', '?')}:")
        try:
            ts = _deserialize_proof(base64.b64decode(proof["proof_b64"]), digest)
            for line in ts.str_tree().splitlines():
                print(f"    {line}")
        except Exception as e:
            print(f"    (cannot render: {e})")


def _cmd_status(darp_path: str, show_proof: bool = False) -> int:
    if not os.path.isfile(darp_path):
        print(f"No .darp file found: {darp_path}")
        print(f"Run: python3 darp.py stamp {darp_path}")
        return 1

    darp     = _json_load(darp_path)
    meta_blk = darp.get("metadata", {})
    data_blk = darp.get("data", {})
    defs_blk = darp.get("definitions", {})

    content_hash = meta_blk.get("content_hash", "—")
    timestamp    = meta_blk.get("timestamp")

    print(f"\nFile:         {os.path.basename(darp_path)}")
    print(f"Subject:      {defs_blk.get('subject', '?')}")
    print(f"Generated:    {data_blk.get('generated_at', '?')}")
    print(f"content_hash: {content_hash}")

    # Verify content_hash integrity
    computed = _compute_content_hash(darp)
    match    = computed == content_hash
    icon     = _icon("PASS" if match else "FAIL")
    msg      = "content_hash matches" if match else "MISMATCH — file may have been modified"
    print(f"  [{icon}] Integrity: {msg}")

    if timestamp:
        status   = timestamp.get("status", "?").upper()
        stamped  = timestamp.get("stamped_at", "—")
        height   = timestamp.get("block_height")
        print(f"\nTimestamp:    {status}")
        print(f"Stamped:      {stamped}")
        if height:
            print(f"Block:        {height}")
        verified = timestamp.get("verified")
        if verified is not None:
            via = timestamp.get("verified_via", "—")
            btime = timestamp.get("block_time", "—")
            print(f"Anchor:       {'VERIFIED' if verified else 'attested (unverified)'}"
                  + (f"  via {via}  @ {btime}" if verified else ""))
        print("\nCalendars:")
        for proof in timestamp.get("ots_proofs", []):
            icon  = _icon("PASS" if proof.get("status") in ("submitted", "confirmed") else "FAIL")
            extra = "  (proof_b64 present)" if "proof_b64" in proof else ""
            print(f"  [{icon}] {proof.get('calendar', '?')}{extra}")

        if show_proof:
            _dump_proof_trees(darp)
    else:
        print("\nNo timestamp yet — run: python3 darp.py stamp <file.darp>")

    orcid_id = defs_blk.get("orcid")
    repo     = meta_blk.get("repo")
    if orcid_id or repo:
        print(f"\nORCID:        https://orcid.org/{orcid_id}" if orcid_id else "\nORCID:        —")
        if repo:
            print(f"Repo:         {repo}")
            print("Authorship:   run `verify --verify-authorship` "
                  "(repo must be listed on your ORCID)")

    return 0


# OpenTimestamps upgrade runs entirely in-process via the opentimestamps
# library — no external `ots` binary — so the whole calendar/merge/parse path
# stays under our control. These helpers wrap the library's serialization and
# remote-calendar API.

def _deserialize_proof(proof_bytes: bytes, digest: bytes) -> Any:
    """Reconstruct a Timestamp from a stored calendar proof rooted at `digest`."""
    import io
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import Timestamp
    ctx = StreamDeserializationContext(io.BytesIO(proof_bytes))
    return Timestamp.deserialize(ctx, digest)


def _serialize_proof(ts: Any) -> bytes:
    """Serialize a (possibly upgraded) Timestamp back to bytes for storage."""
    from opentimestamps.core.serialize import BytesSerializationContext
    ctx = BytesSerializationContext()
    ts.serialize(ctx)
    return ctx.getbytes()


def _bitcoin_height(ts: Any) -> int | None:
    """Return the Bitcoin block height attested anywhere in the timestamp, or None."""
    atts = _bitcoin_attestations(ts)
    return atts[0][1] if atts else None


# ── Bitcoin anchor verification ───────────────────────────────────────────────
# The opentimestamps *library* parses a BitcoinBlockHeaderAttestation but does
# not verify it against the chain — that lives in the (unpackaged) client. So we
# verify it ourselves, mirroring nim-ots: fetch the block header at the attested
# height and check the attestation message equals the block's merkle root. Two
# backends — a Bitcoin Core JSON-RPC node (trustless) and an Esplora/blockstream
# REST explorer (fallback). A BitcoinBlockHeaderAttestation commits the merkle
# root in internal byte order; both backends return it reversed to that order.

_DEFAULT_EXPLORER = "https://blockstream.info/api"


def _bitcoin_attestations(ts: Any) -> list[tuple[bytes, int]]:
    """All (message, height) pairs carrying a Bitcoin block-header attestation."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    out: list[tuple[bytes, int]] = []
    for msg, att in ts.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            out.append((bytes(msg), int(att.height)))
    return out


def _btc_cookie_auth() -> tuple[str, str]:
    """Read Bitcoin Core's auto-generated RPC credentials from ~/.bitcoin/.cookie."""
    path = os.path.join(os.path.expanduser("~"), ".bitcoin", ".cookie")
    try:
        with open(path, encoding="utf-8") as fh:
            user, _, pw = fh.read().strip().partition(":")
            return user, pw
    except OSError:
        return "", ""


def _http_request(url: str, *, data: bytes | None = None,
                  headers: dict[str, str] | None = None, timeout: int = 15) -> str:
    req = urllib.request.Request(url, data=data, headers=headers or {},
                                 method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted URLs)
        return resp.read().decode()


def _btc_core_header(height: int, rpc_url: str, user: str, password: str,
                     timeout: int) -> tuple[bytes, int]:
    if not user and not password:
        user, password = _btc_cookie_auth()
    headers = {"Content-Type": "application/json"}
    if user or password:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"

    def _rpc(method: str, params: list[Any]) -> Any:
        payload = json.dumps({"jsonrpc": "1.0", "id": "darp",
                              "method": method, "params": params}).encode()
        body = json.loads(_http_request(rpc_url, data=payload, headers=headers,
                                        timeout=timeout))
        if body.get("error"):
            raise RuntimeError(f"RPC error: {body['error']}")
        return body["result"]

    block_hash = _rpc("getblockhash", [height])
    h          = _rpc("getblockheader", [block_hash, True])
    merkle     = bytes.fromhex(h["merkleroot"])[::-1]   # RPC display order → internal
    return merkle, int(h["time"])


def _btc_explorer_header(height: int, api_url: str,
                         timeout: int) -> tuple[bytes, int]:
    api        = api_url.rstrip("/")
    block_hash = _http_request(f"{api}/block-height/{height}", timeout=timeout).strip()
    h          = json.loads(_http_request(f"{api}/block/{block_hash}", timeout=timeout))
    merkle     = bytes.fromhex(h["merkle_root"])[::-1]  # display order → internal
    return merkle, int(h["timestamp"])


def _btc_block_header(height: int, opts: dict[str, Any],
                      timeout: int = 15) -> tuple[bytes, int, str]:
    """Fetch (merkle_root_internal, block_time, backend_label) for `height`.

    Backend chosen from `opts`; with none given, try a local Bitcoin Core node
    then fall back to a public block explorer (mirrors nim-ots `chooseBackend`).
    """
    explorer = opts.get("explorer_url")
    node     = opts.get("node_url")
    user     = opts.get("rpc_user", "")
    password = opts.get("rpc_password", "")

    if explorer:
        m, t = _btc_explorer_header(height, explorer, timeout)
        return m, t, f"explorer ({explorer})"
    if node or user or password:
        url  = node or "http://127.0.0.1:8332"
        m, t = _btc_core_header(height, url, user, password, timeout)
        return m, t, f"Bitcoin Core ({url})"
    try:
        m, t = _btc_core_header(height, "http://127.0.0.1:8332", "", "", timeout)
        return m, t, "Bitcoin Core (http://127.0.0.1:8332)"
    except Exception:
        m, t = _btc_explorer_header(height, _DEFAULT_EXPLORER, timeout)
        return m, t, f"explorer ({_DEFAULT_EXPLORER})"


def _verify_anchor(ts: Any, opts: dict[str, Any], timeout: int = 15) -> dict[str, Any]:
    """Independently check the timestamp's Bitcoin attestation against the chain.

    Returns a dict with "status" in {"verified","mismatch","error","none"} plus
    "height"/"time"/"via"/"message" where applicable.
    """
    atts = _bitcoin_attestations(ts)
    if not atts:
        return {"status": "none", "message": "no Bitcoin attestation in proof"}
    last_err = ""
    for msg, height in atts:
        try:
            merkle, btime, via = _btc_block_header(height, opts, timeout)
        except Exception as e:
            last_err = str(e)
            continue
        if msg == merkle:
            return {"status": "verified", "height": height, "time": btime, "via": via,
                    "message": f"merkle root matches Bitcoin block {height}"}
        return {"status": "mismatch", "height": height,
                "message": (f"MERKLE ROOT MISMATCH at block {height} — the proof does "
                            f"not commit to this block (possible tampering)")}
    return {"status": "error", "height": atts[0][1],
            "message": f"block lookup failed: {last_err}"}


def _parse_btc_opts(args: list[str]) -> dict[str, Any]:
    """Extract Bitcoin-backend flags shared by `upgrade` and `verify`."""
    def _val(flag: str) -> str | None:
        if flag in args:
            i = args.index(flag)
            return args[i + 1] if i + 1 < len(args) else None
        return None

    opts: dict[str, Any] = {}
    if (node := _val("--bitcoin-node")):  opts["node_url"]     = node
    if (user := _val("--rpc-user")):      opts["rpc_user"]     = user
    if (pw := _val("--rpc-password")):    opts["rpc_password"] = pw
    if (eurl := _val("--explorer-url")):
        opts["explorer_url"] = eurl
    elif "--explorer" in args:
        opts["explorer_url"] = _DEFAULT_EXPLORER
    return opts


def _iso_utc(unix_time: int) -> str:
    return datetime.fromtimestamp(unix_time, timezone.utc).isoformat(timespec="seconds")


def _upgrade_pending(ts: Any, timeout: int) -> None:
    """Query each pending calendar in-process and merge any returned commitments."""
    from opentimestamps.calendar import RemoteCalendar
    from opentimestamps.core.notary import PendingAttestation

    def _pending_nodes(node: Any) -> Any:
        for att in node.attestations:
            if isinstance(att, PendingAttestation):
                yield node, att.uri
        for sub in node.ops.values():
            yield from _pending_nodes(sub)

    for node, uri in list(_pending_nodes(ts)):
        try:
            upgraded = RemoteCalendar(uri).get_timestamp(node.msg, timeout=timeout)
            node.merge(upgraded)
        except Exception as e:  # not yet confirmed / network — leave pending
            print(f"  [pending] {uri}: {e}", file=sys.stderr)


def _cmd_upgrade(darp_path: str, btc_opts: dict[str, Any] | None = None) -> int:
    btc_opts = btc_opts or {}
    if not os.path.isfile(darp_path):
        print(f"ERROR: {darp_path} not found", file=sys.stderr)
        return 1

    # Upgrade is an ots operation: require the opentimestamps library (it does the
    # calendar query, merge, and Bitcoin-attestation parse in-process — no binary).
    import importlib.util
    if importlib.util.find_spec("opentimestamps") is None:
        print("ERROR: upgrade requires the opentimestamps Python library.\n"
              "  Debian/Ubuntu:  sudo apt-get install python3-opentimestamps\n"
              "  pip:            pip install opentimestamps", file=sys.stderr)
        return 1

    _ini      = _load_ini(_DEFAULT_INI)
    timeout_s = int(_ini.get("anchor", "timeout_s", fallback="15"))

    darp = _json_load(darp_path)
    meta_blk  = darp.get("metadata", {})
    timestamp = meta_blk.get("timestamp")

    if not timestamp:
        print("No timestamp found in .darp — run stamp first.", file=sys.stderr)
        return 1
    if timestamp.get("status") == "confirmed":
        print("Already confirmed.", file=sys.stderr)
        return 0

    content_hash_str = meta_blk.get("content_hash", "")
    if not content_hash_str.startswith("sha256:"):
        print("ERROR: metadata.content_hash missing or not prefixed — regenerate .darp", file=sys.stderr)
        return 1
    digest = bytes.fromhex(content_hash_str.split(":")[1])

    any_confirmed = False
    any_verified  = False
    block_height: int | None = None
    block_time: int | None    = None
    verified_via: str | None  = None

    for proof in timestamp.get("ots_proofs", []):
        if proof.get("status") != "submitted" or "proof_b64" not in proof:
            continue
        calendar = proof.get("calendar", "?")
        try:
            ts = _deserialize_proof(base64.b64decode(proof["proof_b64"]), digest)
        except Exception as e:
            print(f"  [skip] {calendar}: cannot parse stored proof ({e})", file=sys.stderr)
            continue

        _upgrade_pending(ts, timeout_s)

        # "confirmed" must mean Bitcoin-attested: only accept the upgrade when a
        # block-height attestation is present. We then independently verify it
        # against the chain — a merkle-root MISMATCH is a hard failure (the proof
        # does not commit to that block); a network error still records the
        # attestation but flags it as not independently verified.
        result = _verify_anchor(ts, btc_opts, timeout_s)
        st     = result["status"]
        if st == "none":
            print(f"  [·] {calendar}  not anchored yet")
            continue
        if st == "mismatch":
            print(f"  [✗] {calendar}  {result['message']}", file=sys.stderr)
            return 1

        height = int(result["height"])
        proof["proof_b64"] = base64.b64encode(_serialize_proof(ts)).decode()
        proof["status"]    = "confirmed"
        any_confirmed      = True
        if block_height is None:
            block_height = height
        if st == "verified":
            any_verified = True
            block_time   = int(result["time"])
            verified_via = str(result["via"])
            print(f"  [✓] {calendar}  Bitcoin block {height} — verified via {result['via']}")
        else:  # error: attested but not independently checked
            print(f"  [✓] {calendar}  Bitcoin block {height} — attested, NOT verified "
                  f"({result['message']})", file=sys.stderr)

    if any_confirmed:
        timestamp["status"]       = "confirmed"
        timestamp["upgraded_at"]  = datetime.now(timezone.utc).isoformat(timespec="seconds")
        timestamp["block_height"] = block_height
        timestamp["verified"]     = any_verified
        if block_time is not None:
            timestamp["block_time"]  = _iso_utc(block_time)
        if verified_via is not None:
            timestamp["verified_via"] = verified_via
        with open(darp_path, "w", encoding="utf-8") as f:
            json.dump(darp, f, indent=2)
            f.write("\n")
        print(f"Updated: {darp_path}")
        print(f"Bitcoin block: {block_height}"
              + (f"  ({_iso_utc(block_time)}, verified via {verified_via})"
                 if any_verified and block_time is not None else "  (not independently verified)"))
        return 0
    else:
        print("No proofs confirmed yet — the timestamp is not anchored in a Bitcoin\n"
              "block yet. Retry later (~1-2 hours after stamping).", file=sys.stderr)
        return 1


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

_SUBCOMMANDS = {"analyze", "verify", "stamp", "status", "upgrade", "cite"}


def _main_analyze(args: list[str]) -> int:
    if not args or args[0].startswith("-"):
        print("Usage: python3 darp.py analyze <file.darp> [flags]")
        return 2

    darp_path = args[0]
    ini_path  = _DEFAULT_INI
    quiet     = "--quiet" in args
    out_path  = None
    baseline_override_commit = None

    def _flag(name: str) -> str | None:
        if name in args:
            idx = args.index(name)
            return args[idx + 1] if idx + 1 < len(args) else None
        return None

    _bl_ini   = _flag("--baseline-ini")
    _bl_out   = _flag("--out")
    _bl_com   = _flag("--baseline-commit")
    _bl_darp  = _flag("--baseline-darp")
    _bl_vals  = _flag("--baseline-values")

    if _bl_ini:  ini_path                 = _bl_ini
    if _bl_out:  out_path                 = _bl_out
    if _bl_com:  baseline_override_commit = _bl_com

    try:
        darp: Any = _json_load(darp_path)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read {darp_path}: {e}")
        return 2

    baseline_source = "embedded"
    baseline_commit = None

    if _bl_darp:
        baselines       = _load_darp_baseline(_bl_darp)
        baseline_source = f"darp:{os.path.basename(_bl_darp)}"
    elif _bl_vals:
        baselines       = _parse_inline_baseline(_bl_vals)
        baseline_source = "inline"
    else:
        # Use ini [values] if the section exists; otherwise fall back to values
        # embedded in the .darp at generation time — so analyze works without the ini.
        _bl_cfg = configparser.ConfigParser()
        _bl_cfg.read(ini_path)
        if _bl_cfg.has_section("values"):
            baselines, baseline_commit = _load_ini_baseline(ini_path)
            baseline_source = f"ini:{os.path.basename(ini_path)}"
        else:
            _params = (darp.get("definitions", {})
                          .get("algorithm", {})
                          .get("parameters", {}))
            baselines       = {k: float(v) for k, v in _params.get("baseline_values", {}).items()}
            baseline_commit = _params.get("baseline_commit")
            baseline_source = "embedded"

    if baseline_override_commit:
        baseline_commit = baseline_override_commit

    if not baselines:
        print(f"ERROR: no baseline values found — add [values] to {ini_path} "
              f"or regenerate the .darp with a current ini that has [values]")
        return 2

    # Thresholds: .darp embedded values are the base; ini [thresholds] overrides if present.
    _thresh_cfg = configparser.ConfigParser()
    _thresh_cfg.read(ini_path)
    if _thresh_cfg.has_section("thresholds"):
        thresholds = _load_thresholds(ini_path)
    else:
        _embedded = (darp.get("definitions", {})
                        .get("algorithm", {})
                        .get("parameters", {})
                        .get("thresholds", {}))
        thresholds = {
            "noise_band": float(_embedded.get("noise_band", 10.0)),
            "warn_band":  float(_embedded.get("warn_band",  20.0)),
            "div_max":    float(_embedded.get("divergence",  20.0)),
        }
    result = analyze(darp, baselines, thresholds, baseline_commit, baseline_source)

    if out_path:
        if os.path.isdir(out_path):
            date_str     = datetime.now(timezone.utc).strftime("%Y%m%d")
            commit_short = (baseline_commit or "")[:8]
            suffix       = f"-{commit_short}" if commit_short else ""
            subj         = (result.get("subject") or "darp").replace(" ", "-")
            out_path     = os.path.join(out_path, f"{date_str}-{subj}{suffix}.analysis.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
            f.write("\n")
        print(f"Written: {out_path}")
    else:
        _print_analysis(result, quiet)

    return 0 if result["overall"] == "PASS" else 1


def _verify_darp_anchor(darp: dict[str, Any], btc_opts: dict[str, Any]) -> int:
    """Re-verify a stored .darp's Bitcoin anchor against the chain (opt-in)."""
    print("\n── Level 6: Bitcoin anchor ──")
    meta   = darp.get("metadata", {})
    ts_blk = meta.get("timestamp")
    if not ts_blk:
        print("  [—] no timestamp — run stamp/upgrade first")
        return 0

    import importlib.util
    if importlib.util.find_spec("opentimestamps") is None:
        print("  [—] opentimestamps not installed; cannot verify anchor")
        return 0

    content_hash_str = meta.get("content_hash", "")
    if not content_hash_str.startswith("sha256:"):
        print("  [✗] content_hash missing or not prefixed")
        return 1
    digest = bytes.fromhex(content_hash_str.split(":")[1])

    found = False
    rc    = 0
    for proof in ts_blk.get("ots_proofs", []):
        if "proof_b64" not in proof:
            continue
        cal = proof.get("calendar", "?")
        try:
            ts = _deserialize_proof(base64.b64decode(proof["proof_b64"]), digest)
        except Exception as e:
            print(f"  [✗] {cal}: cannot parse stored proof ({e})")
            rc = 1
            continue
        res = _verify_anchor(ts, btc_opts)
        if res["status"] == "none":
            continue
        found = True
        if res["status"] == "verified":
            print(f"  [✓] {cal}: {res['message']} (via {res['via']}, {_iso_utc(int(res['time']))})")
        else:  # mismatch | error
            print(f"  [✗] {cal}: {res['message']}")
            rc = 1
    if not found and rc == 0:
        print("  [—] no Bitcoin attestation yet — run upgrade")
    return rc


def _verify_darp_authorship(darp: dict[str, Any], api_base: str = _ORCID_PUB_API,
                            timeout: int = 15) -> int:
    """Level 7: one public ORCID read validates the iD, author name, and repo.

    Opt-in. Confirms definitions.repo is a researcher-url the claimed ORCID record
    lists — only the owner can add it, only the owner can push to the repo.
    """
    print("\n── Level 7: ORCID-anchored authorship ──")
    res = _verify_ledger_authorship(darp, api_base, timeout)
    st  = res["status"]
    if st == "none":
        print(f"  [—] {res['message']}")
        return 0
    if st == "verified":
        print(f"  [✓] ORCID {res['orcid']} resolves to {res['name'] or '?'}")
        if res.get("account"):
            print(f"  [✓] that ORCID lists account {res['account']}, which owns "
                  f"{res['repo']} (account match)")
        else:
            print(f"  [✓] that ORCID lists {res['repo']} (exact URL match)")
        return 0
    print(f"  [✗] {res['message']}")          # invalid | absent | mismatch | error
    return 1


def _main_verify(args: list[str]) -> int:
    if not args or args[0].startswith("-"):
        print("Usage: python3 darp.py verify <file.darp> [--traces DIR] [--schema FILE]\n"
              "       [--verify-anchor [--bitcoin-node URL | --explorer | --explorer-url URL]]\n"
              "       [--verify-authorship] [--quiet]")
        return 2

    darp_path   = args[0]
    traces_dir  = None
    schema_path = _find_schema(None)
    quiet       = "--quiet" in args

    # Init capture globals from the .darp's embedded parameters if available,
    # so level 4 trace replay works without the ini on a different machine.
    try:
        _darp_pre = _json_load(darp_path)
        _capture  = (_darp_pre.get("definitions", {})
                               .get("algorithm", {})
                               .get("parameters", {})
                               .get("capture"))
        if _capture:
            _init_capture_config_from_dict(_capture)
        else:
            _init_capture_config(_load_ini(_DEFAULT_INI))
    except (OSError, json.JSONDecodeError):
        _init_capture_config(_load_ini(_DEFAULT_INI))

    for flag in ("--traces", "--schema"):
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                val = args[idx + 1]
                if flag == "--traces": traces_dir  = val
                else:                  schema_path = val

    rc = _run_verify(darp_path, traces_dir, schema_path, quiet)

    if "--verify-anchor" in args:
        try:
            rc = _verify_darp_anchor(_json_load(darp_path), _parse_btc_opts(args)) or rc
        except (OSError, json.JSONDecodeError) as e:
            print(f"  [✗] anchor: cannot read {darp_path}: {e}")
            rc = rc or 1

    if "--verify-authorship" in args:
        try:
            _ini      = _load_ini(_DEFAULT_INI)
            api_base  = _ini.get("anchor", "orcid_api", fallback=_ORCID_PUB_API).strip() or _ORCID_PUB_API
            a_timeout = _load_anchor_timeout(_ini)
            rc = _verify_darp_authorship(_json_load(darp_path), api_base, a_timeout) or rc
        except (OSError, json.JSONDecodeError) as e:
            print(f"  [✗] authorship: cannot read {darp_path}: {e}")
            rc = rc or 1

    return rc


def _main_generate(args: list[str]) -> None:
    ini_path = _DEFAULT_INI
    if "--config" in args:
        idx = args.index("--config")
        if idx + 1 < len(args):
            ini_path = args[idx + 1]

    ini     = _load_ini(ini_path)
    ini_dir = os.path.dirname(os.path.abspath(ini_path))

    _init_capture_config(ini)

    def _ini(section: str, key: str, fallback: str) -> str:
        return ini.get(section, key, fallback=fallback).strip()

    trace_dir_raw   = _ini("paths",   "trace_dir", "../state")
    out_dir_raw     = _ini("paths",   "out_dir",   "reports")
    subject         = _ini("subject", "name",      "hint-followthrough")
    session_metric  =     _ini("algorithm", "session_metric", "first_lookup")
    min_sessions    = int(_ini("algorithm", "min_sessions",   "5"))
    thresholds      = _load_thresholds(ini_path)
    definitions     = _load_definitions(ini)
    algo_map        = _load_algo_map(ini)
    source_map      = _load_source_map(ini)

    _sm_alias     = definitions.get(session_metric, {}).get("algorithm", "")
    _sm_primitive = _resolve_algo(_sm_alias, algo_map)
    if session_metric not in definitions or not _PRIMITIVES.get(_sm_primitive, {}).get("is_session_level"):
        print(
            f"ERROR: [algorithm] session_metric = {session_metric!r} must name a "
            f"[definition.X] whose algorithm resolves to a session-level primitive\n"
            f"       found algorithm: {_sm_alias!r}  (resolves to: {_sm_primitive!r})",
            file=sys.stderr,
        )
        sys.exit(1)
    project_name = _ini("project", "name",    "") or None
    license_     = _ini("project", "license", "") or None

    # orcid: plain claimed iD.  repo: this paper's repo (full host/owner/repo URL),
    # written into definitions.repo. Authorship is confirmed by
    # `verify --verify-authorship`: the account owning `repo` must equal the github
    # account the iD's ORCID points to.  links: free-form [links] provenance URLs.
    # citation: CFF object from the [citation] section.
    orcid    = _ini("project", "orcid", "") or None
    repo     = _ini("project", "repo",  "") or None
    links    = _load_links(ini_path)
    citation = _load_citation(ini, orcid)

    project = project_name or None

    trace_dir = _resolve(trace_dir_raw, ini_dir)
    out_dir   = _resolve(out_dir_raw,   ini_dir)

    _ini_stream    = _ini("output", "stream",         "true").lower()
    include_stream = _ini_stream not in ("false", "0", "no")
    format_version = _ini("output", "format_version", _DARP_FORMAT_VERSION)
    if "--no-stream" in args: include_stream = False
    elif "--stream" in args:  include_stream = True

    snapshot_label  = ""
    from_darp_path  = None
    session_slice: tuple[int | None, int | None] | None = None

    for flag in ("--out", "--trace-dir", "--subject", "--snapshot", "--from-darp", "--sessions", "--repo"):
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                val = args[idx + 1]
                if val.startswith("--"):
                    print(f"ERROR: {flag} requires a value, got another flag: {val!r}", file=sys.stderr)
                    sys.exit(1)
                if flag == "--out":          out_dir        = val
                elif flag == "--trace-dir":  trace_dir      = val
                elif flag == "--subject":    subject        = val
                elif flag == "--snapshot":   snapshot_label = val
                elif flag == "--from-darp":  from_darp_path = val
                elif flag == "--sessions":   session_slice  = _parse_slice(val)
                elif flag == "--repo":       repo           = val

    os.makedirs(out_dir, exist_ok=True)
    source_darp_hash    = None
    source_type         = "files"
    source_description  = ""

    if from_darp_path:
        try:
            source_darp = _json_load(from_darp_path)
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read {from_darp_path}: {e}", file=sys.stderr)
            sys.exit(1)
        if not source_darp.get("data", {}).get("data_commitment", {}).get("reproducibility", {}).get("included"):
            print("ERROR: source .darp has no embedded event stream (was it generated with --no-stream?)", file=sys.stderr)
            sys.exit(1)
        embedded_events    = source_darp["data"]["data_commitment"]["reproducibility"]["events"]
        source_type        = "replay"
        source_description = os.path.basename(from_darp_path)
        with open(from_darp_path, "rb") as _fh:
            source_darp_hash = _sha256(_fh.read())
        slice_label = f"sessions {session_slice[0] or 0}:{session_slice[1] or ''}" if session_slice else "all sessions"
        print(f"Config:    {ini_path}", file=sys.stderr)
        print(f"Source:    {from_darp_path} ({len(embedded_events)} events, {slice_label})", file=sys.stderr)
        print(f"Output:    {out_dir}", file=sys.stderr)
        data = compute_anon(embedded_events, definitions,
                            session_slice=session_slice, include_stream=include_stream,
                            session_metric=session_metric, algo_map=algo_map)
    else:
        trace_files = sorted(glob.glob(os.path.join(trace_dir, _CAPTURE.trace_pattern)))
        if session_slice is not None:
            start, stop = session_slice
            trace_files = trace_files[start:stop]
        if not trace_files:
            print(f"No {_CAPTURE.trace_pattern} files found in: {trace_dir}", file=sys.stderr)
            sys.exit(1)
        source_description = f"{_CAPTURE.trace_pattern} ({len(trace_files)} files) in {trace_dir}"
        print(f"Config:    {ini_path}", file=sys.stderr)
        print(f"Traces:    {trace_dir} ({len(trace_files)} files)", file=sys.stderr)
        print(f"Output:    {out_dir}", file=sys.stderr)
        data = compute(trace_files, definitions, include_stream=include_stream,
                       session_metric=session_metric, algo_map=algo_map, source_map=source_map)

    baseline_values, baseline_commit = _load_ini_baseline(ini_path)
    ots_calendars                    = _load_anchor_config(ini)

    cfg = {
        "subject":             subject,
        "project":             project,
        "orcid":               orcid,
        "repo":                repo,
        "links":               links,
        "citation":            citation,
        "license":             license_,
        "include_stream":      include_stream,
        "format_version":      format_version,
        "source_type":         source_type,
        "source_description":  source_description,
        "source_darp_hash":    source_darp_hash,
        "definitions":         definitions,
        "session_metric":      session_metric,
        "min_sessions":        min_sessions,
        "algo_map":            algo_map,
        "source_map":          source_map,
        "thresholds":          thresholds,
        "baseline_commit":     baseline_commit,
        "baseline_values":     baseline_values,
        "anchor": {
            "calendars":       ots_calendars,
        },
    }

    darp = build_darp(data, cfg)

    if not snapshot_label:
        _commit = ini.get("baseline", "commit", fallback="").strip()
        if _commit:
            snapshot_label = _commit[:8]

    date_str  = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix    = f"-{snapshot_label}" if snapshot_label else ""
    out_path  = os.path.join(out_dir, f"{date_str}-{subject}{suffix}.darp")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(darp, f, indent=2)
        f.write("\n")

    _defs = darp["definitions"]
    _data = darp["data"]
    print(f"Generated: {out_path}\n", file=sys.stderr)
    print(f"DARP: {_defs['subject']} @ {_data['generated_at']}")
    print(f"Sessions: {data['session_count']} (smoke excluded: {data['smoke_excluded']})")
    src_hash = data["source_hash"]
    print(f"Source hash: {src_hash[:16]}..." if src_hash else "Source hash: (embedded-stream replay)")
    print("\nMetrics:")
    for m in _data["metrics"]:
        val = m.get("value")
        print(f"  {m['name']:<20} {'—' if val is None else val:>6}%")
    print("\nConsistency checks:")
    for c in darp["metadata"]["consistency_checks"]:
        icon = _icon(c["status"])
        print(f"  [{icon}] {c['check']} / {c['metric']}: {c['detail']}")
    print(f"\nOutput: {out_path}")


# ── Citation (read the embedded CFF block back out) ───────────────────────────

def _cff_year(cit: dict[str, Any]) -> str:
    """Four-digit year from CFF date-released, else 'n.d.'."""
    d = str(cit.get("date-released") or "")
    return d[:4] if d[:4].isdigit() else "n.d."


def _cff_authors(cit: dict[str, Any]) -> list[dict[str, Any]]:
    a = cit.get("authors")
    return a if isinstance(a, list) else []


def _apa_name(a: dict[str, Any]) -> str:
    """'Pereira, L. F.' from CFF given/family names."""
    fam = str(a.get("family-names", "")).strip()
    giv = str(a.get("given-names", "")).strip()
    initials = " ".join(f"{p[0]}." for p in giv.split())
    return f"{fam}, {initials}".strip().rstrip(",") if fam else giv


def _render_cff(cit: dict[str, Any]) -> str:
    """Emit the CFF object as YAML (the native Citation File Format)."""
    lines: list[str] = []
    for k in ("cff-version", "message", "title", "type", "version",
              "doi", "url", "date-released"):
        if cit.get(k):
            lines.append(f"{k}: {cit[k]}")
    if _cff_authors(cit):
        lines.append("authors:")
        for a in _cff_authors(cit):
            first = True
            for ak in ("family-names", "given-names", "orcid"):
                if a.get(ak):
                    lines.append(f"{'  - ' if first else '    '}{ak}: {a[ak]}")
                    first = False
    return "\n".join(lines)


def _render_bibtex(cit: dict[str, Any]) -> str:
    authors = " and ".join(
        f"{a.get('family-names', '')}, {a.get('given-names', '')}".strip(", ")
        for a in _cff_authors(cit)) or "Anonymous"
    year   = _cff_year(cit)
    fam    = _cff_authors(cit)[0].get("family-names", "") if _cff_authors(cit) else ""
    key    = (str(fam).lower().split() or ["darp"])[0] + (year if year != "n.d." else "")
    entry  = "software" if (cit.get("type") or "software") == "software" else "misc"
    fields = [("author", authors), ("title", cit.get("title")), ("year", year),
              ("version", cit.get("version")), ("doi", cit.get("doi")),
              ("url", cit.get("url"))]
    body = "".join(f"  {k} = {{{v}}},\n" for k, v in fields if v)
    return f"@{entry}{{{key},\n{body}}}"


def _render_apa(cit: dict[str, Any]) -> str:
    names = "; ".join(_apa_name(a) for a in _cff_authors(cit)) or "Anonymous"
    typ   = str(cit.get("type") or "software").capitalize()
    tail  = f" (Version {cit['version']})" if cit.get("version") else ""
    src   = f"https://doi.org/{cit['doi']}" if cit.get("doi") else (cit.get("url") or "")
    return f"{names} ({_cff_year(cit)}). {cit.get('title', 'Untitled')}{tail} [{typ}]. {src}".strip()


def _cmd_cite(path: str, fmt: str = "cff") -> int:
    """Print the embedded citation in CFF (default), BibTeX, or APA form."""
    try:
        darp = _json_load(path)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read {path}: {e}", file=sys.stderr)
        return 1
    cit = darp.get("definitions", {}).get("citation")
    if not cit:
        print("No citation in this .darp (add a [citation] section and regenerate).",
              file=sys.stderr)
        return 1
    renderers = {"cff": _render_cff, "bibtex": _render_bibtex, "apa": _render_apa}
    if fmt not in renderers:
        print(f"ERROR: unknown --format {fmt!r} (use cff|bibtex|apa)", file=sys.stderr)
        return 2
    print(renderers[fmt](cit))
    return 0


def main() -> None:
    args = sys.argv[1:]

    if not args:
        _main_generate(args)
        return

    cmd = args[0]

    if cmd in ("-h", "--help"):
        print(__doc__)
        return

    if cmd not in _SUBCOMMANDS:
        _main_generate(args)
        return

    rest = args[1:]

    if cmd == "analyze":
        sys.exit(_main_analyze(rest))

    elif cmd == "verify":
        sys.exit(_main_verify(rest))

    elif cmd == "stamp":
        if not rest:
            print("Usage: python3 darp.py stamp <file.darp>", file=sys.stderr)
            sys.exit(2)
        sys.exit(_cmd_stamp(rest[0]))

    elif cmd == "status":
        if not rest:
            print("Usage: python3 darp.py status <file.darp> [--proof]", file=sys.stderr)
            sys.exit(2)
        sys.exit(_cmd_status(rest[0], show_proof="--proof" in rest))

    elif cmd == "cite":
        if not rest:
            print("Usage: python3 darp.py cite <file.darp> [--format cff|bibtex|apa]",
                  file=sys.stderr)
            sys.exit(2)
        _fmt = "cff"
        if "--format" in rest:
            _i = rest.index("--format")
            if _i + 1 < len(rest):
                _fmt = rest[_i + 1]
        sys.exit(_cmd_cite(rest[0], _fmt))

    elif cmd == "upgrade":
        if not rest:
            print("Usage: python3 darp.py upgrade <file.darp>\n"
                  "       [--bitcoin-node URL [--rpc-user U] [--rpc-password P] | "
                  "--explorer | --explorer-url URL]", file=sys.stderr)
            sys.exit(2)
        sys.exit(_cmd_upgrade(rest[0], _parse_btc_opts(rest)))


if __name__ == "__main__":
    main()
