<!--
Copyright (C) 2026 Luciano Federico Pereira
Licensed under version 2.1 of the GNU Lesser General Public License.
-->

<p align="center">
  <img src="assets/logo.png" alt="DARP logo" width="420">
</p>

# DARP — Diff-Anchored Reporting Proof

A self-contained toolkit for producing **verifiable, tamper-evident behavioral measurement artifacts** from agent telemetry trace files. A `.darp` file is an immutable structural record you can submit to a peer reviewer, anchor to the Bitcoin blockchain, and bind to your federated ORCID identity—all via **unauthenticated public reads**—with cryptographic proof that the data has remained invariant across its entire lifecycle. 

While DARP can be used to standardize automated audit logs for open-source repositories, its primary value proposition lies in **closed, secure, or proprietary systems**. It allows developers and researchers to publish completely verifiable empirical claims without exposing sensitive intellectual property, proprietary codebases, or private user telemetry.

The core problem DARP solves: an isolated, scalar metric percentage reported from a live deployment is fundamentally *ungateable*—its representation lacks any internal record of how it was generated, or whether the underlying trace payload has been manipulated post-hoc. DARP renders a behavioral claim gateable: the recipient independently re-derives every reported metric from an embedded, de-identified event stream and validates it against a committed cryptographic content hash, entirely eliminating the requirement to trust a self-attested report.

---

## Why DARP Exists

Empirical agent measurement introduces severe structural vulnerabilities that standard logging infrastructures and traditional pre-registration protocols fail to prevent. DARP is architected to systematically intercept these failure modes (covered in full within [PAPER.md](PAPER.md)):

* **1 — Unanchored Followthrough (Counterfactual Failure):** A bare followthrough rate—measuring sessions that executed a hint relative to the total sessions exposed to one—cannot distinguish whether the hint actively redirected the agent or if the agent would have independently pursued that trajectory. Both causal pathways yield an identical numerator. A high followthrough rate equivalent to an unhinted baseline is merely a statistical artifact; it is the base rate masquerading as an effect. DARP resolves this by enforcing a *suppressed experimental arm*: a matched cohort of control sessions where the hint triggers within the trace telemetry but the text is strictly withheld from the agent runtime. **A metric stripped of its counterfactual is an observation, not a finding.** DARP commits these operational baselines ex-ante and enforces multi-view metrics to expose hidden event-clustering noise.
* **2 — Auditor = Subject (Systemic Reflexivity):** Within active agent deployments, the analytical software running the data analysis often shares a homogenous architecture or codebase with the subjects under evaluation. Auditing the experiment therefore constitutes an intervention on the measured population, risking state leakage, shared-directory contamination, and altered agent trajectories. **DARP strictly decouples capture from analysis:** the telemetry capture layer is Universally operable across all sessions, but the final analytical execution runs isolated outside the measured environment, ensuring an agent never serves as its own auditor.
* **3 — Instrument-Equivalence (Telemetry Drift):** Because agent software environments are under continuous, often AI-assisted modification, a prompted code change can refactor a telemetry hook or alter log schemas between baseline collection and treatment periods. When this occurs, a before-after comparison estimates instrumental variance rather than true behavioral modification—doing so silently without triggering runtime errors. DARP forces all analytical metrics to be declared as static, declarative data configurations rather than imperative code scripts, ensuring that instrument adjustments are instantly surfaced by the reference monitor.

---

## Contents

- [PAPER.md](PAPER.md) — the paper: verifiable measurement for closed production systems, the three failure modes, and the verification design
- [CITING.md](CITING.md) — how to cite a DARP artifact in your paper and how reviewers verify it
- [Why DARP exists](#why-darp-exists)
- [Concept](#concept)
- [Repository files](#repository-files)
- [Requirements](#requirements)
- [Trace file format](#trace-file-format)
- [Wiring other trace formats](#wiring-other-trace-formats----source)
- [Quick start](#quick-start)
- [File format](#file-format)
- [Verify levels](#verify-levels)
- [Four computation primitives](#four-computation-primitives)
- [Configuration reference](#configuration-reference)
- [Adapting to a new project](#adapting-to-a-new-project)
- [Anchor workflow](#anchor-workflow)
- [Command reference](#command-reference)

---

## Concept

```
Trace files  ──► CAPTURE ──► .darp  ──► VERIFY   (schema + arithmetic + hash)
                                    ──► ANALYZE  (delta vs baseline)
                                    ──► STAMP    (Bitcoin timestamp via OTS)
                                    ──► PUBLISH  (in your repo; ORCID lists the repo)
```

A `.darp` file has **three immutable blocks**:

| Block | Contents | Mutable after generation? |
|---|---|---|
| `definitions` | subject, claimed ORCID iD, `repo`, algorithm config, metric declarations | no |
| `data` | health, metrics, trend, data commitment, optional event stream | no |
| `metadata` | content\_hash, consistency checks, generator provenance | append-only (stamp adds `timestamp`) |

`content_hash = SHA256(canonical {definitions, data})` is what OpenTimestamps commits to. Because only `metadata` grows after generation, `content_hash` stays stable through the full stamp → upgrade workflow. Authorship is not a login: `definitions.orcid` and `definitions.repo` are both hashed, so the full claim is tamper-evident; `verify --verify-authorship` confirms the repo's owner is an account on that ORCID record (see [CITING.md](CITING.md)).

---

## Repository files

| File | Description |
|---|---|
| [`darp.py`](darp.py) | The entire tool — CLI, metric engine, pandas accessor, verifier, and OTS anchoring — in one auditable script. |
| [`darp.ini`](darp.ini) | This repository's live configuration; generates the self-proof artifact below. |
| [`darp.example.ini`](darp.example.ini) | Clean template with placeholder identity — copy to `darp.ini` and edit for your project. |
| [`darp.schema.json`](darp.schema.json) | JSON Schema for the `.darp` format; drives verify Level 1 (strict when `jsonschema` is installed). |
| `*.darp` (reports) | DARP's own **self-proof**: the project measured with its own method. Built from `sample_traces/`, verified by CI on every push. |
| [`sample_traces/`](sample_traces) | The source trace files the self-proof is built from. Including them lets anyone re-derive and validate it (verify Levels 4–5). |
| [`test_darp.py`](test_darp.py) | unittest regression suite for the metric engine, verifier, and authorship checks. |
| [`mypy.ini`](mypy.ini) | Type-check configuration (`mypy darp.py` passes clean). |
| [`.github/workflows/verify.yml`](.github/workflows/verify.yml) | CI that locates the root `*.darp` and verifies it (Levels 1–5, plus authorship informationally). |
| [`PAPER.md`](PAPER.md) | Design rationale, failure modes, and the login-free authorship/timestamp chain. |
| [`CITING.md`](CITING.md) | How to cite a DARP artifact in a paper and how a reviewer verifies it. |

---

## Trace file format

DARP reads **JSONL files** — one JSON object per line, one file per agent session. The filename pattern is configurable (`trace_pattern` in `[capture]`, default `hint_trace_*.jsonl`).

```
state/
  hint_trace_session-abc123.jsonl   # one session
  hint_trace_session-def456.jsonl   # another session
  hint_trace_smoke-test.jsonl       # excluded (smoke_prefix match)
```

The **session ID** is the `*` portion of the filename. Sessions whose ID starts with `smoke_prefix` (default `smoke`) are parsed but excluded from all metrics — useful for integration tests.

### Two event types

Every line in a trace file is either a `hint` event or a `action` event. All other event types are silently ignored.

#### `hint` — a behavioral hint was fired

```jsonc
{
  "event":     "hint",
  "ts":        1748649600.123,      // Unix timestamp (float). First event ts = session zero.
  "source":    "read_gate",         // Must match trigger_source in a [definition.*] section.
  "synthetic": false,               // true → excluded from metrics (used for injected test hints).
  "try_next":  [                    // Suggested next actions. Used to extract API families
    "api.py file? 'packages/Foo'"   //   for the "followed" outcome in next/window primitives.
  ],
  "searched":  "Read packages/Foo/Bar.php"  // Optional: hinted path, used by echo_dedup.
}
```

Key fields:

| Field | Required | Description |
|---|---|---|
| `event` | yes | Must be `"hint"` |
| `ts` | yes | Unix timestamp. First event in the file sets the session origin. |
| `source` | yes | Matches `trigger_source` in a `[definition.*]` section. Drives metric dispatch. |
| `synthetic` | no | If `true`, excluded from all metrics. Default `false`. |
| `try_next` | no | List of invocation strings. Endpoint families extracted for "followed" detection. |
| *(any)* | no | Additional fields (e.g. `searched`) used by `echo_dedup_field` if configured. |

#### `action` — the agent called a tool

```jsonc
{
  "event":      "action",
  "ts":         1748649601.456,
  "tool":       "Read",
  "invocation": "Read 'packages/Foo/Bar.php'"
}
```

Key fields:

| Field | Required | Description |
|---|---|---|
| `event` | yes | Must be `"action"` |
| `ts` | yes | Unix timestamp. |
| `tool` | yes | Tool name (e.g. `Read`, `Glob`, `Grep`, `Bash`). Used for packages bypass detection. |
| `invocation` | yes | Full invocation string. Scanned for `api_command` and `packages_path`. |

### How DARP reads invocations

DARP identifies two special invocation patterns (both configurable in `[capture]`):

**API calls** — invocation contains `api_command` (default `api.py`):
```
api.py which 'Foo'          → is_api_call=true, api_family="which"
api.py grep? 'pattern'      → is_api_call=true, api_family="grep"
```
The endpoint family is the first word after `api_command`. This is what the `next` and `window` primitives track as "followed".

**Packages bypass** — `tool` is in `packages_tools` (default `Read,Glob,Grep`) AND invocation contains `packages_path` (default `packages/`):
```
tool=Read, invocation="Read 'packages/Foo/Bar.php'"  → packages bypass
```
A bypass before the first API call in a session increments `packages_skip_count` in `health{}`.

### Minimal valid trace file

```jsonl
{"event":"hint","ts":1748649600.0,"source":"read_gate","synthetic":false,"try_next":["api.py file? 'packages/Foo'"]}
{"event":"action","ts":1748649601.0,"tool":"Read","invocation":"Read 'packages/Foo/Bar.php'"}
{"event":"action","ts":1748649602.0,"tool":"Bash","invocation":"api.py file? 'packages/Foo'"}
```

### Session ordering

Within a file, events are processed in the order they appear. The `ts` of the first event becomes the session origin (`ts_zero`); all stored timestamps are offsets from it. Across files, sessions are sorted by filename.

### `echo_dedup`

When `echo_dedup = true` on a `window` definition, DARP removes the immediately-following `action` event if its `invocation` contains the path from the hint's `echo_dedup_field` (default `searched`). This prevents the agent's automatic echo of the hinted file from being counted as a followed action.

### Wiring other trace formats — `[source]`

Add a `[source]` section to `darp.ini` to map any external format's field names to DARP's internal model. Only set the keys that differ from the defaults. Dotted paths reach nested fields. `ts_scale` converts raw timestamps to Unix seconds.

#### OpenTelemetry OTLP JSON

Spans exported via otelcol. Tags under `attributes.*` (dict — dotted paths work).

```ini
[source]
event_field      = name
hint_value       = darp_hint        # set this as your hint span name
action_value     = darp_action      # set this as your tool span name
ts_field         = startTimeUnixNano
ts_scale         = 1e-9
source_field     = attributes.darp.source
synthetic_field  = attributes.darp.synthetic
try_next_field   = attributes.darp.try_next
tool_field       = attributes.tool.name
invocation_field = attributes.tool.input
```

#### Zipkin JSON

`timestamp` is microseconds; `tags` is a flat dict.

```ini
[source]
event_field      = name
hint_value       = darp_hint
action_value     = darp_action
ts_field         = timestamp
ts_scale         = 1e-6
source_field     = tags.darp_source
tool_field       = tags.tool_name
invocation_field = tags.tool_input
```

#### Datadog APM JSON

`start` is nanoseconds; `meta` is a flat string dict.

```ini
[source]
event_field      = resource
hint_value       = darp_hint
action_value     = darp_action
ts_field         = start
ts_scale         = 1e-9
source_field     = meta.darp_source
tool_field       = meta.tool_name
invocation_field = meta.invocation
```

#### AWS CloudWatch structured logs

`timestamp` is milliseconds; fields nested under `metadata.*`.

```ini
[source]
event_field      = eventType
hint_value       = darp_hint
action_value     = darp_action
ts_field         = timestamp
ts_scale         = 1e-3
source_field     = metadata.darp_source
tool_field       = metadata.tool_name
invocation_field = metadata.tool_input
```

#### Generic custom NDJSON

Full control — use whatever field names make sense in your application.

```ini
[source]
event_field      = type
hint_value       = darp_hint
action_value     = darp_action
ts_field         = time_ms
ts_scale         = 1e-3
source_field     = src
try_next_field   = next_cmds
tool_field       = tool
invocation_field = cmd
```

#### Jaeger JSON — limited

Jaeger `tags` is an array of `{key, value}` objects, not a dict. Dotted-path access does not work. Flatten tags to a dict in a preprocessing step, then treat as generic NDJSON.

#### LangSmith / LangFuse — limited

`start_time` is an ISO 8601 string, not a numeric timestamp. `ts_scale` cannot convert strings. Parse to Unix seconds in a preprocessing step first.

The `source_map` is embedded in the `.darp` file at generation time (`parameters.source_map`), so `verify --traces` and L5 replay work without the ini on any machine.

---

## Requirements

```bash
sudo apt-get install python3-pandas           # required
sudo apt-get install python3-jsonschema       # optional — enables full schema validation
sudo apt-get install python3-opentimestamps   # optional — required for the upgrade subcommand
```

Python 3.10+. No other dependencies.

**One file, easy to port.** The entire tool is a single script, `darp.py` — no
package to install, no build step. Drop it into any project and run it, or vendor
it wholesale; only pandas is required at runtime. Keeping everything in one file
is deliberate: it makes the tool trivial to audit, to pin by hash (the generator
records its own `script_hash` in every artifact), and to re-implement in another
language, since there is one place to read.

---

## Quick start

```bash
# 1. Generate a .darp from trace files
python3 darp.py

# 2. Verify it (schema + arithmetic + hash)
python3 darp.py verify reports/20260530-hint-followthrough-43b09055.darp

# 3. Compare against baseline values
python3 darp.py analyze reports/20260530-hint-followthrough-43b09055.darp

# 4. Timestamp on Bitcoin
python3 darp.py stamp reports/20260530-hint-followthrough-43b09055.darp

# 5. After ~1-2h, upgrade — anchors in a Bitcoin block and verifies its merkle root
python3 darp.py upgrade reports/20260530-hint-followthrough-43b09055.darp
#   trustless: verify against your own node instead of a public explorer
python3 darp.py upgrade <file.darp> --bitcoin-node http://127.0.0.1:8332 \
        --rpc-user U --rpc-password P

# 6. Publish report.darp in the repo your ORCID lists, then confirm authorship
#    (set [project] repo = https://<host>/<owner>/<repo> and add that same URL
#     as a researcher-url on your ORCID record — see CITING.md)
python3 darp.py verify  reports/20260530-hint-followthrough-43b09055.darp --verify-authorship

# Inspect / re-verify the anchor at any time
python3 darp.py status  <file.darp> --proof          # dump the OTS commitment tree
python3 darp.py verify  <file.darp> --verify-anchor   # re-check merkle root (Level 6)
```

The `content_hash` is canonicalized with [json-canon](https://github.com/lucianofedericopereira/json-canon)
(vendored, `SPEC.md` §2.3), so a `.darp` is reformatting-tolerant and equals
`ots canon -j --exclude /metadata <file>.darp` computed by
[nim-ots](https://github.com/lucianofedericopereira/nim-ots) — i.e. a `.darp` is
independently stampable and verifiable across implementations.

### As a pandas extension

Besides the CLI, importing `darp` registers a `.darp` accessor on the DataFrame
via the official [pandas extension API](https://pandas.pydata.org/docs/development/extending.html)
(`register_dataframe_accessor`) — the same integration pattern as
[json-canon](https://github.com/lucianofedericopereira/json-canon)'s `.jsoncanon`
accessor. A pandas result flows straight into a DARP report, with no intermediate
trace files:

```python
import pandas as pd, darp

df = pd.DataFrame(events)            # rows in DARP's anonymized-event schema
df.darp.metrics(definitions)        # -> raw metric_results
report = df.darp.report(cfg)        # -> a full .darp dict (verifiable content_hash)
```

The accessor runs the very same engine as the CLI (`compute_anon` → `build_darp`),
so a report built from a DataFrame is byte-for-byte equivalent to one built from
trace files. Classification config is read from the process-wide capture settings;
pass `capture=<dict>` to set it explicitly per call (the accessor never mutates
the global config, so two DataFrames with different settings never interfere).

---

## File format

```jsonc
{
  "$schema":     "darp:1.0",
  "darp_version": "1.0",

  "definitions": {               // who, what, algorithm — covered by content_hash
    "subject":      "hint-followthrough",
    "project":      "DARP",
    "orcid":        "0009-0002-4591-6568",   // claimed iD — half of the authorship claim
    "repo":         "https://github.com/<owner>/<repo>",  // other half — verified at L7
    "license":      "LGPL-2.1-only",
    "links":        { "Preprint": "https://...", "Dataset": "https://..." },  // free-form
    "citation":     { "cff-version": "1.2.0", "title": "...", "authors": [ ... ] },  // CFF
    "algorithm": {
      "engine":     { "name": "pandas", "version": "2.x", "language": "python" },
      "parameters": { "session_metric": "first_lookup", "algorithm_map": {}, ... },
      "definitions": { /* metric declarations from darp.ini */ }
    }
  },

  "data": {                      // results — covered by content_hash
    "generated_at": "2026-05-30T...",
    "measurement_period": { "from": "2026-01-01", "to": "2026-05-30" },
    "health":   { "session_count": 42, "first_lookup_specific_pct": 71.4, ... },
    "metrics":  [ { "name": "read_gate", "type": "window_proportion",
                    "n": 120, "k": 87, "value": 72.5, "breakdown": { ... } } ],
    "trend":    [ /* per-session breakdown */ ],
    "data_commitment": {
      "source_hash":   "sha256:...",   // SHA256 of all trace files
      "session_count": 42,
      "reproducibility": { "included": false }   // true when --stream
    }
  },

  "metadata": {                  // proof chain — append-only after generation
    "content_hash":       "sha256:...",   // SHA256(definitions + data)
    "config_hash":        "sha256:...",
    "document_hash":      "sha256:...",
    "consistency_checks": [ ... ],
    "generator":          { "version": "1.0.0", "script_hash": "sha256:..." },
    "timestamp":          null            // filled by: stamp
  }
}
```

The full JSON Schema is in `darp.schema.json` (`$id: darp:1.0`).

---

## Verify levels

```
python3 darp.py verify <file.darp> [--traces DIR] [--schema FILE] [--verify-anchor] [--verify-authorship] [--quiet]
```

| Level | What is checked | Requires |
|---|---|---|
| L1 | Schema validation + cross-validate (algorithm resolves, breakdown keys match) | `.darp` only |
| L2 | Arithmetic re-derivation (deltas, divergence, session count) | `.darp` only |
| L3 | `content_hash` integrity — detects any post-generation tampering | `.darp` only |
| L4 | Source hash: recomputes SHA256 of trace files, compares to stored | `--traces DIR` |
| L5 | Full metric replay: re-runs computation, compares to stored values | `--traces DIR` |
| L6 | Bitcoin anchor: fetches the attested block and compares its merkle root | `--verify-anchor` + network |
| L7 | Authorship: the `definitions.repo` owner is an account on the claimed ORCID record (iD + name + repo, one read) | `--verify-authorship` + network |

L1–L3 are self-contained. The `.darp` file embeds everything they need, including the `algorithm_map` and capture configuration; the ini is never required after generation. L6 and L7 are opt-in and reach the network. L6 confirms the embedded OTS proof commits to the Bitcoin block it claims, against your own node (`--bitcoin-node`) or a public explorer (`--explorer`). L7 reads `pub.orcid.org/v3.0/<iD>/person` once and validates three things: the iD resolves, the author's name, and the repo's ownership. On a **known host** (github.com, gitlab.com, bitbucket.org, codeberg.org, gitea.com, gitee.com) the repo's **account** (`host/owner`) must be listed, so one profile link covers every repo under it; on an **unknown host** the record must list the exact repo URL, one-to-one. No login or token. See [CITING.md](CITING.md).

---

## Four computation primitives

Primitives are declared in `[algorithms]` and referenced in each `[definition.*]` via `algorithm =`.

| Primitive | What it measures | Abstract type | Needs trigger |
|---|---|---|---|
| `next` | Immediately-next tool call: followed / modified / routed / memory | `proportion` | yes |
| `window` | Whether a target action occurs within N steps after a gate | `window_proportion` | yes |
| `first` | Classifies the first API call per session | `classification` | no |
| `rate` | Fraction of sessions containing at least one hint of a source | `proportion` | yes |

### Renaming primitives

You can use project-specific names in `[algorithms]` and reference them in definitions:

```ini
[algorithms]
packages_routing = window   # rename "window" to something meaningful
hint_analysis    = next

[definition.read_gate]
algorithm = packages_routing
```

The mapping is embedded in the `.darp` file at generation time, so verify and replay work without the ini.

### `window` primitive — two-view metric

`window` produces two complementary views:

- **per-gate %** — of all gates that had at least one API call in their window, what fraction was the target call? Tuning metric.
- **per-session %** — fraction of sessions that had at least one gate followed by the target call. Sanity check.

Divergence between the two views beyond `divergence_max` (default 20 pts) triggers a WARNING. High divergence indicates gate-cluster density, not a regression.

---

## Configuration reference

### `[project]`
| Key | Description |
|---|---|
| `name` | Project display name |
| `orcid` | Author ORCID iD (`XXXX-XXXX-XXXX-XXXX`) — a claim, verified at L7 against `repo` |
| `repo` | This paper's repo as a full `host/owner/repo` URL; written to the hashed `definitions.repo`. At L7 its owner is matched against your ORCID researcher-urls — by account on a known host, exact URL otherwise (see [CITING.md](CITING.md)) |
| `license` | License for this artifact — SPDX identifier (e.g. `LGPL-2.1-only`) or URL |

Provenance lives in two free-standing sections (both hashed into `definitions`):

### `[links]`
Free-form provenance links — one `description = url` per line, any number, any wording (preprint, dataset, slides, …). Becomes a `definitions.links` map. Replaces the old fixed `preprint_url`/`repo_url`.

```ini
[links]
Preprint on arXiv = https://arxiv.org/abs/2026.xxxxx
Dataset on Zenodo = https://zenodo.org/record/xxxxx
```

### `[citation]`
How to cite the paper, embedded as a [Citation File Format](https://citation-file-format.github.io/) (CFF 1.2.0) object in `definitions.citation`, so any tool renders APA / BibTeX / MLA. The author is built from `given_names`/`family_names` plus the `[project]` orcid. Read it back with `darp cite` (below).

| Key | Description |
|---|---|
| `title` | Work title (required; omit the section to skip citation) |
| `type` | `software`, `article`, `dataset`, … (default `software`) |
| `version` | Version string |
| `given_names`, `family_names` | Author name (orcid is pulled from `[project]`) |
| `doi`, `url`, `date_released`, `message` | Optional CFF fields |

### `[capture]`
| Key | Default | Description |
|---|---|---|
| `api_command` | `api.py` | Command string that identifies API calls in traces |
| `packages_path` | `packages/` | Path prefix for package bypass detection |
| `vibe_pattern` | `vibe` | API family name excluded from `first` classification |
| `memory_tool` | `mcp__ccd_session__search_session_transcripts` | Tool name classified as "memory" outcome |
| `trace_pattern` | `hint_trace_*.jsonl` | Glob pattern for trace files |
| `smoke_prefix` | `smoke` | Session ID prefix marking smoke/test sessions (excluded from metrics) |
| `specific_families` | `which,component,...` | API endpoint families counted as "specific" |
| `generic_families` | `grep,find` | API endpoint families counted as "generic" |
| `packages_tools` | `Read,Glob,Grep` | Tools that count as packages bypass |

### `[source]`
Maps external trace field names to DARP's internal model. All keys are optional — omit any key that matches the default.

| Key | Default | Description |
|---|---|---|
| `event_field` | `event` | Field holding the event type discriminator |
| `hint_value` | `darp_hint` | Value of `event_field` that means a hint fired |
| `action_value` | `darp_action` | Value of `event_field` that means a tool was called |
| `ts_field` | `ts` | Timestamp field (numeric Unix seconds after scaling) |
| `ts_scale` | `1.0` | Multiply raw timestamp by this to get Unix seconds (e.g. `1e-9` for nanoseconds) |
| `source_field` | `source` | Hint source name — matched against `trigger_source` in definitions |
| `synthetic_field` | `synthetic` | Bool; `true` excludes the hint from metrics |
| `try_next_field` | `try_next` | List of suggested invocation strings |
| `tool_field` | `tool` | Action tool name |
| `invocation_field` | `invocation` | Full invocation string scanned for API calls |

Dotted paths (e.g. `attributes.darp.source`) reach nested fields. The map is embedded in the `.darp` at generation time so verify and replay work without the ini.

### `[algorithms]`
Maps researcher-chosen names to internal primitives. Identity entries (`next = next`) serve as documentation of available primitives. Add entries to introduce project-specific names.

### `[algorithm]`
| Key | Description |
|---|---|
| `session_metric` | Name of a `first`-primitive definition that drives `health{}` and the per-session trend column |
| `min_sessions` | Fewer sessions than this triggers a WARNING on the `session_count` check |

### `[definition.NAME]`
One section per metric. `NAME` must match the `source` field in your trace events.

| Key | Required | Description |
|---|---|---|
| `algorithm` | yes | Primitive name (from `[algorithms]`) |
| `description` | yes | What this metric measures |
| `followed_if` | yes | When an event is counted as "followed" |
| `routed_if` | yes | When an event is counted as "routed" |
| `modified_if` | no | When an event is counted as "modified" (`next` only) |
| `type` | no | Free-text semantic label for reviewers (not used by code) |
| `trigger_source` | `next`/`window`/`rate` | Source name in trace events |
| `window` | `window` | Lookahead step count (default: 10) |
| `divergence_max` | `window` | Max acceptable per-gate vs per-session gap in pts (default: 20.0) |
| `echo_dedup` | `window` | Set `true` to remove echo tool calls that repeat the hinted path |
| `file_family` | `window` | API family that counts as "followed" (default: `file`) |

### `[baseline]`
| Key | Description |
|---|---|
| `commit` | Git commit hash or Zenodo DOI of the pre-registered experiment design |

### `[values]`
Baseline percentages for `analyze`. Keys are definition names (compared against `metrics[].value`) or health keys like `first_lookup_specific_pct` (compared against `health{}`).

### `[thresholds]`
| Key | Default | Description |
|---|---|---|
| `noise_band` | `10.0` | Within this many pts of baseline → PASS |
| `warn_band` | `20.0` | Beyond noise\_band but within warn\_band → WARNING; beyond → FAIL |
| `divergence` | `20.0` | Max per-gate vs per-session gap for `window` metrics |

### `[output]`
| Key | Default | Description |
|---|---|---|
| `stream` | `false` | Embed anonymized event stream. Required for OTS stamping and L5 verify |
| `format_version` | `1.0` | `.darp` format version written to output |

### `[anchor]`
| Key | Default | Description |
|---|---|---|
| `calendars` | three public OTS pool servers | Comma-separated OpenTimestamps calendar URLs |
| `orcid_api` | `https://pub.orcid.org/v3.0` | ORCID public read API base for `verify --verify-authorship` (validates iD, author name, repo in one GET; sandbox: `https://pub.sandbox.orcid.org/v3.0`) |
| `timeout_s` | `15` | Network timeout in seconds (OTS calendars, Bitcoin backend, ORCID read) |

---

## Adapting to a new project

```bash
cp -r darp/ my-project/darp/
cd my-project/darp/
```

Edit `darp.ini` in this order:

1. `[project]` — name, ORCID, URLs, license
2. `[subject]` — experiment label
3. `[capture]` — match your trace format and API command
4. `[paths]` — where traces live, where reports go
5. `[baseline]` — commit hash of your pre-registered experiment design
6. `[algorithms]` — rename primitives to project-specific names (optional)
7. `[algorithm]` — set `session_metric` to your `first`-primitive definition
8. `[definition.X]` — one section per metric source

Then run:

```bash
python3 darp.py
```

---

## Anchor workflow

```
generate  →  stamp  →  (wait ~1-2 hours)  →  upgrade  →  publish in repo (ORCID lists it)
```

```bash
# Generate with event stream (required for stamping)
python3 darp.py --stream

# Submit content_hash to OpenTimestamps (Bitcoin)
python3 darp.py stamp reports/YYYYMMDD-subject.darp

# After Bitcoin confirms (~1-2 hours), upgrade the OTS proof
python3 darp.py upgrade reports/YYYYMMDD-subject.darp

# Check current anchor status (also shows the claimed ORCID iD + repo)
python3 darp.py status reports/YYYYMMDD-subject.darp

# Confirm authorship: definitions.repo's owner must be an account on the claimed ORCID record
python3 darp.py verify reports/YYYYMMDD-subject.darp --verify-authorship
```

**Authorship is login-free.** Set `[project] repo = https://<host>/<owner>/<repo>`,
publish the report in that repo, and add a link on your ORCID record proving you
own it. On a known host (github.com, gitlab.com, bitbucket.org, codeberg.org,
gitea.com, gitee.com) your **profile** `https://<host>/<owner>` suffices: it
covers every repo under your account. On any other host, add the exact repo URL.
One public read — no token, no account, no OAuth — confirms the iD, the author's
name, and that the repo's owner matches an account the record lists. Only you can
add that link, and only you can push under that account, so the match proves the
work is yours. The same `content_hash` is committed to Bitcoin, so a reviewer
confirms *what*, *when*, and *who* from public artifacts alone. Full guide:
[CITING.md](CITING.md).

---

## Command reference

### generate (default)

```
python3 darp.py [flags]

--config FILE       Alternative .ini file (default: darp.ini)
--stream            Embed anonymized event stream in output
--no-stream         Omit event stream
--out DIR           Output directory override
--trace-dir DIR     Directory containing trace files
--subject NAME      Override subject label
--snapshot LABEL    Append label to output filename
--from-darp FILE    Replay from embedded stream in a prior .darp
--sessions N:M      Slice sessions N to M (Python slice semantics)
--repo URL          This paper's repo (host/owner/repo) → definitions.repo
--id LABEL          Citekey label for the report (e.g. 2026a)
```

### analyze

```
python3 darp.py analyze <file.darp> [flags]

--baseline-ini FILE      Read baselines from ini [values] section
--baseline-darp FILE     Read baselines from another .darp file
--baseline-values STR    Inline key=value pairs (e.g. "read_gate=17.0,...")
--baseline-commit HASH   Override commit hash for provenance display
--out FILE|DIR           Write JSON output instead of printing
--quiet                  Only print failures
```

### verify

```
python3 darp.py verify <file.darp> [flags]

--traces DIR         Trace file directory (enables L4 + L5)
--schema FILE        Path to darp.schema.json (default: auto-locate)
--verify-anchor      L6: re-check the OTS proof against the Bitcoin chain
--verify-authorship  L7: definitions.repo's owner must be an account on the claimed ORCID record
--quiet              Only print failures
```

### cite

```
python3 darp.py cite <file.darp> [--format cff|bibtex|apa]
```

Prints the embedded `definitions.citation` (the `[citation]` CFF block). `cff`
(default) emits Citation File Format YAML; `bibtex` and `apa` render from the
same fields. Exits non-zero if the artifact carries no citation.

### stamp / upgrade / status

```
python3 darp.py stamp   <file.darp>
python3 darp.py upgrade <file.darp> [--bitcoin-node URL | --explorer | --explorer-url URL]
python3 darp.py status  <file.darp> [--proof]
```

Authorship has no subcommand — it is verified, not written: `verify --verify-authorship`.

---

## Author & License

Author: **Luciano Federico Pereira**

Licensed under version 2.1 of the **GNU Lesser General Public License** (LGPL-2.1-only).
This program is distributed WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
