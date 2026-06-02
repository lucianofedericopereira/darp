# DARP — Diff-Anchored Reporting Proof

**Luciano Federico Pereira** · independent researcher · orcid.org/0009-0002-4591-6568

## Abstract

Measuring agent behavior in production environments differs fundamentally from benchmark evaluation, creating conditions that directly undermine whether empirical claims can be trusted. While open-source research relies on the publication of full repositories and raw data for independent re-execution, production environments are frequently constrained by intellectual property boundaries, privacy concerns, and security policies that preclude sharing code or logs. The conventional basis for empirical trust is therefore absent; a behavioral statistic from such a deployment can be neither reproduced nor audited by an external reviewer. 

This opacity is compounded by reflexivity: the measurement instrument is itself software under active development, often modified by the very class of agent it measures. We isolate three specific failure modes inherent to this environment—auditor = subject, instrument-equivalence, and unanchored followthrough—and introduce DARP (Diff-Anchored Reporting Proof). DARP is a protocol designed to publish verifiable behavioral results from proprietary or closed environments without exposing the underlying codebase. 

DARP generates a self-contained, de-identified artifact by hashing session identifiers, scrubbing directory paths, and reducing tool interactions to abstract, typed schemas. Using this embedded event stream, an external reviewer can independently re-derive the reported metrics and validate them against a cryptographic content hash, an OpenTimestamps proof anchored to Bitcoin, and the author's ORCID record. This validation protocol relies entirely on public read access and requires neither the original repository nor privileged credentials. Although DARP serves as a generalized validation mechanism applicable to public repositories, its primary contribution is architectural discipline for closed environments: any behavioral claim a system asserts about itself should be constructed so that an external party can deterministically re-derive it without access to the host system.

## 1. Introduction

Empirical validation in software-driven agent deployments is constrained by a persistent operational boundary: the codebases and execution environments are frequently proprietary. Execution traces name internal network endpoints, specific directory paths, and sensitive system identifiers. Publishing these raw repositories or unedited logs would constitute a severe security breach rather than a mere administrative hurdle. This constraint is endemic to production-grade agent measurement, and it effectively nullifies standard open-science remedies. Both pre-registration and open-data policies presume that the measurement instrument and its complete input corpus can be exposed to external scrutiny. When privacy or intellectual property boundaries prevent this exposure, conventional pathways to replication collapse.

Pre-registration—the ex-ante commitment to outcome variables, operational thresholds, and analytical pipelines—was explicitly developed to restrict an evaluator's degrees of freedom (Simmons et al., 2011; Leamer, 1983). It remains the structural benchmark in clinical trials (De Angelis et al., 2004) and is increasingly advocated within empirical machine learning (Pineau et al., 2021). Yet, while pre-registration is a necessary step, it falls short when applied to live agentic systems due to two distinct dynamics. First, it assumes a static, frozen instrument, which a codebase under active, often AI-assisted development lacks. Second, it assumes independent data analysis, which a secure production environment precludes. DARP bridges this gap: a behavioral claim that cannot be validated by releasing the underlying system must instead be encapsulated in a detached artifact that an external party can evaluate independently.

This framework is governed by the principle of reflexivity. An agent cannot reliably validate its own assertions, as the verifying mechanism is vulnerable to the same systemic failure modes as the primary action. Verification must therefore shift to a non-agent mechanism at a serialization boundary. This logic scales directly to measurement. A self-reported behavioral statistic is merely an unverified assertion made by the subject system. Because an agentic system cannot serve as its own auditor, the resulting metrics must be rendered verifiable by an independent non-participant rather than accepted on the producing agent's authority.

## 2. The Proprietary and Closed-System Constraint

Conventional empirical reproducibility is defeated by three intersecting properties of live, production-grade deployments:

1. **Repository Confidentiality:** The underlying codebase is proprietary and cannot be disclosed due to corporate IP restrictions.
2. **Telemetry Sensitivity:** Execution traces contain internal configuration details and sensitive identifiers, meaning raw inputs cannot be made public.
3. **Instrument Instability:** The measurement instrument is composed of software that the subject agents actively help modify, meaning it is neither static nor independently governed.

While the first two conditions prevent external reviewers from re-executing the analytical pipeline or inspecting the underlying data, the third prevents the producer from verifying that the instrument remained constant throughout the evaluation.

As a result, any behavioral metric reported from such a system remains inherently unfalsifiable, leaving external skeptics with no pathway for validation. DARP addresses this vulnerability by elevating falsifiability to a core design requirement. The framework ensures that the generated artifact is simultaneously *publishable*—meaning its distribution cannot expose the underlying codebase—and *independently verifiable*—meaning an external party can re-derive and validate the reported metrics without relying on the repository, the source code, or credentials. While this formatting protocol can be trivially applied to open-source software to standardize audit logs, its structural necessity is maxed in closed environments. The remainder of this paper describes how DARP satisfies both constraints simultaneously, establishing a verification pipeline independent of codebase visibility.

## 3. Three Failure Modes

### 3.1 Unanchored Followthrough

The hint-followthrough rate measures the number of sessions executing a hint relative to the total number of sessions exposed to one. However, this single metric confounds two distinct causal pathways that yield an identical numerator: either the hint actively altered the agent’s trajectory, or the agent would have pursued the same course of action independently. 

A followthrough rate equivalent to the unhinted baseline does not capture a behavioral effect; it is simply the base rate masquerading as one. Correcting this requires a suppressed experimental arm—a matched cohort of control sessions where the hint logic triggers within the trace but the text is strictly withheld from the agent. Absent this control, every reported followthrough metric remains hint-positive by construction, leaving the counterfactual unestablished. DARP fundamentally enforces the discipline that no followthrough rate may be reported without both a pre-committed threshold and a suppressed-arm control. A metric stripped of its counterfactual is an observation, not a finding.

### 3.2 Auditor = Subject

The analytical pipeline reads the experimental design, operational thresholds, active metrics, and execution traces to generate a report. Within an agentic deployment, this analytical session shares a homogenous architecture—operating as an agent session on the same underlying codebase—with the subjects under evaluation. Auditing the experiment therefore constitutes an active intervention on the measured population: the analysis session possesses explicit context regarding the evaluation criteria and risks altering subsequent agent trajectories through state leakage or persistent artifacts left in the working environment. This vulnerability cannot be mitigated post-hoc. While the telemetry capture layer must be universally operable across all sessions, the analysis phase must be isolated to a non-participant session. The foundational constraint that an agent cannot act as its own gate dictates that, in empirical measurement, an agent cannot serve as its own auditor.

### 3.3 Instrument-Equivalence

In traditional empirical research, a validated assay maintains longitudinal stability between baseline and follow-up, just as a frozen test set is applied uniformly across models. Agent evaluation cannot assume this invariance. The trace schema, capture hooks, analysis pipelines, and session-initialization logic that populate stratification fields are software artifacts subject to active, often AI-assisted modification. A single programmatic adjustment can introduce a field, refactor a telemetry hook, or mutate field-population logic between baseline and treatment periods. When this occurs, a before-after comparison confounds behavioral change with instrumental variance—yielding a flawed estimate without triggering runtime errors. Standard pre-registration mechanisms cannot detect this shift, as they presume the ex-ante registered instrument remains identical to the one deployed ex-post. Section 6 details an empirical instance of this instrument drift and evaluates the mechanisms that exposed it.

## 4. Measure Versus Enforce: The Three-Tier Model

Prior to designing any behavioral metric, a foundational question must be resolved: should the target behavior be evaluated via telemetry or restricted by design? Conflating measurement with enforcement is an endemic architectural error. It manifests either as measuring a behavior that a deterministic hard gate already guarantees—where total compliance renders the resulting metric an uninformative constant—or as attempting to enforce a behavioral constraint through a signal that fires only after a violation has already occurred.

| Tier | Condition | Action | Reportable Signal |
| :--- | :--- | :--- | :--- |
| **T1 — Enforce** | Prohibited behavior, unambiguous correct path | Mechanical gate | Block frequency over time; not a followthrough rate |
| **T2 — Measure** | Observable but not forceable in runtime | Track outcome with a suppressed-arm control (§3.1) | The counterfactual outcome rate |
| **T3 — Drop** | Cost of bad path is low, tracking overhead high | Remove the nudge / logging | None; telemetry is net noise |

The single primary health metric DARP reports needs none of this experimental apparatus: *first-lookup endpoint choice*—whether a session's first structured lookup utilized a specific endpoint rather than a generic search. Because this action occurs before any gate or hint can exert influence, it purely reflects the agent's uninstructed prior and requires no counterfactual control arm. It is the one figure an external reviewer can accept at face value.

## 5. DARP Protocol Architecture

### 5.1 Capture Is Not Analysis

Two independent evaluators operating under divergent baseline assumptions must arrive at identical `.darp` artifacts when provided with identical telemetry traces. If the capture layer inadvertently encodes baseline-dependent fields—such as deltas, anomaly flags, or categorical pass/fail verdicts—it violates this requirement of algorithmic determinism. To enforce this, DARP strictly segregates three computational concerns that undisciplined pipelines typically conflate. These operational roles are isolated by interface rather than by file boundaries: DARP is executed via a unified script, `darp.py`, that relies on distinct, decoupled subcommands to maintain state isolation.

| Concern | Role | Execution Interface | Output |
| :--- | :--- | :--- | :--- |
| **What happened** | Capture | `darp.py generate` | Independent `.darp` record |
| **What it means** | Analysis | `darp.py analyze` | Layered metric interpretation |
| **Whether to trust it** | Verification | `darp.py verify` | Seven-tier integrity proof |

The `.darp` artifact serves as an unalterable historical record; analytical interpretation is applied downstream and never mutates the underlying telemetry commitment.

### 5.2 The Artifact Specification

A `.darp` file comprises three structural blocks. The `definitions` block (containing the subject, project, author's ORCID iD, repository location, license, provenance links, an embedded citation, algorithm configurations, and metric declarations) and the `data` block (containing baseline health figures, metrics, per-session trends, a source-hash data commitment, and an optional embedded event stream) are strictly immutable after generation. Conversely, the `metadata` block—which encodes the content hash, runtime consistency checks, generator provenance (including the SHA-256 hash of `darp.py` itself), and any timestamp proofs—is strictly append-only.

The core cryptographic ledger commitment is defined as:

$$\text{content\_hash} = \text{SHA256}(\text{canonical}(\{\text{definitions}, \text{data}\}))$$

Because state expansion is strictly confined to the append-only `metadata` block post-generation, the core content hash remains invariant throughout the entire timestamping and upgrade workflow. The generator's source hash is archived within `metadata` exclusively for provenance, deliberately isolated from the primary data commitment. The validation architecture ensures that verification independently re-derives every metric from the embedded event stream using the deterministic algorithm specification encapsulated in the hashed `definitions` block. As a result, the verification runtime never executes or trusts the original `darp.py` source code. Eliminating the tool's source bytes from the claim hash prevents two critical failure modes: it preserves cross-implementation reproducibility (Section 5.4) and ensures that minor, cosmetic updates to the reporting tool do not invalidate the hashes of static empirical data.

### 5.3 De-Identification as a Security Boundary

Because the generated artifact constitutes the sole publishable residue of a closed system, data de-identification is integrated as an immutable design constraint rather than a post-hoc policy compliance measure. Under this protocol:
- **Session Identifiers:** Undergo pseudonymization via SHA-256 prefix truncation.
- **System Structures:** Directory file paths are completely purged.
- **Temporal Alignment:** Absolute timestamps are transformed into relative offsets from session initialization.
- **Action Abstraction:** Tool invocations are compressed into abstract, typed schemas recording only whether an invocation interacted with the internal API, its corresponding endpoint family, and the underlying tool name, deliberately discarding the literal command string or payload.

Project and author attributes are preserved intact to maintain public attribution. This data reduction ensures that the resulting payload retains the minimum information necessary to deterministically re-derive behavioral claims, while eliminating the risk of information leakage regarding the proprietary codebase or runtime queries.

### 5.4 Canonical Form and Content Commitment

Cryptographic hashes over JSON payloads remain valid only under strict byte-level serialization invariance across heterogeneous runtimes. DARP achieves this determinism by enforcing a canonical schema representation: keys are sorted lexicographically by Unicode code point, strings are encoded as raw UTF-8, and numerical values are normalized into decimal strings via dedicated string and integer manipulations rather than binary floating-point conversions. This architecture avoids IEEE 754 floating-point precision drift, preserving large integers and collapsing divergent syntax like `20.0` and `20` into an identical string representation. 

This serialization protocol yields two fundamental properties:
1. **Reformatting Tolerance:** Structural alterations—such as pretty-printing, whitespace adjustments, or key reordering within the physical file—leave the content hash invariant, as the cryptographic digest is executed strictly over the canonicalized state rather than the raw file bytes.
2. **Cross-Implementation Reproducibility:** An independent verification engine that reconstructs the matching `{definitions, data}` payload will generate the exact same hash, decoupling the validation phase from the specific reporting tool used during initial artifact generation.

### 5.5 Seven Verification Levels

| Level | Integrity Target | Required Context |
| :--- | :--- | :--- |
| **L1** | Schema and structural cross-validation | `.darp` artifact only |
| **L2** | Arithmetic metric re-derivation (rates, ratios, balances) | `.darp` artifact only |
| **L3** | Cryptographic `content_hash` check (tamper detection) | `.darp` artifact only |
| **L4** | Source validation (SHA-256 validation of trace footprint) | Local trace telemetry |
| **L5** | Deterministic metric replay from event logs | Local traces or embedded stream |
| **L6** | Decentralized temporal anchor verification | Network access (Bitcoin OpenTimestamps) |
| **L7** | Federated authorship attribution mapping | Network access (Public ORCID API) |

The verification hierarchy spans seven distinct tiers, moving from localized data integrity to decentralized cryptographic anchoring. Levels 1 through 3 are fully self-contained: the artifact embeds the algorithm and source mappings, obviating the need for an external repository, source code, or runtime configuration. Levels 4 and 5 ingest the execution traces or, when the event stream is embedded, execute a deterministic replay of the entire analytical computation from the standalone artifact. Levels 6 and 7 provide opt-in integration with public decentralized infrastructure, transforming a self-attested artifact into an anchored proof. Specifically, a Bitcoin timestamp establishes the temporal existence of the data, while an ORCID record establishes author identity. Both are resolvable via unauthenticated public reads. Consequently, while standard self-reported metrics remain unfalsifiable, a `.darp` artifact supports seven independent verification vectors without exposing the underlying closed system.

This decentralized identity mechanism addresses a core vulnerability of proprietary deployments: the inability to open the repository that conventionally dictates provenance. By embedding the author's ORCID iD and repository metadata within the cryptographically hashed `definitions` block, the authorship claim becomes inherently tamper-evident. Level 7 validation executes a single public read of the federated ORCID record to verify that the repository owner corresponds to an authenticated account on that profile. For recognized hosting platforms, this mapping operates at the account level—where a single profile reference validates all descendant repositories—while unrecognized hosts require an exact repository URL match. Because this architecture relies on public infrastructure constraints where only the author can modify their ORCID record or push to the corresponding code repository, the resulting binding achieves non-repudiation without requiring shared secrets, public-key infrastructure (PKI) overhead, or runtime authentication.

### 5.6 Verification as Complete Mediation

This verification architecture represents a modern realization of foundational computer security primitives. *Complete mediation* (Saltzer & Schroeder, 1975) mandates that every security-critical evaluation intersect an unbypassable, tamper-resistant mediator; a *reference monitor* (Anderson, 1972) constitutes the abstract mechanism enforcing this constraint. Here, the self-reported metric is the target object requiring mediation. An isolated, scalar percentage remains fundamentally ungateable because its representation lacks any telemetry regarding its generation pipeline. The `.darp` specification resolves this opacity by rendering the metric deterministically re-derivable, transforming the seven verification tiers into an external reference monitor. 

Under this paradigm, a behavioral statistic is validated only if it clears structural re-derivation, cryptographic hashing, source provenance, deterministic replay, decentralized timestamping, and identity anchoring. To enforce the reflexivity constraint—that an agent cannot serve as its own auditor—this reference monitor is implemented strictly outside the agent boundary, utilizing standardized Python runtimes and unauthenticated public infrastructure reads. Consequently, the content hash and federated ORCID-repository binding act as a rigorous provenance type on the underlying measurement: a tampered metric fails Levels 3 and 5, an identity forgery fails Level 7, and an ex-post temporal manipulation fails Level 6.

### 5.7 The Two-View Attribution Metric

Crediting a hint for an internal API invocation based on a fixed lookahead window introduces an over-counting bias during concurrent hint telemetry. This co-occurrence is endemic to multi-layered architectures—such as when a read hint and a search gate fire simultaneously within a single task—resulting in a single downstream invocation being incorrectly attributed to multiple upstream triggers. Rather than compressing this phenomenon into a single confounded metric, DARP evaluates gate telemetry through two complementary lenses, using their divergence as a structural diagnostic. 
- **The Per-Gate (Tuning) View:** Calculates the proportion of gate instances whose lookahead windows contain a target API response.
- **The Per-Session (Sanity) View:** Tracks the proportion of unique sessions containing at least one gate sequence followed by that target invocation. 

When these two analytical dimensions diverge beyond a pre-committed bound, the pipeline triggers a runtime consistency warning. A pronounced divergence indicates localized gate-clustering density—a statistical artifact where a single anomalous session repeatedly executes a gate, inflating the event-level denominator—rather than a systemic behavioral regression. DARP deliberately exposes this variance rather than smoothing it post-hoc, as it serves as the primary signal that an event-level metric is being driven by dense clustering and cannot be interpreted as a uniform, session-level effect. This exact multi-view alignment is the validation mechanism that exposed the instrumentation contamination detailed in Section 6.

### 5.8 Metrics and the Computation Engine

Metrics are configuration rather than code. Each is one of four computation primitives over the de-identified event stream, declared in a definition block with an algorithm selector.

| Primitive | Target Analytical Inquiry | System Output | Execution Mechanism |
| :--- | :--- | :--- | :--- |
| `next` | Immediate operational routing evaluation | Step proportion | `merge_asof` sequence alignment within session |
| `window` | Co-occurrence and temporal tracking | Multi-view bounds | Grouped lookahead bounded trace index scans |
| `first` | Uninstructed behavioral prior classification | Categorical state | Session-isolated initial event row isolation |
| `rate` | Population tracking and deployment reach | Frequency ratio | Grouped session-level boolean identity scans |

Two primary consequences matter. First, the primary health metric (Section 4) relies on an invariant `first` event selection: since the initial invocation within a session occurs prior to any exogenous gate or hint influence, it circumvents the need for a suppressed control arm and stands as an immediately transparent empirical baseline. Second, the primary computational bottle-neck is mitigated via a time-series *as-of join* within the `next` subcommand, which pairs each hint with its chronologically succeeding action while bypassing the quadratic complexity ($O(N^2)$) of a naive scan. 

To maximize flexibility, this underlying execution engine is exposed as a native pandas DataFrame accessor. As a result, any metric that can be modeled as structured event rows can be evaluated without physical trace files, guaranteeing perfect output parity between DataFrame-driven reports and raw-file processing. Ultimately, extending the system with a new metric is reduced to a declarative configuration task rather than an imperative programming one: an evaluator merely appends a new `definitions` block specifying the primitive, the trigger source, and the semantic rules for followthrough or routing, entirely eliminating the need for novel codebase modifications.

## 6. Functional Verification: An Instrumentation Case Study

DARP operates over an unshareable, production-grade deployment where the foundational telemetry artifact is not a static calibration value—which remains meaningless without an open codebase to support replication—but rather a verifiable event in the instrument's own runtime history. During an early evaluation epoch of the tracking system, the read-gate multi-view diagnostic generated per-gate and per-session metrics whose divergence violated a pre-committed threshold, automatically triggering the consistency verification pipeline described in Section 5.7. 

Forensic analysis revealed that this divergence was a symptom of instrumental variance rather than an authentic behavioral shift, driven by two distinct modifications to the measurement layer: an anomalous telemetry emitter subsequently excised as a T3 metric, and an updated field-emission schema introduced via an automated, prompted modification to the capture hooks. Based on this detection, the anomalous epoch was archived and its data replaced.

This operational failure highlights the closed-system constraint in practice. Under traditional open-science paradigms, an evaluator would execute post-hoc replications of the legacy pipeline to isolate changes in the measurement framework. In proprietary environments, this methodology is foreclosed; the repository is inaccessible and historical hooks are entirely unrecoverable. Instead, instrument drift must be established natively through structural design: via a runtime consistency layer that flags metric anomalies during data capture, and via decoupled `.darp` artifacts that sustain independent re-derivation without source dependencies. This drift was exposed precisely because the artifact architecture was engineered to maintain cryptographic integrity past the boundary of a closed codebase. 

Here, the `[baseline]` commit authenticates the temporal boundary where the experimental configuration was frozen, while the multi-view divergence metric exposes changes in the measuring instrument across epochs—a strict prerequisite for valid longitudinal analysis. We disclose this event transparently: an archived epoch does not demonstrate a behavioral intervention effect, but rather proves that an agent-built instrument drifted and that our architectural disciplines successfully exposed the contamination. A rigorous before-after intervention analysis, relying on a suppressed experimental arm (Section 3.1) and an isolated, non-participant analytical runtime (Section 3.2), remains future work. The core contribution of this framework is the instrument architecture itself, alongside the verification disciplines that enable proprietary behavioral claims to be robustly validated by unauthenticated external reviewers.

## 7. Limitations and Scope Boundaries

- **Primary Paradigm Alignment:** While DARP's cryptographic format and verification tiers can be applied directly to public repositories to formalize open-source tracking logs, the protocol's constraints are intentionally optimized for private, closed environments. It trade-offs repository-level deep testing for artifact-level cryptographic verification.
- **Tool-Chain Protocol Focus:** The contribution of this manuscript is bounded strictly to the *DARP protocol architecture* and its mathematical state validation. It does not present novel, large-scale behavioral assertions regarding independent production agent cognitive profiles, using deployment telemetry purely to validate protocol execution.
- **Practitioner-Built, Self-Attested Records:** The initial state generation relies on practitioner initialization. Although the `[baseline]` commit is auditable, it remains an internal system record rather than a third-party ledger. This is structurally mitigated by the public decentralized infrastructure hooks: the OpenTimestamps anchor (L6) and ORCID validation (L7) turn the self-attested values into publicly immutable records, though behavioral validation still benefits from cross-organizational replication.
- **Isolation Boundaries Enforced Operationally:** The separation between passive capture runtimes and non-participant analytical runtimes is supported by the codebase interface, but its real-world implementation is an operational discipline that the static artifact layout cannot enforce on its own.
- **De-Identification Privacy Bounds:** The de-identification protocol relies on deterministic data structural reduction (hashing, truncation, and absolute time suppression). It removes direct identifiers but does not provide a formal $k$-anonymity or differential privacy guarantee against sophisticated side-channel traffic reconstruction attacks based on relative timing offsets.

## 8. Conclusion

Evaluating agent behavior in closed production environments exposes researchers to severe methodological vulnerabilities that traditional pre-registration schemes fail to intercept. These settings introduce two unique compounding challenges: the analytical auditing software is often architecture-homogenous with the system under review, and the measuring instrument itself is a mutating codebase under active, automated development. Standard empirical pre-analysis plans are unequipped to handle these tracking failures silently introduced by code modifications. 

DARP addresses these systemic vulnerabilities by decoupling data capture from baseline analysis, formalizing behavioral assertions into an immutable, de-identified artifact that embeds its own algorithm specifications and source commitments. By passing this payload through seven independent verification levels, an external reviewer can validate, re-derive, and cryptographically audit self-reported metrics without requiring credentialed access to a proprietary host system.

Ultimately, we assert that the identified failure modes represent systemic risks in modern software tracking, and that DARP provides an architectural remedy. By treating metrics as declarative configurations rather than executable commands, and anchoring historical outputs to public distributed infrastructures (Bitcoin and ORCID), DARP translates behavioral verification into an instance of complete mediation executed outside the agent boundary. Under this protocol, behavioral metrics asserted by a closed system are no longer accepted on trusted authority; they are built to be independently re-derived and verified by any non-participant.

---

## Colophon — On the Order of Discovery

The engineering pilots and the instrument-drift case are reported in the historical order they occurred, explicitly detailing the anomalous epoch that was archived rather than hiding the instrument mutation behind a scrubbed data record. The core discipline advocated across this paper—that scientific claims must be cryptographically falsifiable rather than loosely asserted—is applied symmetrically to the text itself: the empirical data footprint regenerates deterministically from the attached state artifacts, ensuring that an analytical course-correction is preserved as an audit trace rather than erased.

---

## Appendix A — Reproducibility Specification

The reference protocol tool is implemented as `darp.py`, a standalone script requiring only the Python standard library and `pandas`. System integration is managed via `darp.ini`, which structures capture rules for line-delimited JSON (`JSONL`) hint traces and maps production endpoints onto core DARP primitives: tracking read gates via `window` (the multi-view metric described in Section 5.7), first-lookups via `first` (the primary health metric described in Section 4), and search boundaries via `next`.

Execution footprints follow standard command-line interfaces:
- **Artifact Generation:** `python3 darp.py generate --stream`
- **Tiers 1–7 Verification:** `python3 darp.py verify <file>.darp`
- **Decentralized Anchor Validation (L6):** `python3 darp.py verify <file>.darp --verify-anchor`
- **Attribution Mapping (L7):** `python3 darp.py verify <file>.darp --verify-authorship`
- **Metadata Citation Printing:** `python3 darp.py cite <file>.darp`

The underlying configuration maps OpenTelemetry, Zipkin, Datadog, CloudWatch, and custom structured JSON footprints onto a unified internal model, ensuring that the tracking schema is detached from any single commercial logging provider. A sample tracking trace—including a generated `.darp` record successfully validated across Levels 1 through 5—ships alongside the source distribution to enable deterministic cross-platform verification.

---

## References

Anderson, J. P. (1972). *Computer Security Technology Planning Study.* ESD-TR-73-51, USAF.

De Angelis, C., Drazen, J. M., Frizelle, F. A., et al. (2004). Clinical trial registration: a statement from the ICMJE. *New England Journal of Medicine*, 351(12), 1250–1251.

Leamer, E. E. (1983). Let's take the con out of econometrics. *American Economic Review*, 73(1), 31–43.

OpenTimestamps. *Bitcoin-anchored timestamping.* https://opentimestamps.org

ORCID. *Public API v3.0.* https://pub.orcid.org

Pineau, J., Vincent-Lamarre, P., Sinha, K., Larivière, V., Beygelzimer, A., d'Alché-Buc, F., Fox, E., & Larochelle, H. (2021). Improving reproducibility in machine learning research (a report from the NeurIPS 2019 reproducibility program). *Journal of Machine Learning Research*, 22(164), 1–20.

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in computer systems. *Proceedings of the IEEE*, 63(9), 1278–1308.

Simmons, J. P., Nelson, L. D., & Simonsohn, U. (2011). False-positive psychology: Undisclosed flexibility in data collection and analysis allows presenting anything as significant. *Psychological Science*, 22(11), 1359–1366.