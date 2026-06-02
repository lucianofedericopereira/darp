<!--
Copyright (C) 2026 Luciano Federico Pereira
Licensed under version 2.1 of the GNU Lesser General Public License.
-->

# Citing & verifying a DARP artifact in your paper

A `.darp` file lets a reader independently re-derive your reported numbers, confirm nothing changed since you published, see when it existed (Bitcoin), and confirm it is really yours (ORCID) — **with no login, no account, and no trust in any tool, including DARP.** This page gives you (1) a paragraph to paste into your paper and (2) the exact commands a skeptical reviewer runs.

---

## 1. One-time author setup

1. Publish the report in your paper's repository on a known host
   (github.com, gitlab.com, bitbucket.org, codeberg.org, gitea.com, gitee.com):
   `https://<host>/<owner>/<repo>/report.darp`
2. On your **ORCID record → Websites & social links**, add a link proving you own
   the repo. On a known host, your **profile** alone suffices
   (`https://github.com/<owner>`): it covers every repo under your account. A full
   repo URL works too. On any other host, add the exact repository URL. Only you
   can do this, and that is what binds the repo to your iD.
3. In `darp.ini` set `[project] orcid = <your iD>` and
   `[project] repo = https://<host>/<owner>/<repo>`, then regenerate so the repo
   lands in `definitions.repo`.
4. `stamp` (and later `upgrade`) the report so its `content_hash` is anchored to
   Bitcoin via OpenTimestamps.

That is the whole loop: **paper → cites repo → holds `report.darp` → claims your ORCID → which lists the repo.**

---

## 2. Statement to paste into your paper

Put this in *Data & Code Availability* (or *Methods → Verification*), filling the
four placeholders:

> **Verification.** The behavioural measurements reported here are published as a
> tamper-evident DARP artifact at `<REPO-URL>/report.darp`. Its integrity hash
> `<CONTENT-HASH>` is anchored to the Bitcoin blockchain via OpenTimestamps, and
> the artifact is bound to author ORCID `<ORCID-iD>` through a researcher-url on
> that ORCID record pointing to the same repository. Any reader can recompute the
> reported metrics from the embedded event stream, confirm the hash, the
> timestamp, and the authorship, using the open-source DARP tool — no account or
> credentials required. See the artifact for the exact verification procedure.

Shorter footnote form:

> Measurements verifiable as a DARP artifact (`<REPO-URL>/report.darp`,
> `content_hash <CONTENT-HASH>`), Bitcoin-timestamped and ORCID-bound; verify with
> `darp verify`.

`<CONTENT-HASH>` is `metadata.content_hash` in the file.

---

## 3. What a reviewer runs (no credentials)

```sh
# fetch the artifact the paper cites
curl -sO https://<host>/<owner>/<repo>/report.darp

# L1–L5: schema, arithmetic re-derivation, and content_hash integrity
python3 darp.py verify report.darp

# L6: the Bitcoin anchor — merkle root of the attested block
python3 darp.py verify report.darp --verify-anchor

# L7: authorship — the repo's owner must be an account the claimed ORCID lists
python3 darp.py verify report.darp --verify-authorship
```

What each proves:

| Check | Question it answers |
|---|---|
| `content_hash` recomputes | Were the numbers or data altered after publication? |
| metric replay (`--traces`) | Do the reported percentages actually follow from the events? |
| `--verify-anchor` | Did this exact content exist before a known Bitcoin block? |
| `--verify-authorship` | Does the cited repo's owner match an account on the claimed author's ORCID record? |

All four are public reads. A failure on any line is a concrete, citable discrepancy.

---

## 4. Why this is trustworthy without a login

Two facts only the genuine author can create, and anyone can read:

- only **you** can add a researcher-url to **your** ORCID record, and
- only **you** can push to a repository under **your** account.

DARP checks that the repo (`definitions.repo`) is yours. On a known host, its
**account** (host and owner) must appear on your ORCID record, so one profile
link binds every repo under it; on any other host, the record must list the exact
repo URL. A bare host never matches. An impostor can neither edit your record nor
push under your account, so the match cannot be forged. The Bitcoin anchor adds trustless
time; the repository's commit history and publication in multiple venues
corroborate it. Full rationale: [PAPER.md](PAPER.md).
