<!-- ATTACK-Navi - Copyright (c) 2026 TeamStarWolf - MIT License -->
# Library Layers Guide

**Library layers** are curated MITRE ATT&CK Navigator overlays bundled with ATTACK-Navi. Select one from the **Library Layers** picker in the matrix controls and the workbench colors each technique cell by that layer's score, letting you see a theme, a data-driven frequency, or a specific adversary's documented behavior projected onto the ATT&CK matrix. This build ships **36 layers**.

Counts below are distinct technique IDs in each layer, not technique/tactic rows or machine counts. The inventory is checked against the [bundled manifest](../src/assets/data/library-layers/index.json); the layers target the bundled Enterprise ATT&CK v19.2 snapshot.

## How to use them

- Open the **Library Layers** section of the matrix controls and pick a layer; the matrix recolors immediately.
- **Cell color = score.** For curated layers, score encodes a membership tier (core vs supporting). For the frequency layer, score is a normalized count. For threat-group layers, every colored cell is a documented technique (score 100).
- Layers are **overlays for exploration**, not authoritative coverage claims. Switch layers to compare, e.g. overlay a threat group, then a control theme, to reason about gaps.
- The picker reads `src/assets/data/library-layers/index.json` at runtime, so the set grows without any code change.

## Reading the scores & provenance

| Layer type | Score meaning | Source |
|---|---|---|
| Curated theme / weakness | Membership tier (core = 100, supporting = 55) or membership-only | TeamStarWolf reference library + validated against bundled ATT&CK data. **Not** an official MITRE mapping. |
| HTB frequency views | Normalized machine count (100 = most frequent technique within that layer) | Derived technique metadata only; broad, core, OS, and difficulty views have different cohorts/methods. Reflects HTB teaching bias, not enterprise prevalence. |
| Agentic AI Swarm | Event frequency across a de-identified 8-phase intrusion | Illustrative composite pattern; ATT&CK x ATLAS. Not an attribution of any specific incident. |
| Threat Group emulation | 100 = MITRE-documented use | Generated directly from MITRE's `intrusion-set --uses--> technique` relationships. **MITRE's own attribution.** |

## Application & Weakness (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Web Application Attacks | 32 | Web and API intrusion paths, including application exploitation, account abuse, session theft, and data access |
| OWASP Top 10 (2021) | 14 | Connects the library's OWASP Top 10 (2021) themes with relevant attacker behaviors |
| CWE Weakness Classes | 98 | Connects CWE weakness classes to ATT&CK behaviors through explicit CAPEC links in the library |
| CAPEC Families | 19 | Shows techniques explicitly linked to broad CAPEC Meta patterns in the library |

## Infrastructure & Platform (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Cloud Attacks | 23 | Covers selected cloud intrusion behaviors, from account and token abuse to data theft and destructive impact |
| Active Directory | 28 | Covers domain reconnaissance, credential theft, Kerberos and NTLM abuse, certificate attacks, and remote access |
| Container and Kubernetes Attacks | 9 | Covers container deployment, image abuse, host escape, workload discovery, and unauthorized compute use |
| macOS & Linux Attacks | 39 | Selected Unix/macOS behaviors; a technique may apply to either platform, not necessarily both. Per-row platform metadata narrows scope |

## Campaign & Behavior (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Ransomware TTPs | 14 | Follows common ransomware intrusion themes through access, credential theft, movement, exfiltration, encryption, and recovery inhibition |
| Insider Threat | 23 | Curated abuse of granted access, collection, export, and sabotage; behavior matches do not establish malicious intent |
| Impact: Destruction, Extortion & Disruption | 25 | Enterprise impact behaviors with supporting theft/preparation; a planning view, not a destructive execution runbook |

## Cross-Tactic Technique Themes (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Living-off-the-Land (LOTL) | 59 | Signed/legitimate binaries, interpreters, and admin tooling abused across execution, evasion, movement, and exfiltration |
| Phishing & Social Engineering | 36 | Lure delivery, user execution, and account/MFA abuse enabling human-targeted initial access |
| Supply Chain & Trusted-Relationship Compromise | 36 | Third-party, software/hardware supply-chain, and trusted-relationship intrusion paths |
| Data Collection & Exfiltration | 47 | Collection, staging/packaging, and egress channels for data theft |
| Credential Theft & Abuse | 64 | Dumping, cracking, store/file harvesting, ticket/token theft, and credential reuse |

## Frequency Analysis

| Layer | Techniques | Machine cohort | Normalization maximum |
|---|---|---|---|
| [HTB Technique Frequency](../src/assets/data/library-layers/htb-technique-frequency.json) | 135 | 535: 131 careful originals + 404 keyword-derived additions | 494 machines |
| [HTB Core Techniques (528, precise)](../src/assets/data/library-layers/htb-core-techniques-528.json) | 21 | 528, one uniform precise-pattern pass | 494 machines |
| [HTB Linux Techniques](../src/assets/data/library-layers/htb-linux-techniques.json) | 19 | 347 Linux records from the 529-machine content cohort | 323 machines |
| [HTB Windows Techniques](../src/assets/data/library-layers/htb-windows-techniques.json) | 19 | 142 Windows records from the 529-machine content cohort | 135 machines |
| [HTB Easy Techniques](../src/assets/data/library-layers/htb-easy-techniques.json) | 20 | 109 Easy records from the 529-machine content cohort | 109 machines |
| [HTB Medium Techniques](../src/assets/data/library-layers/htb-medium-techniques.json) | 21 | 125 Medium records from the 529-machine content cohort | 125 machines |
| [HTB Hard Techniques](../src/assets/data/library-layers/htb-hard-techniques.json) | 21 | 82 Hard records from the 529-machine content cohort | 82 machines |
| [HTB Insane Techniques](../src/assets/data/library-layers/htb-insane-techniques.json) | 21 | 56 Insane records from the 529-machine content cohort | 54 machines |

These are text-derived training signals, not executed attack validation or enterprise prevalence estimates. Scores normalize to the most frequent technique **inside each layer**, not the cohort size: 100 is not a prevalence percentage. Compare technique mix and supporting counts, not raw normalized scores across layers. OS and difficulty subsets do not exhaust the 529-machine content cohort; inventory-only distributions use a different denominator and must not be substituted here.

The broad layer's current manifest describes 535 machines. The core layer's description still contains a stale comparison to an older 249-machine broad snapshot; this guide uses the current broad artifact, while preserving the separate 528-machine core provenance. Dataset/registry reconciliation is a separate data task, not an implicit refresh in this documentation change.

## AI & Emerging Threats

| Layer | Techniques | Notes |
|---|---|---|
| Agentic AI Swarm Intrusion | 74 | Enterprise ATT&CK frequency across a generalized agentic-AI-swarm kill chain: credential reuse, egress-relay C2, pipeline exploitation, and cluster takeover |

## Lylat Training Range (mission coverage)

Coverage from the [Lylat Labs](https://github.com/TeamStarWolf/Lylat-Labs) themed training missions. **Planned/training coverage only** — the missions are `execution_verified: false`, so these layers show which techniques each mission is *designed to exercise*, **not** a validated detection or coverage result. Not an official MITRE mapping.

**Curated overlay (in the picker):**

| Layer | Techniques | Notes |
|---|---|---|
| TeamStarWolf - Lylat Mission Coverage | 105 | Enterprise ATT&CK techniques across the 28 enterprise Lylat missions, scored by how many missions map each (normalized to the most-mapped technique). Planned/training coverage, not detection. Excludes 3 IDs the missions cite that are revoked in the bundled 19.2 snapshot (T1070.001/T1562.002/T1656 — a library data-currency item, tracked separately). |

**Per-mission + per-domain layers (vendored, one-click importable):** all 35 individual layers (31 per-mission + 4 per-domain coverage) are served from `src/assets/data/lylat-mission-layers/` (see its `index.json`). Load any one through the matrix controls' **Import Layer** action (or your instance's load-from-file/URL) — e.g. `assets/data/lylat-mission-layers/lylat-mission-katina-phish-01.json`. This keeps the curated picker uncluttered while making every mission's coverage available in the instance.

**Domain note:** the enterprise per-mission layers, the enterprise per-domain coverage layer, and the curated aggregate above render in the standard **enterprise-attack** matrix (bundled 19.2). The **ICS/OT**, **Mobile**, and **ATLAS** mission layers are vendored too but render only where the matching matrix is available (the ATLAS layer needs the MITRE **ATLAS Navigator**; ICS/Mobile need their ATT&CK matrices) — they will not resolve against the bundled enterprise matrix.

## Adversary Emulation - Threat Groups (MITRE attribution)

| Layer | Techniques | Notes |
|---|---|---|
| Threat Group: APT29 (G0016) | 66 | APT29 (G0016) adversary emulation overlay: 66 MITRE-documented techniques |
| Threat Group: Volt Typhoon (G1017) | 81 | Volt Typhoon (G1017) adversary emulation overlay: 81 MITRE-documented techniques |
| Threat Group: Scattered Spider (G1015) | 64 | Scattered Spider (G1015) adversary emulation overlay: 64 MITRE-documented techniques |
| Threat Group: Lazarus Group (G0032) | 93 | Lazarus Group (G0032) adversary emulation overlay: 93 MITRE-documented techniques |
| Threat Group: Sandworm Team (G0034) | 79 | Sandworm Team (G0034) adversary emulation overlay: 79 MITRE-documented techniques |
| Threat Group: FIN7 (G0046) | 67 | FIN7 (G0046) adversary emulation overlay: 67 MITRE-documented techniques |
| Threat Group: Turla (G0010) | 68 | Turla (G0010) adversary emulation overlay: 68 MITRE-documented techniques |
| Threat Group: APT41 (G0096) | 82 | APT41 (G0096) adversary emulation overlay: 82 MITRE-documented techniques |
| Threat Group: Kimsuky (G0094) | 109 | Kimsuky (G0094) adversary emulation overlay: 109 MITRE-documented techniques |
| Threat Group: MuddyWater (G0069) | 58 | MuddyWater (G0069) adversary emulation overlay: 58 MITRE-documented techniques |
| Threat Group: TeamTNT (G0139) | 56 | TeamTNT (G0139) adversary emulation overlay: 56 MITRE-documented techniques |

## Analyst use-cases

- **Detection-gap analysis** - overlay a control/theme layer against your own coverage layer to find uncovered techniques.
- **Adversary emulation & purple teaming** - load a threat-group layer to scope an emulation plan or a tabletop around what that actor actually does.
- **Prioritization** - the HTB frequency and agentic-swarm layers highlight techniques that recur, useful for sequencing detection or hardening work.
- **Comparison** - switch between two group layers to see shared vs distinctive TTPs, or a group vs a theme to map an actor onto a weakness class.

## Adding a new layer

Layers are **data-only** at runtime. The approved program architecture makes the companion library the canonical source for all layers; migration of workbench-only layers and the vendoring script is planned, not yet implemented in this checkout. Do not create a competing canonical source while that migration is coordinated.

The current workbench ingestion contract is:

1. Drop a MITRE Navigator v4.5 layer JSON into `src/assets/data/library-layers/` (`domain: enterprise-attack`, a `techniques[]` array of `{ techniqueID, tactic, score, comment }`).
2. Append an entry to `index.json` with `file`, `name`, `description`, and `blurb`.
3. Ensure every `techniqueID` and tactic resolves in the bundled `enterprise-attack.json`; preserve cohort, method, version, and normalization metadata. No component change is needed just to list the layer: the picker enumerates the manifest at runtime.
4. Run `node scripts/validate-curated-threat-layers.mjs` and the relevant tests. Reconcile this guide with all manifest entries, counting unique IDs rather than tactic-expanded rows. Keep deterministic generators alongside their outputs in the canonical source; do not commit private source material or locators.

