<!-- ATTACK-Navi - Copyright (c) 2026 TeamStarWolf - MIT License -->
# Library Layers Guide

**Library layers** are curated MITRE ATT&CK Navigator overlays bundled with ATTACK-Navi. Select one from the **Library Layers** picker in the matrix controls and the workbench colors each technique cell by that layer's score, letting you see a theme, a data-driven frequency, or a specific adversary's documented behavior projected onto the ATT&CK matrix. This build ships **26 layers**.

## How to use them

- Open the **Library Layers** section of the matrix controls and pick a layer; the matrix recolors immediately.
- **Cell color = score.** For curated layers, score encodes a membership tier (core vs supporting). For the frequency layer, score is a normalized count. For threat-group layers, every colored cell is a documented technique (score 100).
- Layers are **overlays for exploration**, not authoritative coverage claims. Switch layers to compare, e.g. overlay a threat group, then a control theme, to reason about gaps.
- The picker reads `src/assets/data/library-layers/index.json` at runtime, so the set grows without any code change.

## Reading the scores & provenance

| Layer type | Score meaning | Source |
|---|---|---|
| Curated theme / weakness | Membership tier (core = 100, supporting = 55) or membership-only | TeamStarWolf reference library + validated against bundled ATT&CK data. **Not** an official MITRE mapping. |
| HTB Technique Frequency | Normalized machine count (100 = most frequent technique) | Analysis of the owner's own HTB writeups (technique metadata only). Reflects HTB teaching bias, not enterprise prevalence. |
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

## Campaign & Behavior (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Ransomware TTPs | 14 | Follows common ransomware intrusion themes through access, credential theft, movement, exfiltration, encryption, and recovery inhibition |

## Cross-Tactic Technique Themes (curated)

| Layer | Techniques | Notes |
|---|---|---|
| Living-off-the-Land (LOTL) | 59 | Signed/legitimate binaries, interpreters, and admin tooling abused across execution, evasion, movement, and exfiltration |
| Phishing & Social Engineering | 36 | Lure delivery, user execution, and account/MFA abuse enabling human-targeted initial access |
| Supply Chain & Trusted-Relationship Compromise | 36 | Third-party, software/hardware supply-chain, and trusted-relationship intrusion paths |
| Data Collection & Exfiltration | 47 | Collection, staging/packaging, and egress channels for data theft |
| Credential Theft & Abuse | 64 | Dumping, cracking, store/file harvesting, ticket/token theft, and credential reuse |

## Frequency Analysis

| Layer | Techniques | Notes |
|---|---|---|
| HTB Technique Frequency | 131 | Shows normalized technique counts from the supplied analysis of the user's own 131 HTB machines |

## AI & Emerging Threats

| Layer | Techniques | Notes |
|---|---|---|
| Agentic AI Swarm Intrusion | 74 | Enterprise ATT&CK frequency across a generalized agentic-AI-swarm kill chain: credential reuse, egress-relay C2, pipeline exploitation, and cluster takeover |

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

Layers are **data-only**. To add one:

1. Drop a MITRE Navigator v4.5 layer JSON into `src/assets/data/library-layers/` (`domain: enterprise-attack`, a `techniques[]` array of `{ techniqueID, tactic, score, comment }`).
2. Append an entry to `index.json` with `file`, `name`, `description`, and `blurb`.
3. Ensure every `techniqueID` resolves in the bundled `enterprise-attack.json`. No component or test changes are needed - the picker enumerates the manifest at runtime.

