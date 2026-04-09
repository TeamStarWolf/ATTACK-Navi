# Starred Project Integration Analysis

> Analysis of 30 starred GitHub repositories + 200+ additional repos from 18 authors/orgs, mapped to ATTACK-Navi integration opportunities.
> Generated: April 2026

---

## Overview

TeamStarWolf has 30 starred repositories across cybersecurity domains. We investigated all repos by every author/org behind those stars — totaling 200+ public repos across 18 GitHub accounts. This document ranks all discovered integration candidates.

---

## P0 — Implemented

These integrations are **already built and deployed** on the `claude/analyze-starred-projects-ogveP` branch:

| Integration | Source Repo | Stars | What It Does |
|---|---|---|---|
| **CVE2CAPEC Kill Chain** | `Galeax/CVE2CAPEC` | 286 | Full CVE→CWE→CAPEC→ATT&CK→D3FEND chain per technique. New `kill-chain` heatmap mode + sidebar section. |
| **PoC Exploit Enrichment** | `trickest/cve` | 7,675 | Flags techniques with public proof-of-concept exploits. New `poc-exploits` heatmap mode + sidebar section. |

**Files added/modified:** 12 files, 551 lines — 2 new services, wired into all 7 standard touchpoints.

---

## P1 — High-Value Integration Candidates (Next)

### 1. TTPMapper — AI-Driven Threat Intel Parser
- **Repo:** `infosecn1nja/TTPMapper` (52★, Python)
- **What:** Uses LLMs to parse threat intelligence reports into ATT&CK TTPs automatically
- **Integration:** Import threat reports → auto-highlight techniques on the matrix
- **Effort:** Medium — needs backend/API for LLM processing
- **Roadmap alignment:** Tier 4.3 "AI-Powered Analysis"

### 2. Community Sigma Rules
- **Repo:** `mdecrevoisier/SIGMA-detection-rules` (423★)
- **What:** 350+ production-ready Sigma rules mapped to ATT&CK, organized by product (Windows, Exchange, AD, SQL)
- **Integration:** Merge counts into existing `sigma.service.ts` — supplementary detection coverage
- **Effort:** Low — same YAML format, parse `tags` for technique IDs

### 3. EVTX Samples + Event Log Mindmap
- **Repos:** `mdecrevoisier/EVTX-to-MITRE-Attack` (621★) + `Microsoft-eventlog-mindmap` (1,092★)
- **What:** 270+ EVTX samples mapped to ATT&CK + comprehensive Windows event log reference
- **Integration:** New sidebar section: "EVTX Samples" showing which techniques have real event log evidence. New heatmap: "Event Log Coverage"
- **Effort:** Low-Medium — parse directory structure (tactic/technique folders) for counts

### 4. Caldera Adversary Profile Export
- **Repo:** `mitre/caldera` (6,876★)
- **What:** Export technique selections as Caldera YAML adversary profiles for automated emulation
- **Integration:** New export button: "Export as Caldera Profile" generating YAML with `phases` and `technique.attack_id`
- **Effort:** Low — client-side YAML generation, no external fetch needed
- **Roadmap alignment:** Tier 2.3 "Threat Actor Emulation Plans"

### 5. Anthropic Cybersecurity Skills
- **Repo:** `mukul975/Anthropic-Cybersecurity-Skills` (4,151★)
- **What:** 754 structured skills mapped to ATT&CK (291 techniques), NIST CSF, D3FEND, ATLAS, AI RMF
- **Integration:** Ingest `mappings/attack-navigator-layer.json` for heatmap + link individual SKILL.md files in sidebar
- **Effort:** Low — Navigator layer ingestion follows existing pattern

### 6. SysmonTools — Telemetry Mapping
- **Repo:** `nshalabi/SysmonTools` (1,635★, TypeScript)
- **What:** Sysmon configuration visualization and ATT&CK technique mapping
- **Integration:** Map Sysmon event types to ATT&CK data sources, show "Sysmon Coverage" in sidebar
- **Effort:** Medium

### 7. Sentinel ATT&CK Detection Rules
- **Repo:** `edoardogerosa/sentinel-attack` (1,081★)
- **What:** Azure Sentinel hunting queries and workbooks mapped to ATT&CK
- **Integration:** Import Sentinel detection rule counts into existing M365/Sentinel integration
- **Effort:** Low — extends existing `m365-defender.service.ts`

### 8. ThreatHunter Playbook
- **Repo:** `OTRF/ThreatHunter-Playbook` (4,527★)
- **What:** Detection notebooks with `attack_navigator.json` layer + `analytic_summary.csv` index
- **Integration:** Ingest Navigator layer for heatmap + link playbook notebooks per technique in sidebar
- **Effort:** Low — Navigator layer + external links

---

## P2 — Strong Complementary Value

### 9. Security Datasets
- **Repo:** `OTRF/Security-Datasets` (1,733★, PowerShell)
- **What:** Replay-able security event datasets for detection validation
- **Integration:** Sidebar link: "Test Dataset Available" per technique

### 10. EDR Bypass Catalog
- **Repo:** `tkmru/awesome-edr-bypass` (1,513★)
- **What:** Curated EDR bypass resources mapping to Defense Evasion techniques
- **Integration:** "Known Bypass" indicator on detection rules, helping analysts understand detection gaps

### 11. OWASP OpenCRE — Cross-Standard Compliance
- **Repo:** `OWASP/OpenCRE` (151★, Python)
- **What:** Maps between NIST, CIS, OWASP, CWE, CAPEC standards bidirectionally
- **Integration:** Enrich compliance mapper with cross-standard links
- **Roadmap alignment:** Tier 2.4 "Compliance Framework Mapper"

### 12. DeTT&CT Coverage Mapping
- **Repo:** `siriussecurity/dettectinator` (118★, Python)
- **What:** Python library for DeTT&CT YAML — standardizes data source coverage tracking
- **Integration:** Import/export DeTT&CT YAML format for detection coverage

### 13. Zeek ATT&CK Detection (bzar)
- **Repo:** `mitre-attack/bzar` (622★, Zeek)
- **What:** Zeek scripts detecting ATT&CK techniques at network level
- **Integration:** New sidebar section: "Zeek Detections" showing network-level coverage

### 14. MITRE Heimdall2 — Compliance Scan Viewer
- **Repo:** `mitre/heimdall2` (248★, HTML)
- **What:** View/compare InSpec security control scan results
- **Integration:** Import Heimdall JSON results to auto-populate compliance coverage

### 15. Secondary PoC Source
- **Repo:** `0xMarcio/cve` (1,208★, Python)
- **What:** Latest CVEs with PoC exploit links — secondary source to trickest/cve
- **Integration:** Merge into `poc-exploit.service.ts` as fallback data source

### 16. Official CVE List
- **Repo:** `CVEProject/cvelistV5` (2,582★)
- **What:** Authoritative CVE data in JSON 5 format
- **Integration:** Use as primary CVE data source alongside NVD

### 17. OWASP Threat Dragon
- **Repo:** `OWASP/threat-dragon` (1,376★, JavaScript)
- **What:** Open-source threat modeling tool
- **Integration:** Export ATT&CK selections as threat model inputs

---

## P3 — Niche / Reference Value

| Repo | Stars | Use Case |
|---|---|---|
| `infosecn1nja/Red-Teaming-Toolkit` | 10,230 | Reference: red team tool catalog |
| `infosecn1nja/AD-Attack-Defense` | 4,811 | Reference: AD attack/defense techniques |
| `infosecn1nja/awesome-mitre-attack` | 618 | Reference: curated ATT&CK resource links |
| `mitre-attack/attack-navigator` | 2,353 | Reference: layer format compatibility |
| `mitre-attack/attack-stix-data` | 552 | Already consumed via DataService |
| `OTRF/ATTACK-Python-Client` | 568 | Python STIX client (we use JS) |
| `OTRF/Microsoft-Sentinel2Go` | 589 | Lab deployment (not data feed) |
| `mukul975/Privacy-Data-Protection-Skills` | 43 | Privacy compliance skills |
| `JohnHammond/active_directory` | 127 | AD technique references |
| `mitre/saf` | 174 | Security Automation Framework CLI |
| `CVEProject/cve-services` | 237 | CVE API specification |
| `stanislav-web/OpenDoor` | 917 | Recon tool (T1595) |
| `ebranca/owasp-pysec` | 413 | Python security (stale since 2021) |

---

## Author Repo Summary

| Author/Org | Public Repos | Relevant Repos | Highlights |
|---|---|---|---|
| **mitre** | 559 | 5 | caldera, heimdall2, saf |
| **mitre-attack** | 19 | 5 | car, bzar, attack-navigator, attack-stix-data |
| **OTRF** | 30 | 5 | ThreatHunter-Playbook, Security-Datasets, ATTACK-Python-Client |
| **OWASP** | 1,355 | 3 | OpenCRE, threat-dragon, CheatSheetSeries |
| **mukul975** | 29 | 2 | Anthropic-Cybersecurity-Skills, Privacy-Data-Protection-Skills |
| **infosecn1nja** | 30+ | 4 | TTPMapper, Red-Teaming-Toolkit, AD-Attack-Defense |
| **mdecrevoisier** | 11 | 5 | SIGMA-rules, EVTX-to-MITRE-Attack, Microsoft-eventlog-mindmap, Splunk-baseline |
| **CVEProject** | 26 | 3 | cvelistV5, cve-schema, cve-services |
| **trickest** | 26 | 3 | cve, find-gh-poc, wordlists |
| **nshalabi** | 8 | 2 | SysmonTools, ATTACK-Tools |
| **edoardogerosa** | 12 | 2 | sentinel-attack, pockint |
| **siriussecurity** | 5 | 3 | dettectinator, mitre-attack-mapping |
| **Galeax** | 7 | 1 | CVE2CAPEC |
| **JohnHammond** | 73 | 2 | active_directory, vbe-decoder |
| **tkmru** | 99 | 1 | awesome-edr-bypass |
| **0xMarcio** | 37 | 1 | cve |
| **stanislav-web** | 40 | 1 | OpenDoor |
| **ebranca** | 2 | 1 | owasp-pysec (stale) |

**Total repos scanned:** 200+ across 18 accounts
**Integration candidates identified:** 32 repos across 4 priority tiers
