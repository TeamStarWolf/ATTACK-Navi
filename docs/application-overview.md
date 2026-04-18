# ATTACK-Navi Application Overview

## What It Is

ATTACK-Navi is a browser-based cybersecurity workbench built on top of the MITRE ATT&CK framework. The application is designed to help analysts move from a technique-centric view into richer operational questions: what is covered, what is exposed, what intelligence is relevant, and what evidence exists for detection or control depth.

The project is intentionally broader than a traditional ATT&CK Navigator layer viewer. It treats the ATT&CK matrix as the entry point to a multi-surface analysis environment rather than the final product.

## Primary Workflows

### 1. Coverage review

Analysts can use ATTACK-Navi to review mitigation coverage, implementation status, control mappings, and data-source depth at the tactic and technique level. This is the closest workflow to a classic ATT&CK assessment, but the app pushes beyond color-coding by exposing sidebars, comparisons, and export surfaces.

### 2. Threat-intelligence correlation

The intelligence workflow connects ATT&CK techniques to groups, campaigns, software, MISP events, and OpenCTI indicators. The goal is to help an analyst answer "who uses this technique and what supporting evidence do we have?" without leaving the matrix context.

### 3. Exposure analysis

Exposure workflows map ATT&CK techniques to CVE, KEV, EPSS, ExploitDB, Nuclei, and CWE-derived evidence. This allows ATT&CK techniques to be used as a navigation layer for vulnerability review instead of keeping exposure data in a disconnected list.

### 4. Detection validation

Detection workflows combine Sigma, Elastic, Splunk, Atomic Red Team, CAR, and related sources so an analyst can judge how measurable or testable a technique is. This makes ATTACK-Navi useful for both detection engineering and purple-team preparation.

### 5. Reporting and sharing

ATTACK-Navi is also built to turn interactive analysis into artifacts. The app supports CSV, XLSX, HTML, PNG, state export, and Navigator-layer export so teams can preserve or circulate findings outside the live UI.

## Experience Priorities

- keep ATT&CK as the organizing model while still allowing deep pivots into adjacent evidence
- make dense information navigable without requiring a backend for the core experience
- be honest about which data is live, which is bundled, and which is derived from mappings
- preserve shareability through URL state, exports, and reusable saved views

## Runtime Model

The primary application is a static Angular SPA that can run on GitHub Pages or any similar static host. Most core data is fetched client-side from public sources or bundled assets.

There is also an optional backend proxy under `server/` for environments that do not want browser clients holding OpenCTI or MISP credentials directly. That split matters operationally:

- static deployment is enough for ATT&CK browsing, mappings, and most public-source workflows
- the proxy becomes important when secret-backed integrations move from experimentation into production use

## Current Strengths

- broad ATT&CK-centered surface area across coverage, exposure, detection, and intelligence
- strong technique detail panels and multi-panel analyst workflows
- large amount of export and reporting support for review and handoff
- useful public demo value because the core app still works without private infrastructure

## Current Limits

- some mappings are only as strong as the upstream datasets and may be partial
- secure integrations need careful deployment choices when real secrets are involved
- breadth is a strength, but it also means documentation has to work harder to explain how the panels fit together

## Related Docs

| Document | Purpose |
| --- | --- |
| [README](../README.md) | Public landing page and feature overview |
| [Architecture](../ARCHITECTURE.md) | Angular component, service, and state walkthrough |
| [Workflows](../WORKFLOWS.md) | Analyst workflow descriptions by use case |
| [Data Source Scorecard](../DATA_SOURCE_SCORECARD.md) | Integration depth and source quality snapshot |
| [Security](../SECURITY.md) | Deployment and vulnerability-reporting guidance |

---

## Community Context

ATTACK-Navi is part of the [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) public resource library. Each discipline page in that library describes how ATTACK-Navi fits into a practitioner's workflow for that area, alongside learning paths, free training, and tooling recommendations.

| If you are working on... | See this discipline page |
|---|---|
| Threat intelligence and adversary tracking | [Threat Intelligence](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/threat-intelligence.md) |
| Detection rule development and SIEM coverage | [Detection Engineering](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/detection-engineering.md) |
| Active incident investigation | [Incident Response](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/incident-response.md) |
| Red team and adversary emulation planning | [Offensive Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/offensive-security.md) |
| Vulnerability prioritization and CVE analysis | [Vulnerability Management](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/vulnerability-management.md) |
| Cloud attack surface and container security | [Cloud Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/cloud-security.md) |
| Network monitoring and C2 detection | [Network Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/network-security.md) |
| Malware behavior and capability mapping | [Malware Analysis](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/malware-analysis.md) |
| Industrial control system and OT threats | [ICS/OT Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/ics-ot-security.md) |
| Web application and API security | [Application Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/application-security.md) |
| AI/LLM red teaming and AI-enabled attacks | [AI & LLM Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/ai-llm-security.md) |
