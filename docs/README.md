# ATTACK-Navi Docs Index

This folder and the root technical documents together form the project handbook for ATTACK-Navi.

If you are new to the repo, start in this order:

1. [README](../README.md)
2. [Application Overview](application-overview.md)
3. [Architecture](../ARCHITECTURE.md)
4. [Workflows](../WORKFLOWS.md)
5. [Data Source Scorecard](../DATA_SOURCE_SCORECARD.md)
6. [Heatmaps](HEATMAPS.md)
7. [Services](SERVICES.md)
8. [Components](COMPONENTS.md)
9. [Configuration](CONFIGURATION.md)
10. [Security](../SECURITY.md)

## Documentation Map

### Product and analyst workflows

- [Application Overview](application-overview.md)
  Product-level summary of the app, its strongest workflows, and its current boundaries.
- [Workflows](../WORKFLOWS.md)
  End-to-end analyst paths across behavior, intelligence, exposure, detection, validation, and defense.
- [Data Source Scorecard](../DATA_SOURCE_SCORECARD.md)
  Status of live, bundled, and planned data integrations.
- [Mappings Cheat Sheet](../MAPPINGS_CHEAT_SHEET.md)
  Quick reference for ATT&CK-adjacent mapping systems and terminology.

### Architecture and implementation

- [Architecture](../ARCHITECTURE.md)
  State management, component orchestration, and data-loading patterns.
- [Heatmaps](HEATMAPS.md)
  Heatmap intent, scoring behavior, and mode-specific notes.
- [Services](SERVICES.md)
  Service responsibilities, integration helpers, and runtime data roles.
- [Components](COMPONENTS.md)
  Component-level notes for the Angular UI surface.
- [Configuration](CONFIGURATION.md)
  Local settings, deployment knobs, and integration setup details.

### Operations and contribution

- [Security](../SECURITY.md)
  Deployment posture, vulnerability reporting, and integration safety guidance.
- [Contributing](../CONTRIBUTING.md)
  Development setup and contributor expectations.
- [Server README](../server/README.md)
  Optional backend proxy notes for OpenCTI and MISP secret handling.
- [Open Source Integrations](../OPEN_SOURCE_INTEGRATIONS.md)
  Expansion ideas for future integrations and adjacent tooling.

## Quick Orientation

ATTACK-Navi is strongest when it is used as an analysis surface rather than a static ATT&CK viewer:

- compare coverage and control depth across tactics
- pivot from techniques into threat groups, campaigns, software, and indicators
- connect exposure evidence and detection content to specific ATT&CK techniques
- export findings into review-ready artifacts

## Documentation Standards

When adding new docs:

- describe current behavior before describing future intent
- distinguish live data from bundled or derived data
- call out partial coverage honestly when a mapping or integration is incomplete
- keep workflow and panel names consistent with the running application

---

## Community Learning Resources

ATTACK-Navi is maintained by [TeamStarWolf](https://github.com/TeamStarWolf), a public cybersecurity resource library. The discipline pages below provide learning paths, free training, tools, certifications, and guidance for each major area of practice. ATTACK-Navi is referenced throughout each page as the recommended ATT&CK analysis surface for that discipline.

| Discipline | How ATTACK-Navi applies |
|---|---|
| [Threat Intelligence](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/threat-intelligence.md) | Threat group filters, campaign timelines, MISP/OpenCTI correlation, and STIX export |
| [Detection Engineering](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/detection-engineering.md) | Sigma rule coverage, Elastic/Splunk detection counts, Atomic Red Team test mapping, and CAR analytics |
| [Incident Response](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/incident-response.md) | Technique-to-TTP pivot during active investigations; ATT&CK coverage gap analysis post-incident |
| [Offensive Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/offensive-security.md) | ATT&CK technique mapping for red team operations; CVE/EPSS correlation for exploitation planning |
| [Vulnerability Management](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/vulnerability-management.md) | CVE-to-technique overlays, EPSS scores, CISA KEV indicators, and ExploitDB cross-reference |
| [Cloud Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/cloud-security.md) | Cloud technique clusters in ATT&CK; detection and compliance coverage for cloud-specific TTPs |
| [Network Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/network-security.md) | Command-and-Control, Lateral Movement, and Exfiltration technique analysis with detection coverage |
| [Malware Analysis](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/malware-analysis.md) | Map observed malware capabilities to ATT&CK techniques; correlate with threat group attribution |
| [ICS/OT Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/ics-ot-security.md) | ICS ATT&CK matrix domain; visualize OT-specific techniques, adversary emulation in industrial environments |
| [Application Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/application-security.md) | Initial Access and Execution technique mapping; connect web exploitation to the full ATT&CK kill chain |
| [AI & LLM Security](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/disciplines/ai-llm-security.md) | ATTACK-Navi as an example of AI-assisted ATT&CK analysis; maps AI-enabled attack techniques across the matrix |

Visit the [TeamStarWolf profile](https://github.com/TeamStarWolf/TeamStarWolf) for the full resource library including books, starred repositories, YouTube channels, and follow lists.
