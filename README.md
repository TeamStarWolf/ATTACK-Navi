# ATT&CK NAV

**Live Site: [https://ccwilliams314.github.io/attack-nav/](https://ccwilliams314.github.io/attack-nav/)**

An Angular 19 application for exploring MITRE ATT&CK techniques, analyzing mitigation coverage, tracking implementation status, and correlating threat intelligence across 20+ cybersecurity frameworks and data sources.

## Features

### Core
- Interactive ATT&CK matrix with Enterprise, ICS, and Mobile domains
- 24 heatmap visualization modes (coverage, risk, EPSS, KEV, Sigma, Elastic, Splunk, Intelligence, and more)
- Mitigation coverage analysis with implementation tracking
- Threat group, software, campaign, platform, and data source filtering

### Threat Intelligence
- Unified TIP panel combining MISP + OpenCTI + ATT&CK intel
- Live MISP server connection (configurable) with Galaxy cluster data
- OpenCTI GraphQL integration for indicators and threat actors
- Intelligence heatmap showing signal density per technique

### Vulnerability & Exposure
- CVE-to-ATT&CK mappings (CTID + NVD bulk precomputation)
- CISA KEV catalog integration with ransomware indicators
- EPSS exploitation probability scores
- 708-entry CWE catalog with ATT&CK technique mapping
- ExploitDB public exploit counts per technique
- Nuclei scan template counts per technique

### Detection & Defense
- Sigma rule counts (SigmaHQ live Navigator layer)
- Elastic Detection Rules integration
- Splunk Security Content integration
- CAR analytics, D3FEND countermeasures, MITRE Engage
- Zeek, Suricata, and YARA template generation

### Compliance & Controls
- NIST 800-53 Rev5 control mappings
- CIS Controls v8
- CRI Profile controls
- AWS, Azure, GCP cloud security controls
- VERIS incident action framework

### Analysis & Reporting
- Radar chart (coverage polygon across 14 tactics)
- Kill chain analysis, risk matrix, technique graph
- Campaign timeline, actor comparison, scenario simulation
- Technique completeness scoring (0-100 from 13 data sources)
- Data source health ribbon (15+ service status indicators)
- Export to CSV, XLSX, HTML, PNG, JSON, ATT&CK Navigator layers

### UX
- 35+ nav rail panels
- Collapsible sidebar sections with expand-relevant
- Dark theme with responsive layout
- URL hash state persistence and sharing
- Keyboard shortcuts

## Getting Started

```bash
npm install
npx ng serve
```

Open `http://localhost:4200/`.

## Build

```bash
npx ng build
```

## Tech Stack

- Angular 19.2 with standalone components
- RxJS 7.8 for reactive state management
- TypeScript 5.7
- OnPush change detection throughout

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — Component architecture and data flow
- [WORKFLOWS.md](WORKFLOWS.md) — Workflow model across ATT&CK, intel, exposure, detection, validation, defense
- [DATA_SOURCE_SCORECARD.md](DATA_SOURCE_SCORECARD.md) — Integration status and priorities
- [MAPPINGS_CHEAT_SHEET.md](MAPPINGS_CHEAT_SHEET.md) — Mapping systems reference
- [OPEN_SOURCE_INTEGRATIONS.md](OPEN_SOURCE_INTEGRATIONS.md) — Integration roadmap
