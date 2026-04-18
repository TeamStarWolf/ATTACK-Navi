# ATTACK-Navi Roadmap

## Current State (April 2026)

- 50+ components, 45+ services, 25 heatmap modes
- 4.5M CVE mappings across 163 ATT&CK techniques
- Live integrations: ATT&CK STIX, CTID, CISA KEV, EPSS, NVD, Elastic, Splunk, Sigma, MISP, OpenCTI, M365 Defender, ExploitDB, Nuclei, Atomic Red Team
- STIX 2.1 import/export, custom technique editing, collection sharing
- PWA, Docker, Helm, GitHub Pages with daily rebuild
- 220+ unit tests, 9 E2E tests, 0 vulnerabilities

---

## Tier 1: Highest Impact (Next Sprint)

### 1.1 Real-Time Alert Correlation Engine
**Why**: The app shows static coverage â€” but defenders need to correlate live alerts against ATT&CK in real time.
- Ingest Syslog/CEF/JSON events via WebSocket or polling
- Map incoming alerts to ATT&CK techniques using Sigma rule matching
- "Active Threats" heatmap showing which techniques are firing NOW
- Timeline view: alert â†’ technique â†’ tactic chain visualization
- Alert fatigue scoring: suppress low-confidence repeat alerts

### 1.2 Asset Inventory + CVE Exposure Scoring
**Why**: 4.5M CVE mappings are useless without knowing which products YOU run.
- Import asset inventory (CSV: hostname, OS, software, version)
- Match assets against CVE CPE strings
- Per-technique exposure score: "3 of your servers run vulnerable Apache"
- "My Exposure" heatmap mode showing only YOUR risk, not theoretical
- Priority queue: techniques sorted by (your assets) Ã— (EPSS) Ã— (KEV)

### 1.3 Detection Gap Analysis Report
**Why**: CISOs need a one-page answer to "where are we blind?"
- Auto-generate a detection gap report comparing:
  - Techniques used by your selected threat actors
  - vs. techniques with Sigma/Elastic/Splunk/M365 detection rules
  - vs. techniques with mitigations implemented
- RAG (Red/Amber/Green) status per tactic
- Exportable as PDF/XLSX for board presentations
- Scheduled weekly email via GitHub Actions

---

## Tier 2: High Impact (Next Month)

### 2.1 Collaborative Workspaces
**Why**: Security teams need to share annotations, not just export files.
- Firebase or Supabase backend (optional, free tier)
- Shared workspace: team members see the same annotations, statuses, custom techniques
- Role-based access: admin, analyst, viewer
- Activity log: "Alice marked T1059 as implemented on March 3"
- Conflict resolution for simultaneous edits

### 2.2 SIEM Query Library
**Why**: Sigma export is good but analysts need ready-to-paste queries for their SIEM.
- Pre-built query library per technique for: Splunk SPL, Elastic KQL, Microsoft KQL, CrowdStrike LogScale, Chronicle YARA-L
- "Copy to clipboard" per SIEM
- Query effectiveness scoring (maps to detection data sources)
- Community-contributed queries (via GitHub PRs)

### 2.3 Threat Actor Emulation Plans
**Why**: Purple teams need step-by-step playbooks, not just technique lists.
- For each threat actor: ordered sequence of techniques (kill chain flow)
- Per-step: Atomic Red Team test command, expected detection, expected log source
- Caldera/SCYTHE integration: export as adversary profile
- "Run Emulation" mode: step through the plan with pass/fail checkboxes

### 2.4 Compliance Framework Mapper
**Why**: Map ATT&CK coverage directly to audit evidence.
- SOC 2 Type II control mapping
- ISO 27001 Annex A control mapping
- PCI DSS v4.0 requirement mapping
- Auto-generate evidence artifacts: "Control X.Y is addressed by mitigations for techniques T1059, T1078, T1190"
- Compliance score dashboard

---

## Tier 3: Medium Impact (Next Quarter)

### 3.1 Machine Learning Threat Prediction
- Train a model on historical ATT&CK usage patterns
- Predict: "Based on APT29's recent campaigns, they're likely to add T1059.001 next"
- Trending techniques visualization (which techniques are gaining adoption)
- "Emerging Threats" heatmap mode

### 3.2 Integration Marketplace
- Plugin architecture for custom data sources
- Standard interface: `{ loaded$, total$, covered$, getScoreForTechnique() }`
- Community-contributed integrations via npm packages
- Config UI for enabling/disabling integrations

### 3.3 Multi-Domain Comparison
- Side-by-side Enterprise vs ICS vs Mobile matrices
- Cross-domain technique mapping (shared techniques highlighted)
- "Which ICS techniques overlap with our Enterprise detections?"

### 3.4 Incident Response Playbooks
- Per-technique response procedures
- Containment, eradication, recovery steps
- Integration with ticketing (Jira, ServiceNow) via webhooks
- Post-incident ATT&CK mapping: tag an incident with techniques used

---

## Tier 4: Nice to Have (Future)

### 4.1 Browser Extension
- Right-click any CVE/technique ID on any webpage â†’ view in ATTACK-Navi
- Highlight ATT&CK technique IDs on threat intel blog posts
- Quick-add to watchlist from any page

### 4.2 Mobile Native App
- React Native or Capacitor wrapper
- Offline-first with IndexedDB sync
- Push notifications for new KEV entries

### 4.3 AI-Powered Analysis
- "Describe your environment" â†’ auto-suggest priority techniques
- Natural language queries: "Show me credential theft techniques targeting Windows AD"
- Auto-summarize technique coverage in plain English for executives

### 4.4 Gamification / Training Mode
- "Coverage Challenge": achieve 80% mitigation coverage across all tactics
- Technique quiz: "Which tactic does T1059 belong to?"
- Team leaderboard for implementation progress
- CTF integration: map CTF challenges to ATT&CK techniques

---

## Technical Debt

| Item | Priority | Effort |
|------|----------|--------|
| Increase test coverage to 80%+ | High | Medium |
| Code splitting per panel (lazy routes) | High | Medium |
| Replace remaining hardcoded data with live feeds (D3FEND, Engage, CAR) | Medium | Low |
| Migrate from Karma to Jest (faster tests) | Medium | Low |
| Add Storybook for component documentation | Low | Medium |
| Internationalization (i18n) framework | Low | High |
| ~~Migrate inline nav-rail template to separate files~~ âœ… | Low | Low |
| ~~Add Docker build and smoke-test CI workflow~~ ✅ | Low | Low |
| Add OpenTelemetry for performance monitoring | Low | Medium |

---

## Quick Wins (< 1 Hour Each)

- [x] Add "Copy as Markdown" button for technique details
- [x] Add CSV import for bulk implementation status
- [x] Add "Technique of the Day" random highlight
- [x] Add matrix zoom to fit viewport button
- [x] Add print stylesheet optimization
- [x] Add technique count badges on tactic headers
- [x] Add "Share this technique" button (URL with technique pre-selected)
- [x] Add changelog panel auto-update notification
