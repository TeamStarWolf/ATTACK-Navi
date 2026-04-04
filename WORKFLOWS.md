# Analyst Workflow Guide

This guide describes eight operational workflows supported by the MITRE ATT&CK Navi. Each workflow follows a structured sequence of steps using the panels, heatmaps, and sidebar sections built into the application.

The Navigator is organized around a left-hand navigation rail with panels grouped into four sections: **Threats**, **Analysis**, **Coverage**, and **Tools**. The ATT&CK matrix is always visible behind any open panel, and the technique sidebar opens whenever a matrix cell is selected.

---

## Table of Contents

1. [Behavior Analysis](#1-behavior-analysis)
2. [Threat Intelligence](#2-threat-intelligence)
3. [Vulnerability Exposure](#3-vulnerability-exposure)
4. [Detection Coverage](#4-detection-coverage)
5. [Validation and Testing](#5-validation-and-testing)
6. [Compliance Mapping](#6-compliance-mapping)
7. [Coverage Analysis](#7-coverage-analysis)
8. [Reporting and Export](#8-reporting-and-export)

---

## 1. Behavior Analysis

**Purpose:** Understand adversary tactics, techniques, and procedures (TTPs) using the ATT&CK matrix as the primary navigation model.

### Overview

Behavior analysis is the starting point for every other workflow. The matrix displays all techniques organized by tactic columns (Initial Access through Impact). Selecting a technique opens the sidebar with full enrichment data. Threat group and campaign filters narrow the matrix to specific adversary profiles.

### Prerequisites

- ATT&CK data loaded (happens automatically on launch from MITRE STIX bundle)
- Domain selected (Enterprise, ICS, or Mobile)

### Steps

1. **Select the ATT&CK domain.** Use the domain selector in the toolbar to choose Enterprise, ICS, or Mobile. The matrix reloads with the corresponding STIX bundle. Enterprise is the default.

2. **Browse the matrix.** Scroll horizontally through tactic columns. Each cell represents a technique. Hover over a cell to see a tooltip with the technique ID, name, and summary scores. Click a cell to open the full technique sidebar.

3. **Search for techniques.** Use the search bar in the toolbar to filter techniques by name or ID. Toggle between name-only and full-text search scope. Enable search filter mode to dim non-matching techniques on the matrix.

4. **Explore the technique sidebar.** When a technique is selected, the sidebar opens with:
   - Technique name, ATT&CK ID, and description
   - Coverage score (weighted composite of mitigations, CAR, Atomic, D3FEND, and NIST data)
   - Signal summary pills (CVE count, EPSS score, Sigma rules, Atomic tests)
   - Collapsible sections for mitigations, threat groups, software, campaigns, procedures, data sources, and more

5. **Filter by threat group.** Open the **Threats** panel from the nav rail. Select one or more threat groups. The matrix highlights only the techniques used by those groups. This is the fastest way to scope an assessment to a specific adversary.

6. **Compare actors.** Open the **Actor vs.** panel to select two threat groups and see a side-by-side comparison of their technique usage, shared TTPs, and unique behaviors.

7. **Explore campaigns.** Open the **Campaigns** panel to browse ATT&CK campaigns on a timeline. Select a campaign to filter the matrix to its associated techniques.

8. **Inspect software.** Open the **Software** panel to see malware and tools mapped to techniques. Select a software item to highlight its technique footprint on the matrix.

9. **View the kill chain.** Open the **Kill Chain** panel for a linear progression view of selected techniques across the cyber kill chain phases.

### Expected Outputs

- A scoped understanding of which techniques are relevant to a particular adversary, campaign, or software family
- A filtered matrix view that can be shared via URL hash state or exported

### Related Panels

| Panel | Nav Rail ID | Purpose |
|-------|------------|---------|
| Dashboard | `dashboard` | Summary statistics and quick access |
| Threats | `threats` | Threat group selection and filtering |
| Actors | `actor` | Detailed actor profile view |
| Actor Compare | `actor-compare` | Side-by-side actor comparison |
| Campaigns | `campaign-timeline` | Campaign timeline browser |
| Software | `software` | Software/malware technique mapping |
| Kill Chain | `killchain` | Linear kill chain visualization |
| Scenario | `scenario` | Attack scenario builder |
| Graph | `technique-graph` | Technique relationship graph |

---

## 2. Threat Intelligence

**Purpose:** Correlate threat intelligence from external platforms (MISP, OpenCTI) with ATT&CK techniques to understand current adversary activity.

### Overview

The threat intelligence workflow connects the Navigator to live CTI sources. The Intelligence panel (INTEL) provides an overview of connected threat intelligence. MISP integration brings event-driven indicators and ATT&CK galaxy clusters. OpenCTI integration enriches techniques with structured threat data, confidence levels, and attribution.

### Prerequisites

- MISP server configured in Settings > Integrations (URL, API key, optional Org ID)
- OpenCTI instance configured in Settings > Integrations (URL, API token)
- At least one successful connection test for each platform

### Steps

1. **Open the Intelligence panel.** Click the **INTEL** item in the nav rail (under Threats). This panel aggregates intelligence from all connected sources and provides a unified overview.

2. **Review the intelligence overview.** The panel shows:
   - Connected source status (MISP, OpenCTI)
   - Recent events and indicators mapped to ATT&CK techniques
   - Technique coverage from intelligence sources

3. **Search for indicators.** Use the Search panel to query across all loaded data, including indicators from connected CTI platforms.

4. **Connect to MISP.** If not already connected, open Settings > Integrations. Enter the MISP server URL (e.g., `https://misp.example.org`), paste the API key, and optionally provide an Org ID. Click "Test & Save" to verify the connection.

5. **Browse MISP events.** Once connected, the sidebar shows MISP galaxy cluster data for selected techniques. MISP tags are displayed alongside ATT&CK technique metadata. Events tagged with ATT&CK technique IDs appear in the technique sidebar under the MISP section.

6. **Connect to OpenCTI.** In Settings > Integrations, enter the OpenCTI URL and API token. Click "Test & Save" to verify. The Navigator queries OpenCTI's GraphQL API for indicators and threat actors.

7. **Enrich techniques with OpenCTI data.** Once connected, the sidebar includes an OpenCTI section for each technique showing:
   - Linked indicators with confidence scores
   - Associated threat actors
   - Last-seen timestamps and provenance data

8. **Switch to the intelligence heatmap.** In the toolbar heatmap mode selector, choose "intelligence". The matrix colors techniques based on the volume and recency of threat intelligence data available.

9. **Use the Watchlist.** Open the **Watchlist** panel to track specific techniques of interest. Add techniques from the sidebar. The watchlist persists across sessions in localStorage.

### Expected Outputs

- Techniques enriched with current threat intelligence from MISP events and OpenCTI indicators
- An intelligence-driven heatmap showing which techniques have active reporting
- A curated watchlist of priority techniques based on live intel

### Related Panels

| Panel | Nav Rail ID | Purpose |
|-------|------------|---------|
| Intelligence | `intelligence` | Unified threat intelligence overview |
| Threats | `threats` | Threat group filtering |
| Actors | `actor` | Actor profile with CTI enrichment |
| Actor Compare | `actor-compare` | Compare actors across intel sources |
| Campaigns | `campaign-timeline` | Campaign timeline with intel context |
| Watchlist | `watchlist` | Tracked techniques of interest |
| Settings | `settings` | Configure MISP and OpenCTI connections |

---

## 3. Vulnerability Exposure

**Purpose:** Assess which ATT&CK techniques are associated with known vulnerabilities, active exploitation, and exploitation likelihood.

### Overview

The vulnerability exposure workflow uses CVE mappings, the CISA Known Exploited Vulnerabilities (KEV) catalog, and EPSS exploitation probability scores to quantify the real-world risk associated with each technique. The CVE panel provides search and filtering capabilities, while the sidebar shows per-technique vulnerability data.

### Prerequisites

- ATT&CK-to-CVE mapping data loaded (built-in)
- Optional: NVD API key configured in Settings > Integrations for higher rate limits

### Steps

1. **Open the CVE panel.** Click the **CVE** item in the nav rail (under Analysis). The panel lists all CVEs mapped to ATT&CK techniques.

2. **Search by technique.** Use the CVE panel search to find CVEs associated with a specific technique ID or name. Click a CVE entry to filter the matrix, highlighting only techniques linked to that vulnerability.

3. **Review the KEV catalog.** Techniques with CVEs listed in CISA's Known Exploited Vulnerabilities catalog are flagged. Switch to the "kev" heatmap mode to see which techniques have actively exploited vulnerabilities.

4. **Check EPSS scores.** The EPSS (Exploit Prediction Scoring System) provides a probability estimate for each CVE being exploited in the wild within the next 30 days. Switch to the "epss" heatmap mode to color techniques by their maximum EPSS score. In the sidebar, EPSS scores appear as pills next to each CVE.

5. **View ExploitDB and Nuclei counts.** The sidebar includes ExploitDB and Nuclei sections showing the number of public exploits and Nuclei templates available for each technique's associated CVEs. These indicate the practical availability of exploit code.

6. **Use the CVE heatmap.** Switch to "cve" heatmap mode to color the matrix by CVE count per technique. Techniques with more mapped vulnerabilities appear in warmer colors.

7. **Inspect CWE weakness families.** The sidebar CAPEC and CWE sections group vulnerabilities by weakness type, showing which attack patterns and weaknesses underlie each technique.

8. **Assess risk.** Open the **Risk** panel for a matrix-style risk assessment that combines vulnerability exposure with other factors.

### Expected Outputs

- A vulnerability-focused view of the ATT&CK matrix showing which techniques have known CVEs
- KEV and EPSS overlays identifying techniques with actively exploited or likely-to-be-exploited vulnerabilities
- Per-technique exploit availability counts from ExploitDB and Nuclei

### Related Panels

| Panel | Nav Rail ID | Purpose |
|-------|------------|---------|
| CVE | `cve` | CVE search and technique-CVE mapping |
| Risk Matrix | `risk-matrix` | Risk assessment combining multiple factors |
| Analytics | `analytics` | Statistical analysis including CVE distributions |
| Data Sources | `datasources` | Data source coverage for vulnerability detection |
| Settings | `settings` | NVD API key configuration |

---

## 4. Detection Coverage

**Purpose:** Measure the organization's detection readiness by mapping Sigma rules, Elastic detections, Splunk content, and CAR analytics against ATT&CK techniques.

### Overview

Detection coverage answers the question "can we see this technique?" The Navigator loads detection data from multiple rule repositories and displays coverage as matrix heatmaps. The Detection panel provides a consolidated view, while the Sigma and SIEM panels offer rule generation and export.

### Prerequisites

- Sigma rule data loaded (built-in Navigator layer from SigmaHQ)
- Elastic detection rules loaded (built-in)
- Splunk content loaded (built-in)
- CAR analytics loaded (built-in)

### Steps

1. **Check detection heatmaps.** Use the toolbar heatmap mode selector to cycle through detection overlays:
   - **sigma** -- Colors techniques by Sigma rule count from SigmaHQ
   - **elastic** -- Colors techniques by Elastic detection rule count
   - **splunk** -- Colors techniques by Splunk content pack coverage
   - **detection** -- Composite detection heatmap combining all sources
   - **car** -- Colors techniques by MITRE CAR analytic availability

2. **Open the Detection panel.** Click the **Detect** item in the nav rail (under Analysis). This panel shows:
   - Overall detection coverage percentage
   - Per-tactic detection rates
   - Techniques with no detection coverage (gaps)
   - Detection source breakdown

3. **Review per-technique detection.** Select any technique on the matrix. The sidebar Detection section shows:
   - Sigma rule count for this technique
   - Elastic rule count
   - Splunk content count
   - CAR analytics with descriptions
   - Data components that provide visibility

4. **Generate Sigma rules.** Open the **SIGMA** panel from the nav rail (under Tools). Select a technique to generate a template Sigma rule based on the technique's ATT&CK data sources and detection descriptions. Export the rule as YAML.

5. **Export SIEM queries.** Open the **SIEM** panel from the nav rail. Select a technique and target SIEM platform (Elastic, Splunk). The panel generates platform-specific query syntax that can be copied to the clipboard or exported.

6. **View data source coverage.** Open the **Sources** panel to see which ATT&CK data sources are covered by existing detections. Filter the matrix by data source to find techniques that depend on specific log sources.

### Expected Outputs

- A detection coverage heatmap identifying gaps in rule coverage across tactics
- Generated Sigma rules and SIEM queries for uncovered techniques
- A data source dependency map showing which log sources are most critical

### Related Panels

| Panel | Nav Rail ID | Purpose |
|-------|------------|---------|
| Detection | `detection` | Consolidated detection coverage view |
| Sigma | `sigma` | Sigma rule generation and export |
| SIEM | `siem` | SIEM query generation (Elastic/Splunk) |
| Data Sources | `datasources` | ATT&CK data source coverage |
| Analytics | `analytics` | Detection analytics and statistics |
| Graph | `technique-graph` | Technique relationship visualization |

---

## 5. Validation and Testing

**Purpose:** Plan red team exercises and purple team validation by reviewing available test procedures and generating detection signatures.

### Overview

Validation answers "can we test this?" and "can we prove our detections work?" The Navigator integrates Atomic Red Team test data, provides a purple team planning panel, and includes YARA and Suricata rule generation for creating validation signatures.

### Prerequisites

- Atomic Red Team data loaded (built-in Navigator layer; live test details fetched from GitHub on demand)
- ATT&CK data loaded

### Steps

1. **Review Atomic Red Team tests.** Select a technique on the matrix and expand the Atomic Red Team section in the sidebar. This shows:
   - Number of available Atomic tests
   - Test names and supported platforms (Windows, Linux, macOS)
   - A link to the full test YAML on GitHub
   - Live test details (fetched on demand) with executor commands and prerequisites

2. **Use the atomic heatmap.** Switch to "atomic" heatmap mode in the toolbar. The matrix colors techniques by the number of Atomic Red Team tests available. Uncovered techniques (no tests) are clearly visible as gaps.

3. **Open the Purple Team panel.** Click the **Purple** item in the nav rail (under Tools). This panel helps plan purple team exercises by:
   - Listing techniques with both detections and tests available
   - Identifying techniques where tests exist but detections are missing
   - Suggesting priority techniques for validation exercises

4. **Generate YARA rules.** Open the **YARA** panel from the nav rail. Select a technique or software family to generate YARA rule templates. Export the rules for file-based detection validation.

5. **Generate Suricata rules.** The YARA panel also supports Suricata rule generation for network-based detection validation scenarios.

6. **Plan attack scenarios.** Open the **Scenario** panel from the nav rail. Build multi-step attack scenarios by chaining techniques across tactics. This supports red team operation planning with a visual kill chain flow.

7. **Compare coverage.** Open the **Compare** panel to load two Navigator layers or saved views and compare them side by side. This is useful for comparing pre-exercise and post-exercise detection states.

### Expected Outputs

- A list of testable techniques with Atomic Red Team procedures
- Generated YARA and Suricata rules for detection validation
- A purple team exercise plan prioritized by detection gaps
- Attack scenarios for red team operations

### Related Panels

| Panel | Nav Rail ID | Purpose |
|-------|------------|---------|
| Purple Team | `purple` | Purple team planning and validation |
| YARA | `yara` | YARA and Suricata rule generation |
| Scenario | `scenario` | Attack scenario builder |
| Compare | `comparison` | Layer comparison for pre/post analysis |
| Detection | `detection` | Detection coverage context |
| Sigma | `sigma` | Sigma rule generation for blue team |

---

## 6. Compliance Mapping

**Purpose:** Map ATT&CK techniques to regulatory frameworks and security controls to support compliance assessments and audit preparation.

### Overview

The compliance workflow maps ATT&CK techniques to NIST 800-53 Rev5 controls, CRI Profile controls, CIS Controls, cloud provider controls, and VERIS action categories. This enables organizations to assess whether their control implementations address specific adversary behaviors.

### Prerequisites

- NIST 800-53 mapping data loaded (built-in)
- CRI Profile data loaded (built-in)
- Cloud controls data loaded (built-in)
- VERIS data loaded (built-in)

### Steps

1. **View the NIST 800-53 heatmap.** Switch to "nist" heatmap mode in the toolbar. The matrix colors techniques by the number of NIST 800-53 Rev5 controls mapped to each technique. Warmer colors indicate more control coverage.

2. **View the CRI Profile heatmap.** Switch to "cri" heatmap mode. The matrix colors techniques by CRI (Cyber Risk Institute) Profile control coverage.

3. **View the VERIS heatmap.** Switch to "veris" heatmap mode. The matrix colors techniques by VERIS (Vocabulary for Event Recording and Incident Sharing) action category mappings.

4. **View cloud controls.** Select a technique and expand the Cloud Controls section in the sidebar. This shows AWS, Azure, and GCP security controls that address the technique.

5. **Open the Compliance panel.** Click the **Comply** item in the nav rail (under Coverage). This panel provides:
   - A consolidated compliance coverage view across all frameworks
   - Per-framework coverage statistics
   - Techniques with no control coverage (compliance gaps)
   - Framework-specific drill-down

6. **Open the Controls panel.** Click the **Controls** item in the nav rail for a detailed view of all control mappings including:
   - NIST 800-53 controls with families and descriptions
   - D3FEND countermeasures
   - Engage activities
   - CIS Controls and implementation groups

7. **Review per-technique controls.** Select any technique and review the sidebar sections:
   - **NIST Controls** -- Mapped 800-53 controls with family groupings
   - **CRI Profile** -- CRI Profile controls
   - **Cloud Controls** -- AWS/Azure/GCP controls
   - **VERIS** -- VERIS action categories
   - **CIS Controls** -- CIS v8 control mappings

8. **Assess D3FEND countermeasures.** Switch to "d3fend" heatmap mode. The matrix shows MITRE D3FEND countermeasure coverage. The sidebar D3FEND section lists specific defensive techniques for each ATT&CK technique.

### Expected Outputs

- Compliance coverage heatmaps across NIST 800-53, CRI Profile, VERIS, and cloud frameworks
- A list of techniques with gaps in control coverage
- Per-technique control mappings for audit documentation

### Related Panels

| Panel | Nav Rail ID | Purpose |
|-------|------------|---------|
| Compliance | `compliance` | Consolidated compliance coverage |
| Controls | `controls` | Detailed control mappings |
| Priority | `priority` | Prioritized gap remediation |
| Target | `target` | Target profile for scoped assessments |
| Custom Mitigations | `custom-mit` | Organization-specific control mappings |

---

## 7. Coverage Analysis

**Purpose:** Understand overall mitigation coverage, identify gaps, track changes over time, and prioritize remediation efforts.

### Overview

Coverage analysis is the core analytical workflow. The default "coverage" heatmap shows how well each technique is mitigated. The gap view highlights uncovered techniques. The analytics panel provides radar charts and statistical breakdowns. The coverage diff panel compares two points in time.

### Prerequisites

- ATT&CK data loaded
- Optional: Implementation status tracked for mitigations (via sidebar or settings)
- Optional: Timeline snapshots saved for historical comparison

### Steps

1. **View the coverage heatmap.** The default heatmap mode is "coverage". Each technique cell is colored based on a weighted coverage score computed from:
   - ATT&CK mitigations (default weight: 40)
   - CAR analytics (default weight: 20)
   - Atomic Red Team tests (default weight: 15)
   - D3FEND countermeasures (default weight: 15)
   - NIST 800-53 controls (default weight: 10)

   The weights are configurable in Settings > Scoring Weights.

2. **Identify gaps.** Look for red or dark cells on the matrix -- these techniques have low or no coverage. Enable "Dim uncovered" in the toolbar to fade techniques with zero mitigations, making gaps stand out.

3. **Use the unified heatmap.** Switch to "unified" heatmap mode for a composite view that blends coverage, detection, and exposure data into a single color scale.

4. **Open the Analytics panel.** Click the **Analytics** item in the nav rail (under Analysis). This panel provides:
   - Coverage distribution histogram
   - Radar chart showing coverage dimensions (mitigations, detections, validation, controls, intelligence)
   - Per-tactic coverage percentages
   - Top covered and least covered techniques

5. **Compare coverage over time.** Open the **Diff** panel from the nav rail (under Coverage). Select two saved timeline snapshots to see which techniques gained or lost coverage. Added mitigations appear in green; removed ones appear in red.

6. **Save timeline snapshots.** Open the **Timeline** panel to save the current coverage state as a named snapshot. Snapshots are stored in localStorage and can be compared later using the Diff panel.

7. **Prioritize remediation.** Open the **Priority** panel from the nav rail. This panel ranks techniques by their coverage gap severity, factoring in exposure (CVE/KEV/EPSS data), detection state, and control coverage.

8. **Set a target profile.** Open the **Target** panel to define a target coverage profile. This establishes a goal state that the Priority panel uses for gap calculations.

9. **Run What-If analysis.** Open the **What-If** panel to simulate the impact of implementing specific mitigations. Select mitigations to see how coverage scores would change if they were fully deployed.

10. **Filter by implementation status.** Use the implementation status filter in the toolbar to show only techniques whose mitigations are in a specific state (implemented, in-progress, planned, not-started).

### Expected Outputs

- A clear picture of overall mitigation coverage and the most critical gaps
- A radar chart showing coverage balance across dimensions
- A prioritized remediation list ranked by risk and gap severity
- A timeline-based coverage diff showing improvement or regression

### Related Panels

| Panel | Nav Rail ID | Purpose |
|-------|------------|---------|
| Analytics | `analytics` | Statistical coverage analysis and radar chart |
| Priority | `priority` | Prioritized technique gap ranking |
| What-If | `whatif` | Mitigation simulation |
| Coverage Diff | `coverage-diff` | Compare two snapshots |
| Timeline | `timeline` | Save and manage coverage snapshots |
| Target | `target` | Target coverage profile |
| Watchlist | `watchlist` | Track specific techniques |
| Dashboard | `dashboard` | Summary statistics |

---

## 8. Reporting and Export

**Purpose:** Produce deliverables for stakeholders, compliance audits, and integration with other security tools.

### Overview

The reporting workflow covers all export capabilities: CSV and XLSX spreadsheets, HTML reports with organization branding, PNG matrix screenshots, Navigator-compatible JSON layers, STIX bundles, and Sigma/YARA rule exports. The Report panel is the central hub for document generation.

### Prerequisites

- ATT&CK data loaded
- Optional: Organization name configured in Settings > Organization
- Optional: Filters and heatmap configured to scope the export

### Steps

1. **Open the Report panel.** Click the **Report** item in the nav rail (under Tools). This panel provides export options for all supported formats.

2. **Export to CSV.** Generate a comma-separated file of all techniques with their coverage scores, mitigation counts, implementation status, and CVE data. This is useful for spreadsheet analysis and importing into other tools.

3. **Export to XLSX.** Generate a formatted Excel workbook with multiple sheets covering techniques, mitigations, implementation status, and coverage statistics. The XLSX export includes conditional formatting.

4. **Generate an HTML report.** Create a self-contained HTML report that includes:
   - Organization name and generation date (from Settings)
   - Executive summary with coverage statistics
   - Technique-by-technique coverage detail
   - Heatmap visualization
   - Mitigation recommendations

5. **Export as PNG.** Capture the current matrix view as a PNG image. The export respects the current heatmap mode, filters, and dim settings, producing an accurate visual snapshot.

6. **Generate Navigator layers.** Open the **Layers** panel to create ATT&CK Navigator-compatible JSON layer files. These can be imported into the official MITRE ATT&CK Navigator or shared with other teams.

7. **Create STIX bundles.** Export technique and mitigation data as STIX 2.1 bundles for interoperability with CTI platforms and threat intelligence sharing.

8. **Export implementation status.** In Settings > Data, click "Export Implementation CSV" to export the current mitigation implementation status as a CSV file.

9. **Export Sigma rules.** From the Sigma panel, export generated Sigma rules as YAML files for import into SIEM platforms.

10. **Export YARA/Suricata rules.** From the YARA panel, export generated rules for file and network detection tooling.

11. **Share via URL.** The application encodes the current filter state (heatmap mode, threat group filters, mitigation filters, search query, platform filter, and more) in the URL hash. Copy the URL to share a specific view with colleagues.

### Expected Outputs

- CSV/XLSX spreadsheets for data analysis and record-keeping
- Branded HTML reports for management and compliance
- PNG screenshots for presentations and documentation
- Navigator JSON layers for tool interoperability
- STIX bundles for CTI platform integration
- Sigma/YARA rule files for security engineering

### Related Panels

| Panel | Nav Rail ID | Purpose |
|-------|------------|---------|
| Report | `report` | Central export hub |
| Layers | `layers` | Navigator layer management |
| Sigma | `sigma` | Sigma rule export |
| SIEM | `siem` | SIEM query export |
| YARA | `yara` | YARA/Suricata rule export |
| Compare | `comparison` | Layer comparison and merge |
| Settings | `settings` | Organization branding and data export |
| Changelog | `changelog` | Track changes for audit trails |

---

## Cross-Workflow Reference

### All Navigation Panels

| Group | Panel | ID | Heatmap Modes |
|-------|-------|----|---------------|
| -- | Dashboard | `dashboard` | -- |
| -- | Search | `search` | -- |
| Threats | Threats | `threats` | -- |
| Threats | Actors | `actor` | -- |
| Threats | Actor Compare | `actor-compare` | -- |
| Threats | Scenario | `scenario` | -- |
| Threats | Campaigns | `campaign-timeline` | campaign |
| Threats | Software | `software` | software |
| Threats | Intelligence | `intelligence` | intelligence |
| Analysis | Kill Chain | `killchain` | -- |
| Analysis | Risk Matrix | `risk-matrix` | risk |
| Analysis | Analytics | `analytics` | -- |
| Analysis | Detection | `detection` | detection |
| Analysis | Graph | `technique-graph` | -- |
| Analysis | Data Sources | `datasources` | -- |
| Analysis | CVE | `cve` | cve, kev, epss |
| Coverage | Controls | `controls` | controls, d3fend, engage |
| Coverage | Compliance | `compliance` | nist, cri, veris |
| Coverage | Priority | `priority` | -- |
| Coverage | What-If | `whatif` | -- |
| Coverage | Timeline | `timeline` | -- |
| Coverage | Coverage Diff | `coverage-diff` | -- |
| Coverage | Target | `target` | -- |
| Coverage | Watchlist | `watchlist` | -- |
| Tools | Sigma | `sigma` | sigma |
| Tools | SIEM | `siem` | elastic, splunk |
| Tools | YARA | `yara` | -- |
| Tools | Purple Team | `purple` | atomic |
| Tools | Layers | `layers` | -- |
| Tools | Compare | `comparison` | -- |
| Tools | Custom Mitigations | `custom-mit` | -- |
| Tools | Tags | `tags` | -- |
| Tools | Roadmap | `roadmap` | -- |
| Tools | Changelog | `changelog` | -- |
| Tools | Report | `report` | -- |
| Bottom | Settings | `settings` | -- |

### All Heatmap Modes

| Mode | Description |
|------|-------------|
| `coverage` | Weighted mitigation coverage score (default) |
| `exposure` | Vulnerability exposure composite |
| `status` | Implementation status of mitigations |
| `controls` | Control mapping density |
| `software` | Software/malware usage frequency |
| `campaign` | Campaign association count |
| `risk` | Composite risk score |
| `kev` | CISA Known Exploited Vulnerabilities |
| `d3fend` | D3FEND countermeasure coverage |
| `atomic` | Atomic Red Team test availability |
| `engage` | MITRE Engage activity coverage |
| `car` | MITRE CAR analytic coverage |
| `cve` | CVE count per technique |
| `detection` | Composite detection coverage |
| `frequency` | Technique usage frequency across groups |
| `cri` | CRI Profile control coverage |
| `unified` | Blended multi-factor heatmap |
| `sigma` | Sigma rule count |
| `nist` | NIST 800-53 control count |
| `veris` | VERIS action category mapping |
| `epss` | EPSS exploitation probability |
| `elastic` | Elastic detection rule count |
| `splunk` | Splunk content pack coverage |
| `intelligence` | Threat intelligence data density |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `/` or `Ctrl+K` | Focus search bar |
| `Esc` | Close sidebar or active panel |
| `D` | Toggle dim uncovered |
| `?` | Show keyboard help |

### URL State Parameters

The current filter state is encoded in the URL hash for sharing:

| Parameter | Description |
|-----------|-------------|
| `mit` | Active mitigation filter ATT&CK IDs |
| `tq` | Technique search query |
| `pf` | Platform filter |
| `plat` | Multi-platform filter |
| `dim` | Dim uncovered flag (1/0) |
| `sfm` | Search filter mode (1/0) |
| `ds` | Data source filter |
| `heat` | Heatmap mode |
| `impl` | Implementation status filter |
| `scope` | Search scope (name/full) |
| `tsearch` | Technique search |
| `grp` | Active threat group ATT&CK IDs |
| `sw` | Active software ATT&CK IDs |
| `camp` | Active campaign ATT&CK IDs |
