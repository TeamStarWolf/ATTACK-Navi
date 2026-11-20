# Analyst Workflow Guide

This guide describes eight operational workflows ATT&CK-Navi supports. Each one is a
sequence of steps through the app's **routed workspaces**, the **heatmap lenses** that
recolor the matrix, and the **technique sidebar**.

## Getting around

The app is a single-page app with **hash routing**: every destination has its own URL, so
bookmarks and the browser's back/forward buttons work. There are three ways to move:

- **Left rail.** The rail groups the workspaces into three sections — **Threat & Exposure**
  (Matrix, Exposure, Intel), **Response** (Detect, Coverage) and **Reference** (Dashboard,
  Reports, Library, Status) — with **Help** and **Settings** pinned at the bottom and a
  **viewpoint** selector (Analyst by default) at the top. Click a workspace, then its tab.
- **Command palette.** `Ctrl+K` (`Cmd+K` on macOS) searches techniques, groups, actors,
  software, campaigns and CVEs, and has "Go to" entries for every workspace tab.
- **Direct URL.** Each tab has a path, e.g. `#/exposure/gap-analysis` or `#/intel/groups`.

The ATT&CK **matrix** lives at `#/matrix`. Selecting any matrix cell opens the **technique
sidebar** (its jump index groups the sections into Technique, Threat Intel, Vulnerabilities,
Compliance, Detections, Offense & Hunting and Workspace), from any workspace.

**Lenses.** The matrix toolbar has a lens button that shows the active lens's short label
(the default lens is **Frequency**, framed as adversary prevalence) and opens a menu to
recolor the matrix. With no viewpoint set the menu groups are Threat Landscape,
Vulnerabilities, Detections, Frameworks and Coverage & Posture; the complete list of all 36
lenses, their scores and rungs is in [docs/HEATMAPS.md](docs/HEATMAPS.md) (and the
authoritative count is the Heatmap modes row of [docs/FACTS.md](docs/FACTS.md)). Every lens
carries a rung (KNOWN, COVERED self-attested, THREAT, EXPOSURE or PROVEN) shown as its
legend badge; read a color from the legend, not the color alone.

**Domains.** The toolbar's domain selector switches between Enterprise (default), ICS,
Mobile and the CTID F3 Fraud Framework. Enterprise ATT&CK is bundled at the pinned version
shown on the toolbar's vintage chip.

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

**Purpose:** Understand adversary tactics, techniques and procedures (TTPs) using the
ATT&CK matrix as the primary navigation model.

### Steps

1. **Select the domain.** Use the domain selector in the toolbar (Enterprise, ICS, Mobile
   or F3). The matrix reloads with that domain's techniques, grouped into tactic columns.
2. **Browse the matrix** at `#/matrix`. Each cell is a technique; techniques with
   sub-techniques show a chevron to expand them (`Ctrl+E` expands all). Hover for a quick
   tooltip; click a cell to open the technique sidebar.
3. **Read the sidebar.** The jump index lists the populated sections by group — Technique
   (mitigations, sub-techniques, data sources, procedures, relationship graph), Threat
   Intel (groups, software, campaigns, MISP, OpenCTI), and so on. The "Reference sources
   mapped" card is a Known count of how many public sources map the technique.
4. **Scope to a threat group.** Open **Intel > Groups** (`#/intel/groups`), select one or
   more ATT&CK groups, and the matrix highlights the techniques they use. Each group row
   shows its technique count and a mitigation-mapped percentage (reference data, not
   deployed defense).
5. **Compare adversaries.** Open **Intel > Compare** (`#/intel/compare`) to put two groups
   side by side and see shared vs. distinctive techniques.
6. **Explore campaigns and software.** **Intel > Campaigns** (`#/intel/campaigns`) browses
   ATT&CK campaigns on a timeline; **Intel > Software** (`#/intel/software`) maps malware
   and tools to techniques. Selecting one filters the matrix to its techniques.
7. **See relationships and progression.** **Exposure > Graph** (`#/exposure/graph`) draws a
   technique relationship graph; **Exposure > Kill Chain** (`#/exposure/kill-chain`) lays
   selected techniques out across kill-chain phases.

### Expected outputs

- A scoped view of which techniques matter for a chosen adversary, campaign or software
  family, shareable via the Share button (the URL carries the filter state).

---

## 2. Threat Intelligence

**Purpose:** Correlate threat-intelligence signals with ATT&CK techniques to see where
adversary reporting concentrates.

### Steps

1. **Open the Intel workspace** at `#/intel`. Its tabs are Groups, Actors, Compare,
   Scenarios, Emulation, Campaigns, Software and **Feeds**.
2. **Review the intelligence overview.** **Intel > Feeds** (`#/intel/feeds`) is the threat
   intelligence panel, with Intel Overview, Indicators, Threat Actors and MISP Events tabs.
   Its per-technique signal score is the number of ATT&CK groups that use the technique,
   plus one when MISP Galaxy has a cluster for it.
3. **Color the matrix by intel.** Switch to the **Intelligence** lens from the lens menu
   (Threat Landscape group) to shade techniques by that signal.
4. **(Optional) Connect MISP.** The public MISP Galaxy ATT&CK clusters load with no setup
   and appear in the sidebar's MISP section. To add a server, open **Settings >
   Preferences > Integrations**, enter the MISP URL and API key, and click **Test & Save**.
   Live MISP event and attribute queries are not yet wired to the UI (the MISP Events tab
   builds templates locally).
5. **(Optional) Connect OpenCTI.** In the same Integrations tab, enter the OpenCTI URL and
   API token and Test & Save; indicators then appear in the sidebar and in Intel > Feeds.
6. **Track techniques of interest.** Add techniques to **Library > Watchlist**
   (`#/library/watchlist`); the watchlist persists in the browser.

### Expected outputs

- Techniques enriched with threat-group, MISP Galaxy and (if configured) OpenCTI signals,
  an intelligence-driven matrix view, and a watchlist of priority techniques.

---

## 3. Vulnerability Exposure

**Purpose:** Assess which techniques are tied to known vulnerabilities, active exploitation
and exploitation likelihood.

### Steps

1. **Open the Exposure workspace** at `#/exposure`. Tabs: CVE, Risk, Kill Chain, Graph, Gap
   Analysis, Priority, SSVC, Dossier, What-If, CTEM.
2. **Search CVEs.** **Exposure > CVE** (`#/exposure/cve`) has Search (NVD lookup by CVE ID
   or keyword), a KEV Dashboard, By Technique, CTID Curated, a Timeline, Products and CVSS
   Analytics views.
3. **Overlay exploitation on the matrix.** From the lens menu (Vulnerabilities group),
   switch to **KEV** (CISA Known Exploited Vulnerabilities count), **CVE** (CVE count per
   technique), **EPSS** (average exploitation probability), **CVE Kill Chain** or **PoC
   Exploits**.
4. **Read per-technique vulnerability data** in the sidebar: CVE and KEV links, EPSS
   scores, and the CAPEC, ExploitDB, Nuclei and PoC Exploits sections (counts of public
   exploit and template availability).
5. **Prioritize by risk.** **Exposure > Risk** (`#/exposure/risk`) plots techniques by
   threat exposure against security gap in four quadrants; **Exposure > Priority**
   (`#/exposure/priority`) ranks techniques by gap severity; **Exposure > SSVC**
   (`#/exposure/ssvc`) and **Exposure > CTEM** (`#/exposure/ctem`) add decision and
   exposure-management views; **Exposure > Dossier** (`#/exposure/dossier`) opens a
   per-technique CVE dossier.

### Expected outputs

- A vulnerability-focused matrix with KEV/EPSS overlays, per-technique exploit-availability
  counts, and a risk-ranked priority list. Exports are available from the CVE tab.

---

## 4. Detection Coverage

**Purpose:** Measure detection readiness by mapping public detection content against ATT&CK
techniques.

### Steps

1. **Open the Detect workspace** at `#/detect`. Tabs: Detections, Sigma, SIEM, YARA,
   Validation, Data Sources, Purple Team.
2. **Review consolidated coverage.** **Detect > Detections** (`#/detect/detections`) shows
   how many techniques have reference content mapped (CAR, Atomic, D3FEND) with a
   "Reference depth" breakdown and Overview / Gaps views — reference data, not your
   deployed detections.
3. **Overlay detection content on the matrix** from the lens menu (Detections group):
   **Detection content available** (a weighted composite), **Sigma Rules**, **Elastic
   Rules**, **Splunk Detections**, **Wazuh stock rules (curated)**, **M365 Defender**,
   **CAR** and **Atomic**. The Elastic, Splunk and community-Sigma counts come from a
   bundled rule-coverage snapshot (reference data about public repositories).
4. **Read per-technique detection content** in the sidebar: the **Rule sources** section
   (Elastic, Splunk and mdecrevoisier Sigma rule counts and names at a pinned commit), CAR
   Detection Analytics, and Detected By (the ATT&CK data components that provide visibility).
5. **Generate detection content.** **Detect > Sigma** (`#/detect/sigma`) generates template
   Sigma rules; **Detect > SIEM** (`#/detect/siem`) generates platform query syntax; both
   export from their tab.
6. **Check data-source coverage.** **Detect > Data Sources** (`#/detect/data-sources`) shows
   which ATT&CK data sources existing detections depend on.

### Expected outputs

- A detection-coverage matrix identifying gaps, generated Sigma/SIEM starting points, and a
  data-source dependency view.

---

## 5. Validation and Testing

**Purpose:** Plan adversary emulation and purple-team validation, and record what you have
tested.

### Steps

1. **Review Atomic tests.** Select a technique and open the Atomic Red Team section in the
   sidebar (test names, platforms, and live YAML test detail fetched on demand). Switch to
   the **Atomic** lens to color the matrix by test availability.
2. **Plan a purple-team exercise.** **Detect > Purple Team** (`#/detect/purple-team`) pairs
   techniques that have both tests and detections against those that have tests but no
   detection.
3. **Record validation runs.** **Detect > Validation** (`#/detect/validation`) is where you
   log a validation run by hand, each with an outcome and evidence links. These are
   self-recorded, not an automated result; a named detection that fired or a block on a
   recorded date is what the Proven lens reads.
4. **Generate file/network signatures.** **Detect > YARA** (`#/detect/yara`) generates YARA
   (and Suricata) rule templates to export.
5. **Build attack scenarios.** **Intel > Scenarios** (`#/intel/scenarios`) simulates a
   chosen group's attack against your current coverage; **Intel > Emulation**
   (`#/intel/emulation`) builds an emulation plan.
6. **Compare before and after.** **Library > Comparison** (`#/library/comparison`) loads two
   Navigator layers or saved views side by side.

### Expected outputs

- A list of testable techniques, generated YARA/Suricata rules, a purple-team plan, recorded
  validation runs, and emulation scenarios.

---

## 6. Compliance Mapping

**Purpose:** Map techniques to control frameworks to support compliance assessment and audit
preparation.

### Steps

1. **Open the Coverage workspace** at `#/coverage`. Tabs: Assessment, Controls, Custom
   Mitigations, Compliance, Diff, Timeline, Target, Assets.
2. **Overlay a framework on the matrix** from the lens menu (Frameworks group): **NIST
   800-53**, **VERIS Actions**, **CRI Profile**, **CSA CCM**, **M365 Controls**, **D3FEND**,
   **Engage** or **F3 Origin**.
3. **Review per-technique controls** in the sidebar's Compliance group: NIST 800-53, CRI
   Profile, VERIS, CSA CCM and Cloud Controls (AWS/Azure/GCP). Control mappings come from
   the CTID Mappings Explorer and are matched on the technique IDs as published (see the
   note on version skew in [README.md](README.md#data-sources)).
4. **See consolidated compliance coverage.** **Coverage > Compliance**
   (`#/coverage/compliance`) gives per-framework coverage and compliance gaps.
5. **Manage control mappings.** **Coverage > Controls** (`#/coverage/controls`) lists the
   control-to-technique mappings; **Coverage > Custom Mitigations**
   (`#/coverage/custom-mitigations`) adds organization-specific mitigations.

### Expected outputs

- Compliance-coverage matrices across the mapped frameworks, a list of techniques with no
  control coverage, and per-technique control mappings for audit documentation.

> **CIS Controls** are not available: CTID removed them from Mappings Explorer as of ATT&CK
> v16, so that source loads empty.

---

## 7. Coverage Analysis

**Purpose:** Understand mitigation coverage and your own recorded posture, identify gaps,
track change over time and prioritize remediation.

### Steps

1. **Run an assessment.** **Coverage > Assessment** (`#/coverage/assessment`) is a five-step
   wizard: select the ATT&CK domain, choose the threat groups relevant to your sector, and
   set an implementation status for each technique. The results show how many techniques you
   marked Implemented or In Progress, a coverage percentage, a threat-weighted gap (0–100), a
   tactic breakdown and the top priority gaps — self-attested, not validated. Export
   Assessment (CSV) saves them.
2. **Shade the matrix by your input.** From the lens menu (Coverage & Posture group), the
   **Status** lens shows the implementation status you set, **Controls** the controls you
   declare, **Posture**, **Covered (self-attested or range)** and **Proven** show your
   recorded posture, and **Mitigations mapped** / **Reference depth** show reference data.
   Enable "Dim uncovered" to fade techniques with no coverage.
3. **Analyze.** **Dashboard > Analytics** (`#/dashboard/analytics`) gives coverage
   distribution, a radar chart across dimensions, and per-tactic percentages;
   **Dashboard > Overview** (`#/dashboard/overview`) summarizes.
4. **Prioritize and target.** **Coverage > Priority** (`#/coverage/priority`) ranks gaps by
   severity; **Coverage > Target** (`#/coverage/target`) defines a target profile the
   priority ranking measures against.
5. **Model changes.** **Exposure > What-If** (`#/exposure/what-if`) simulates the effect of
   implementing specific mitigations on your coverage scores.
6. **Track over time.** **Coverage > Timeline** (`#/coverage/timeline`) saves coverage
   snapshots; **Coverage > Diff** (`#/coverage/diff`) compares two snapshots to show what
   gained or lost coverage.
7. **Scope to assets.** **Coverage > Assets** (`#/coverage/assets`) imports a host inventory
   (CSV) and, in its Exposure tab, colors the matrix by which techniques reach your assets
   (the My Exposure lens — a reachability view, not a posture rung).

### Expected outputs

- A coverage picture and prioritized remediation list, a target profile, what-if estimates,
  and a timeline diff showing improvement or regression.

---

## 8. Reporting and Export

**Purpose:** Produce deliverables for stakeholders, audits and interoperability with other
tools.

### Steps

1. **Open the Reports workspace** at `#/reports`. Tabs: Report Builder, IR Playbooks, Export
   Hub.
2. **Build a report.** **Reports > Report Builder** (`#/reports/builder`) assembles the
   mitigation report (executive summary, coverage framed as Known/Theoretical with no claim
   about your environment); use **⚙ Sections** to choose sections, **⬇ Export CSV**, or **🖨
   Print / Save PDF**.
3. **Use the Export Hub.** **Reports > Export Hub** (`#/reports/exports`) collects the
   exports in six groups: Coverage Data (Coverage CSV, Tactic Summary, Implementation Plan,
   Excel Workbook), Reports (Full Report, HTML Report, PDF Report, Print Matrix, Matrix
   PNG), ATT&CK Navigator (Export, Open in, Import), Workspace State (Export/Import State),
   Saved Layers, and Full Workspace Backup (Export/Import Workspace).
4. **Produce IR playbooks.** **Reports > IR Playbooks** (`#/reports/playbooks`) builds
   incident-response playbooks.
5. **Share STIX and layers.** STIX 2.1 bundle import/export is in **Library > Collections**
   (`#/library/collections`); saved Navigator layers are in **Library > Layers**
   (`#/library/layers`) and the Export Hub.
6. **Export detection content** from its own Detect tab — Sigma (`#/detect/sigma`), SIEM
   (`#/detect/siem`) and YARA/Suricata (`#/detect/yara`).
7. **Share a view.** The Share button copies the current URL, which encodes the filter state
   (lens, filters, selected groups/software/campaigns and more). The selected technique is
   not in the Share link, but an incoming `tech=` parameter selects one.

### Expected outputs

- CSV/XLSX spreadsheets, branded HTML and PDF reports, a matrix PNG, Navigator JSON layers,
  STIX bundles, IR playbooks, and generated detection rules.

---

## Reference

### Workspaces and tabs

| Workspace | Route | Tabs |
| :-- | :-- | :-- |
| Matrix | `#/matrix` | none (the grid, lens picker, filters and sidebar) |
| Exposure | `#/exposure` | CVE, Risk, Kill Chain, Graph, Gap Analysis, Priority, SSVC, Dossier, What-If, CTEM |
| Intel | `#/intel` | Groups, Actors, Compare, Scenarios, Emulation, Campaigns, Software, Feeds |
| Detect | `#/detect` | Detections, Sigma, SIEM, YARA, Validation, Data Sources, Purple Team |
| Coverage | `#/coverage` | Assessment, Controls, Custom Mitigations, Compliance, Diff, Timeline, Target, Assets |
| Dashboard | `#/dashboard` | Overview, Analytics |
| Reports | `#/reports` | Report Builder, IR Playbooks, Export Hub |
| Library | `#/library` | Workbench, Layers, Collections, Comparison, Roadmap, Watchlist, Tags |
| Status | `#/status` | none (source health and data freshness) |
| Settings | `#/settings` | Preferences, Changelog |

This table and the tab paths are derived from the routes; the authoritative count of
workspaces and tabs is in [docs/FACTS.md](docs/FACTS.md).

### Lenses

The lens button recolors the matrix. The 36 lenses, grouped into Threat Landscape,
Vulnerabilities, Detections, Frameworks and Coverage & Posture, are documented in full —
each with its score, rung and color ramp — in [docs/HEATMAPS.md](docs/HEATMAPS.md). The
default is the Frequency (Prevalence) lens.

### Keyboard shortcuts

Press `?` in the app for the full list. Common ones: `Ctrl+K` (command palette), `Ctrl+F`
(focus the matrix search), `Ctrl+E` (expand all sub-techniques), `m` (go to the Matrix),
`c` (clear filters), `Esc` (close the palette/help, otherwise deselect).

### URL state

Filter state is encoded in the URL hash as router query params, e.g.
`#/matrix?heat=sigma&grp=G0007`. The parameters are listed in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md#10-url-state).
