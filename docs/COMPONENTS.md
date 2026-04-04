# Component Catalog

> Auto-generated reference for all 50 Angular components in the MITRE ATT&CK Mitigation Navigator.
> Each component is standalone, uses `ChangeDetectionStrategy.OnPush`, and lives under `src/app/components/`.

---

## Quick Reference Table

| # | Selector | Category | Panel ID | Purpose |
|---|----------|----------|----------|---------|
| 1 | `app-root` | Shell | -- | Application root; orchestrates layout and domain loading |
| 2 | `app-toolbar` | Shell | -- | Top toolbar with search, filters, heatmap picker, and export actions |
| 3 | `app-nav-rail` | Shell | -- | Left-side vertical navigation rail with panel launchers |
| 4 | `app-stats-bar` | Shell | -- | Coverage statistics bar beneath the toolbar |
| 5 | `app-matrix` | Matrix | -- | Full ATT&CK matrix grid rendering all tactic columns |
| 6 | `app-technique-cell` | Matrix | -- | Single technique cell with heatmap coloring and status indicators |
| 7 | `app-technique-tooltip` | Matrix | -- | Hover tooltip showing technique summary on mouseover |
| 8 | `app-legend` | Matrix | -- | Dynamic heatmap legend that updates with the active mode |
| 9 | `app-filter-chips` | Matrix | -- | Active-filter chip bar with one-click removal |
| 10 | `app-quick-filters` | Matrix | -- | Preset filter buttons (No Mitigation, KEV Exposed, etc.) |
| 11 | `app-gap-view` | Matrix | -- | Modal overlay listing all uncovered techniques grouped by tactic |
| 12 | `app-tactic-summary` | Matrix | -- | Popover card showing tactic-level stats on header click |
| 13 | `app-sidebar` | Sidebar | -- | Right-side detail panel for a selected technique |
| 14 | `app-threat-panel` | Threat Intel | `threats` | Threat group and campaign browser with coverage gaps |
| 15 | `app-threat-intelligence-panel` | Threat Intel | `intelligence` | Aggregated MISP + OpenCTI intelligence overview |
| 16 | `app-actor-profile-panel` | Threat Intel | `actor` | Deep-dive profile for a single threat actor |
| 17 | `app-actor-compare-panel` | Threat Intel | `actor-compare` | Side-by-side comparison of two threat actors |
| 18 | `app-scenario-panel` | Threat Intel | `scenario` | Attack simulation scoring a group against current defenses |
| 19 | `app-campaign-timeline-panel` | Threat Intel | `campaign-timeline` | Gantt-style campaign timeline with group color coding |
| 20 | `app-software-panel` | Threat Intel | `software` | Malware and tool browser with technique overlay |
| 21 | `app-analytics-panel` | Analysis | `analytics` | Executive analytics dashboard with tactic stats and top gaps |
| 22 | `app-killchain-panel` | Analysis | `killchain` | Kill-chain view with per-tactic coverage, group counts, and averages |
| 23 | `app-risk-matrix-panel` | Analysis | `risk-matrix` | Threat-vs-gap scatter plot with quadrant classification |
| 24 | `app-detection-panel` | Analysis | `detection` | Detection coverage combining CAR, Atomic, D3FEND, and Sigma |
| 25 | `app-technique-graph-panel` | Analysis | `technique-graph` | Force-directed relationship graph for a technique |
| 26 | `app-datasource-panel` | Analysis | `datasources` | MITRE data-source and data-component browser |
| 27 | `app-cve-panel` | Analysis | `cve` | CVE search, CISA KEV browser, and technique-to-CVE mapping |
| 28 | `app-controls-panel` | Coverage | `controls` | Security controls manager (NIST, CIS, ISO, Custom) |
| 29 | `app-compliance-panel` | Coverage | `compliance` | Multi-framework compliance matrix (NIST, CIS, CRI, AWS, Azure, GCP) |
| 30 | `app-priority-panel` | Coverage | `priority` | Mitigation priority ranker by unique coverage, exposure, KEV, and more |
| 31 | `app-whatif-panel` | Coverage | `whatif` | What-if analysis simulating new mitigation deployments |
| 32 | `app-timeline-panel` | Coverage | `timeline` | Coverage snapshot timeline with trend and comparison views |
| 33 | `app-coverage-diff-panel` | Coverage | `coverage-diff` | Side-by-side snapshot comparison with tactic-level deltas |
| 34 | `app-target-panel` | Coverage | `target` | Target coverage planner computing the shortest path to a % goal |
| 35 | `app-watchlist-panel` | Coverage | `watchlist` | Technique watchlist with priority levels and analyst notes |
| 36 | `app-sigma-export` | Tools | `sigma` | Sigma rule export with mode selection and YAML preview |
| 37 | `app-siem-export` | Tools | `siem` | Multi-SIEM export (Splunk, Sentinel, Elastic, Suricata, Zeek) |
| 38 | `app-yara-export` | Tools | `yara` | YARA rule export with technique-based filtering |
| 39 | `app-purple-team-panel` | Tools | `purple` | Purple-team readiness scorer (D3FEND + Engage + CAR + Atomic) |
| 40 | `app-layers-panel` | Tools | `layers` | ATT&CK Navigator layer save, load, and import/export |
| 41 | `app-comparison-panel` | Tools | `comparison` | Group-vs-group technique overlap comparison |
| 42 | `app-custom-mit-panel` | Tools | `custom-mit` | Custom mitigation CRUD with technique mapping |
| 43 | `app-tags-panel` | Tools | `tags` | Tag manager for technique tagging and bulk operations |
| 44 | `app-roadmap-panel` | Tools | `roadmap` | Auto-generated quarterly implementation roadmap |
| 45 | `app-report-panel` | Tools | `report` | Executive summary report with export to clipboard/HTML |
| 46 | `app-changelog-panel` | Tools | `changelog` | ATT&CK release changelog viewer |
| 47 | `app-settings-panel` | Settings | `settings` | Application settings (scoring weights, theme, integrations) |
| 48 | `app-keyboard-help` | Utility | -- | Keyboard shortcut reference overlay (toggle with `?`) |
| 49 | `app-data-health` | Utility | -- | Inline data-source health ribbon (loaded/loading/failed dots) |
| 50 | `app-dashboard-panel` | Utility | `dashboard` | Executive dashboard with KPIs, tactic bars, and trend data |
| -- | `app-universal-search` | Utility | `search` | Global search across techniques, mitigations, groups, and more |

---

## 1. Shell Components

These components form the application frame and are always visible.

### AppComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-root` |
| **File** | `src/app/app.component.ts` |
| **Purpose** | Root component that bootstraps the layout. Loads the ATT&CK domain, wires the toolbar, matrix, sidebar, nav-rail, stats-bar, and all panel components together. Manages the light/dark theme toggle and global keyboard shortcuts (`Escape` to close panels, `?` for help). |
| **Key I/O** | None (root component) |

---

### ToolbarComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-toolbar` |
| **File** | `src/app/components/toolbar/toolbar.component.ts` |
| **Purpose** | Top-of-page toolbar providing technique search, mitigation dropdown filter, platform pills, heatmap mode picker (24 modes), sort/dim toggles, saved views, and a comprehensive export menu (CSV, XLSX, PNG, HTML report, Navigator layer, implementation plan). |
| **Inputs** | `mitigations: Mitigation[]`, `techniques: Technique[]`, `isLightMode: boolean`, `currentDomain: AttackDomain`, `multiSelectMode: boolean`, `activePlatforms: Set<string>` |
| **Outputs** | `domainChange`, `expandAll`, `collapseAll`, `toggleMultiSelect`, `exportCsv`, `exportTacticCsv`, `exportImplPlan`, `exportState`, `importState`, `exportNavigatorLayer`, `importNavigatorLayer`, `openNavigator`, `exportFullReport`, `exportMatrixPng`, `exportHtmlReport`, `exportXlsx`, `showGapView`, `toggleDark`, `copyShareLink` |

---

### NavRailComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-nav-rail` |
| **File** | `src/app/components/nav-rail/nav-rail.component.ts` |
| **Purpose** | Fixed left-side vertical navigation rail. Organizes 37+ panel launchers into five groups (Threats, Analysis, Coverage, Tools) plus a bottom-pinned Settings button. Emits panel toggle events to open/close side panels. |
| **Inputs** | `activePanel: string \| null` |
| **Outputs** | `panelToggle: EventEmitter<string>`, `focusSearch: EventEmitter<void>` |

---

### StatsBarComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-stats-bar` |
| **File** | `src/app/components/stats-bar/stats-bar.component.ts` |
| **Purpose** | Horizontal statistics bar showing total techniques, covered count, coverage percentage, implemented percentage, and per-tactic mini-bar charts. Clicking a tactic bar filters the matrix to that tactic. Recomputes on every implementation status change. |
| **Inputs** | `domain: Domain` |
| **Outputs** | `tacticClicked: EventEmitter<string>` |

---

## 2. Matrix Components

Components that render the ATT&CK matrix grid and its supporting UI.

### MatrixComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-matrix` |
| **File** | `src/app/components/matrix/matrix.component.ts` |
| **Purpose** | Core matrix renderer. Subscribes to all FilterService observables, computes per-technique heatmap scores for all 24 modes, manages sorted columns, zoom (0.5x--1.5x), minimap overlay, column visibility, and keyboard-based cell navigation (arrow keys, Enter, Escape). Passes score data down to each TechniqueCellComponent. |
| **Inputs** | `domain: Domain` |
| **Outputs** | `focusSearch: EventEmitter<void>`, `tacticClicked: EventEmitter<{ tactic, techniques, event }>` |

---

### TechniqueCellComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-technique-cell` |
| **File** | `src/app/components/technique-cell/technique-cell.component.ts` |
| **Purpose** | Individual technique cell within the matrix. Renders the ATT&CK ID, name, implementation status dot, note indicator, annotation badge, and watchlist marker. Computes its own background color from the active heatmap mode and the score inputs it receives. Uses `tinycolor2` for readable text-color contrast. |
| **Inputs** | `technique`, `isHighlighted`, `isDimmed`, `isSelected`, `isFocused`, `exposureScore`, `softwareScore`, `campaignScore`, `heatmapMode`, `implStatus`, `maxExposure`, `maxSoftware`, `maxCampaign`, `riskScore`, `maxRisk`, `controlStatus`, `hasNote`, `kevScore`, `maxKev`, `d3fendScore`, `maxD3fend`, `atomicScore`, `maxAtomic`, `engageScore`, `carScore`, `cveScore`, `maxCveScore`, `detectionScore`, `frequencyScore`, `criScore`, `maxCriScore`, `unifiedScore`, `sigmaScore`, `nistScore`, `verisScore`, `epssScore`, `elasticScore`, `splunkScore`, `intelScore`, `maxIntelScore`, `showTechniqueId`, `showMitigationCount`, `showTechniqueName`, `annotation`, `isSearchMatch`, `hasActiveSearch`, `isWatched` |
| **Outputs** | `selected: EventEmitter<Technique>` |

---

### TechniqueTooltipComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-technique-tooltip` |
| **File** | `src/app/components/technique-tooltip/technique-tooltip.component.ts` |
| **Purpose** | Floating tooltip card that appears on technique cell hover. Shows technique name, ATT&CK ID, mitigation count, and threat group count. Positions itself to avoid viewport overflow. |
| **Key I/O** | Programmatic API: `show(tech, mitCount, groupCount, mouseX, mouseY)` / `hide()` |

---

### LegendComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-legend` |
| **File** | `src/app/components/legend/legend.component.ts` |
| **Purpose** | Dynamic color-scale legend below the matrix. Maintains a `MODE_CONFIGS` record mapping all 24 `HeatmapMode` values to their label, color stops, and categorical/gradient flag. Automatically updates when the heatmap mode changes. |
| **Key I/O** | Subscribes to `FilterService.heatmapMode$` |

---

### FilterChipsComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-filter-chips` |
| **File** | `src/app/components/filter-chips/filter-chips.component.ts` |
| **Purpose** | Renders a horizontal bar of active-filter chips (mitigation filters, search query, platform, dim-uncovered, hidden tactics, threat groups, software, campaigns). Each chip has a remove button. Includes a "Clear all" button. |
| **Key I/O** | Subscribes to eight FilterService observables via `combineLatest` |

---

### QuickFiltersComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-quick-filters` |
| **File** | `src/app/components/quick-filters/quick-filters.component.ts` |
| **Purpose** | Expandable preset filter bar with one-click scenarios: No Mitigation, KEV Exposed, Not Implemented, APT Focus, and more. Each preset selects a specific heatmap mode and applies relevant filters. Persists expanded/collapsed state to localStorage. |
| **Key I/O** | Reads/writes `FilterService.heatmapMode$` and other filter observables |

---

### GapViewComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-gap-view` |
| **File** | `src/app/components/gap-view/gap-view.component.ts` |
| **Purpose** | Full-screen modal overlay listing all techniques with zero mitigations, grouped by tactic. Shows a count header and allows clicking a technique to open it in the sidebar. Dark overlay backdrop. |
| **Key I/O** | Subscribes to `DataService.domain$` and `FilterService` for visibility |

---

### TacticSummaryComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-tactic-summary` |
| **File** | `src/app/components/tactic-summary/tactic-summary.component.ts` |
| **Purpose** | Popover card triggered by clicking a tactic column header. Shows technique count, coverage percentage, implementation status breakdown, and top uncovered techniques for that tactic. Positioned near the click event. |
| **Key I/O** | Programmatic API: `show(data: TacticSummaryData, event: MouseEvent)` |

---

## 3. Sidebar Component

### SidebarComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-sidebar` |
| **File** | `src/app/components/sidebar/sidebar.component.ts` |
| **Purpose** | Right-side slide-out detail panel for a selected technique. The most data-rich component in the app -- integrates with 20+ services to display: technique description, mitigations with implementation status/documentation, D3FEND countermeasures, MITRE Engage activities, CAR analytics, Atomic Red Team tests, CVE/KEV mappings, EPSS scores, NIST 800-53/CIS/CRI/Cloud controls, VERIS actions, CAPEC/CWE entries, MISP galaxy clusters, OpenCTI indicators, Sigma rules, ExploitDB/Nuclei references, custom mitigations, annotations, tags, watchlist management, and a relationship graph visualization. Tabbed interface with sections for Overview, Mitigations, Detection, Intelligence, and Compliance. |
| **Key I/O** | Subscribes to `FilterService.selectedTechnique$` to open/close |

---

## 4. Threat Intelligence Components

### ThreatPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-threat-panel` |
| **File** | `src/app/components/threat-panel/threat-panel.component.ts` |
| **Panel ID** | `threats` |
| **Purpose** | Two-tab panel for browsing threat groups and campaigns. Groups tab shows each group's technique count and coverage. Campaigns tab shows attributed groups and technique counts. Selecting groups/campaigns highlights their techniques on the matrix and identifies coverage gaps with KEV exposure. |
| **Key I/O** | Reads/writes `FilterService.activeThreatGroupIds$`, `activeCampaignIds$` |

---

### ThreatIntelligencePanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-threat-intelligence-panel` |
| **File** | `src/app/components/threat-intelligence-panel/threat-intelligence-panel.component.ts` |
| **Panel ID** | `intelligence` |
| **Purpose** | Aggregated threat intelligence hub with four tabs: Overview (technique intel scores), Indicators (MISP + OpenCTI IOCs), Actors (combined ATT&CK + OpenCTI actors), and MISP Events. Correlates external intelligence sources with the ATT&CK matrix. |
| **Key I/O** | Subscribes to `MispService`, `OpenCtiService`, `DataService` |

---

### ActorProfilePanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-actor-profile-panel` |
| **File** | `src/app/components/actor-profile-panel/actor-profile-panel.component.ts` |
| **Panel ID** | `actor` |
| **Purpose** | Deep-dive profile for a single threat actor. Shows technique list, associated software, campaigns, coverage percentage, tactic breakdown, and top uncovered techniques. Four-tab view: Overview, Techniques, Software, Campaigns. |
| **Key I/O** | Subscribes to `DataService.domain$`, `ImplementationService.status$` |

---

### ActorComparePanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-actor-compare-panel` |
| **File** | `src/app/components/actor-compare-panel/actor-compare-panel.component.ts` |
| **Panel ID** | `actor-compare` |
| **Purpose** | Side-by-side comparison of two threat actors. Shows overlapping techniques, techniques unique to each actor, and a matrix view. Searchable actor selection dropdowns with four tabs: Overlap, Unique A, Unique B, Matrix. |
| **Key I/O** | Subscribes to `DataService.domain$` |

---

### ScenarioPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-scenario-panel` |
| **File** | `src/app/components/scenario-panel/scenario-panel.component.ts` |
| **Panel ID** | `scenario` |
| **Purpose** | Attack scenario simulator. Select a threat group and simulate an attack against current defenses. Classifies each technique as blocked, detected, vulnerable, or unknown based on implementation status, detection coverage, and mitigation presence. Generates an overall risk score (0--100) with radar chart visualization and a recommended action plan. Three tabs: Summary, Techniques, Plan. |
| **Key I/O** | Subscribes to `FilterService`, `DataService`, `ImplementationService`, `CARService`, `AtomicService`, `D3fendService` |

---

### CampaignTimelinePanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-campaign-timeline-panel` |
| **File** | `src/app/components/campaign-timeline-panel/campaign-timeline-panel.component.ts` |
| **Panel ID** | `campaign-timeline` |
| **Purpose** | Gantt-style horizontal timeline of ATT&CK campaigns. Each bar is color-coded by attributed threat group. Supports year filtering, group filtering, search, and clicking a campaign to highlight its techniques on the matrix. Uses 15 predefined group colors. |
| **Key I/O** | Subscribes to `DataService.domain$`, `FilterService.activeCampaignIds$` |

---

### SoftwarePanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-software-panel` |
| **File** | `src/app/components/software-panel/software-panel.component.ts` |
| **Panel ID** | `software` |
| **Purpose** | Browsable list of ATT&CK software entries (tools and malware). Filterable by type and searchable by name. Selecting a software entry highlights the techniques it uses on the matrix. |
| **Inputs** | `software: AttackSoftware[]` |
| **Key I/O** | Reads/writes `FilterService.activeSoftwareIds$` |

---

## 5. Analysis Components

### AnalyticsPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-analytics-panel` |
| **File** | `src/app/components/analytics-panel/analytics-panel.component.ts` |
| **Panel ID** | `analytics` |
| **Purpose** | Executive analytics dashboard showing per-tactic stats (coverage %, average risk), implementation status summary, top coverage gaps (ranked by group count, KEV, and risk), and highest-impact mitigations. Integrates CVE, Sigma, and NIST data for enriched scoring. |
| **Key I/O** | Subscribes to `DataService`, `ImplementationService`, `CveService`, `SigmaService`, `NistMappingService` |

---

### KillchainPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-killchain-panel` |
| **File** | `src/app/components/killchain-panel/killchain-panel.component.ts` |
| **Panel ID** | `killchain` |
| **Purpose** | Kill-chain analysis showing each ATT&CK tactic as a row with total techniques, covered count, coverage percentage, sub-technique count, threat group count, average mitigations per technique, and the top uncovered technique. Click a tactic to see its detail. |
| **Key I/O** | Subscribes to `DataService.domain$` |

---

### RiskMatrixPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-risk-matrix-panel` |
| **File** | `src/app/components/risk-matrix-panel/risk-matrix-panel.component.ts` |
| **Panel ID** | `risk-matrix` |
| **Purpose** | 2D scatter plot placing techniques by threat score (Y: group count) vs. gap score (X: inverse of mitigation coverage). Techniques are classified into four quadrants: Critical (high threat, low coverage), Monitor (high threat, covered), Low Priority (low threat, low coverage), and Well Protected (low threat, covered). Filterable by quadrant with a searchable list view. |
| **Key I/O** | Subscribes to `DataService.domain$` |

---

### DetectionPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-detection-panel` |
| **File** | `src/app/components/detection-panel/detection-panel.component.ts` |
| **Panel ID** | `detection` |
| **Purpose** | Detection coverage analysis combining four detection sources: CAR analytics, Atomic Red Team tests, and D3FEND countermeasures. Shows per-technique detection scores, gaps (techniques with zero detection), top-covered techniques, and tactic-grouped breakdowns. Four tabs: Overview, Gaps, Top, Tactic. |
| **Key I/O** | Subscribes to `CARService`, `AtomicService`, `D3fendService` |

---

### TechniqueGraphPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-technique-graph-panel` |
| **File** | `src/app/components/technique-graph-panel/technique-graph-panel.component.ts` |
| **Panel ID** | `technique-graph` |
| **Purpose** | Interactive force-directed graph visualization showing a technique's relationships: mitigations, threat groups, software, CVEs, campaigns, subtechniques, and parent techniques. Nodes are color-coded by kind and draggable. Supports click-to-pin and panning. |
| **Key I/O** | Subscribes to `FilterService.selectedTechnique$`, `DataService.domain$`, `AttackCveService` |

---

### DatasourcePanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-datasource-panel` |
| **File** | `src/app/components/datasource-panel/datasource-panel.component.ts` |
| **Panel ID** | `datasources` |
| **Purpose** | Browser for MITRE ATT&CK data sources and their components. Two tabs: Sources (grouped by data source with expandable component lists) and Components (flat, sortable list). Shows technique counts per source/component and supports search and sort by name or technique count. |
| **Key I/O** | Subscribes to `DataService.domain$` |

---

### CvePanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-cve-panel` |
| **File** | `src/app/components/cve-panel/cve-panel.component.ts` |
| **Panel ID** | `cve` |
| **Purpose** | CVE research panel with three tabs: Search (NVD lookup with EPSS enrichment), KEV (CISA Known Exploited Vulnerabilities catalog), and By Technique (ATT&CK-to-CVE mappings from CTID dataset). Supports NVD API key configuration for higher rate limits and CWE cross-reference. |
| **Key I/O** | Subscribes to `CveService`, `AttackCveService`, `EpssService`, `CweService`, `SettingsService` |

---

## 6. Coverage Components

### ControlsPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-controls-panel` |
| **File** | `src/app/components/controls-panel/controls-panel.component.ts` |
| **Panel ID** | `controls` |
| **Purpose** | Security controls manager. CRUD interface for creating controls mapped to framework templates (NIST 800-53, CIS Controls v8, ISO 27001, Custom). Two tabs: My Controls (manage individual controls with technique/mitigation counts) and By Mitigation (view controls grouped by ATT&CK mitigation). Supports bulk import. |
| **Key I/O** | Subscribes to `ControlsService`, `DataService.domain$` |

---

### CompliancePanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-compliance-panel` |
| **File** | `src/app/components/compliance-panel/compliance-panel.component.ts` |
| **Panel ID** | `compliance` |
| **Purpose** | Multi-framework compliance matrix. Six tabs (NIST, CIS, AWS, Azure, GCP, CRI) showing how each technique maps to controls in that framework. Displays control counts per technique, sortable by technique name or coverage depth, with hover tooltips showing control details. |
| **Key I/O** | Subscribes to `CisControlsService`, `CloudControlsService`, `NistMappingService`, `CriProfileService` |

---

### PriorityPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-priority-panel` |
| **File** | `src/app/components/priority-panel/priority-panel.component.ts` |
| **Panel ID** | `priority` |
| **Purpose** | Mitigation priority ranker. Scores each mitigation across eight dimensions: unique technique coverage, total techniques, threat group exposure, KEV CVE count, Atomic test count, Sigma rule count, unified risk score, and NIST control count. Sortable by any column. Inline implementation status editing. |
| **Key I/O** | Subscribes to `DataService`, `ImplementationService`, `CveService`, `AtomicService`, `SigmaService`, `EpssService`, `AttackCveService`, `NistMappingService` |

---

### WhatifPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-whatif-panel` |
| **File** | `src/app/components/whatif-panel/whatif-panel.component.ts` |
| **Panel ID** | `whatif` |
| **Purpose** | What-if analysis panel. Shows all mitigations with their potential new technique coverage and exposure reduction. Check mitigations to simulate deployment -- the panel recalculates coverage percentage in real time, showing current vs. projected coverage. Filterable to show only non-implemented mitigations. |
| **Key I/O** | Reads/writes `FilterService.whatIfMitigationIds$`, subscribes to `ImplementationService.status$` |

---

### TimelinePanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-timeline-panel` |
| **File** | `src/app/components/timeline-panel/timeline-panel.component.ts` |
| **Panel ID** | `timeline` |
| **Purpose** | Coverage snapshot timeline. Take point-in-time snapshots of coverage and implementation status, add labels and notes, and track progress over time. Three tabs: Timeline (chronological snapshot list), Compare (side-by-side snapshot diff), Trends (coverage delta chart). Snapshots are persisted via `TimelineService`. |
| **Key I/O** | Subscribes to `TimelineService.snapshots$`, `ImplementationService.status$` |

---

### CoverageDiffPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-coverage-diff-panel` |
| **File** | `src/app/components/coverage-diff-panel/coverage-diff-panel.component.ts` |
| **Panel ID** | `coverage-diff` |
| **Purpose** | Detailed side-by-side comparison of two coverage snapshots. Shows per-tactic coverage deltas (old vs. new percentage, absolute change) and implementation status deltas. Select any two snapshots from dropdown menus. |
| **Key I/O** | Subscribes to `TimelineService.snapshots$` |

---

### TargetPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-target-panel` |
| **File** | `src/app/components/target-panel/target-panel.component.ts` |
| **Panel ID** | `target` |
| **Purpose** | Target coverage planner. Set a target coverage percentage (default 80%) and the panel computes the minimum set of mitigations needed to reach it, using a greedy algorithm that maximizes new technique coverage per mitigation. Shows current gap and a step-by-step implementation plan with cumulative coverage. |
| **Key I/O** | Subscribes to `DataService.domain$`, `ImplementationService.status$` |

---

### WatchlistPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-watchlist-panel` |
| **File** | `src/app/components/watchlist-panel/watchlist-panel.component.ts` |
| **Panel ID** | `watchlist` |
| **Purpose** | Technique watchlist for tracking techniques of interest. Entries have priority levels (high/medium/low), analyst notes, and timestamps. Filterable by priority, sortable by added date/priority/name, with inline note editing. |
| **Key I/O** | Subscribes to `WatchlistService.entries$` |

---

## 7. Tools Components

### SigmaExportComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-sigma-export` |
| **File** | `src/app/components/sigma-export/sigma-export.component.ts` |
| **Panel ID** | `sigma` |
| **Purpose** | Sigma detection rule export. Four export modes: Current (visible techniques), Implemented (mitigations marked implemented), All, and Custom (manual technique selection). Generates YAML preview of Sigma rules from the `SigmaService` rule database. |
| **Key I/O** | Subscribes to `SigmaService`, `ImplementationService`, `DataService.domain$` |

---

### SiemExportComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-siem-export` |
| **File** | `src/app/components/siem-export/siem-export.component.ts` |
| **Panel ID** | `siem` |
| **Purpose** | Multi-platform SIEM export supporting five targets: Splunk (SPL), Microsoft Sentinel (KQL), Elastic (EQL), Suricata (IDS rules), and Zeek (scripts). Three export scopes: All, By Technique, or By Tactic. Generates platform-specific query content from CAR analytics and copies to clipboard. |
| **Key I/O** | Subscribes to `CARService`, `SuricataService`, `ZeekService` |

---

### YaraExportComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-yara-export` |
| **File** | `src/app/components/yara-export/yara-export.component.ts` |
| **Panel ID** | `yara` |
| **Purpose** | YARA rule export. Three modes: Current (visible techniques), Implemented, and All. Generates YARA rule previews from the `YaraService` rule database with technique-count statistics. |
| **Key I/O** | Subscribes to `YaraService`, `ImplementationService`, `DataService.domain$` |

---

### PurpleTeamPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-purple-team-panel` |
| **File** | `src/app/components/purple-team-panel/purple-team-panel.component.ts` |
| **Panel ID** | `purple` |
| **Purpose** | Purple-team readiness assessor. Scores each technique across four dimensions: D3FEND countermeasures, Engage activities, CAR analytics, and Atomic Red Team tests. Classifies coverage as excellent/good/partial/poor/none. Three views: Selected technique detail, top gaps, and top covered. |
| **Key I/O** | Subscribes to `D3fendService`, `EngageService`, `CARService`, `AtomicService` |

---

### LayersPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-layers-panel` |
| **File** | `src/app/components/layers-panel/layers-panel.component.ts` |
| **Panel ID** | `layers` |
| **Purpose** | ATT&CK Navigator layer management. Save the current matrix state as a named layer snapshot, load previous layers, import Navigator JSON files, and export layers in Navigator-compatible format. Each layer captures heatmap mode, filters, and implementation status. |
| **Key I/O** | Subscribes to `LayersService.layers$` |

---

### ComparisonPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-comparison-panel` |
| **File** | `src/app/components/comparison-panel/comparison-panel.component.ts` |
| **Panel ID** | `comparison` |
| **Purpose** | Group-vs-group technique comparison. Select two threat groups from dropdowns and see which techniques are used by only group A, only group B, or both. Simple Venn-diagram style analysis for identifying unique and shared TTPs. |
| **Key I/O** | Subscribes to `DataService.domain$` |

---

### CustomMitPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-custom-mit-panel` |
| **File** | `src/app/components/custom-mit-panel/custom-mit-panel.component.ts` |
| **Panel ID** | `custom-mit` |
| **Purpose** | Custom mitigation CRUD panel. Create organization-specific mitigations beyond the ATT&CK catalog, assign them to techniques, set categories (EDR, SIEM, Network, etc.), and track their implementation status. Three views: List, Create, Edit. Technique search with autocomplete suggestions. |
| **Key I/O** | Subscribes to `CustomMitigationService`, `DataService.domain$` |

---

### TagsPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-tags-panel` |
| **File** | `src/app/components/tags-panel/tags-panel.component.ts` |
| **Panel ID** | `tags` |
| **Purpose** | Technique tagging manager. View all tags with usage counts, filter by tag, see which techniques are tagged, and rename or delete tags. Supports search and inline rename editing. Tags are persisted via `TaggingService`. |
| **Key I/O** | Subscribes to `TaggingService`, `DataService.domain$` |

---

### RoadmapPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-roadmap-panel` |
| **File** | `src/app/components/roadmap-panel/roadmap-panel.component.ts` |
| **Panel ID** | `roadmap` |
| **Purpose** | Auto-generated quarterly implementation roadmap. Assigns mitigations to Q1--Q4 phases based on priority scores (impact / effort). Each phase shows the mitigations to deploy, new technique coverage gained, and CVEs addressed. Uses predefined effort estimates per ATT&CK mitigation ID. |
| **Key I/O** | Subscribes to `DataService.domain$`, `ImplementationService.status$`, `AttackCveService` |

---

### ReportPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-report-panel` |
| **File** | `src/app/components/report-panel/report-panel.component.ts` |
| **Panel ID** | `report` |
| **Purpose** | Executive summary report generator. Compiles total techniques, coverage percentage, implemented-coverage percentage, per-tactic breakdown with top gaps, recommended mitigations ranked by unique coverage, and documented mitigations with owner/due-date/evidence metadata. Supports copy-to-clipboard and HTML export. |
| **Key I/O** | Subscribes to `DataService`, `ImplementationService`, `DocumentationService` |

---

### ChangelogPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-changelog-panel` |
| **File** | `src/app/components/changelog-panel/changelog-panel.component.ts` |
| **Panel ID** | `changelog` |
| **Purpose** | ATT&CK framework release changelog viewer. Fetches release data from `ChangelogService` and displays each ATT&CK version with expandable details showing new, modified, and deprecated techniques, mitigations, groups, and software. |
| **Key I/O** | Subscribes to `ChangelogService.releases$`, `ChangelogService.loaded$` |

---

## 8. Settings and Utility Components

### SettingsPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-settings-panel` |
| **File** | `src/app/components/settings-panel/settings-panel.component.ts` |
| **Panel ID** | `settings` |
| **Purpose** | Application settings with five tabs: Scoring (risk weight sliders), Display (color theme picker with 5 themes, cell display toggles), Organization (metadata fields), Data (ATT&CK version info, cache management, data refresh), and Integrations (NVD API key, OpenCTI URL/token connection test, MISP configuration). |
| **Key I/O** | Subscribes to `SettingsService`, `OpenCtiService`, `MispService` |

---

### KeyboardHelpComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-keyboard-help` |
| **File** | `src/app/components/keyboard-help/keyboard-help.component.ts` |
| **Purpose** | Modal overlay displaying all keyboard shortcuts organized into groups: Navigation (12 shortcuts), Matrix Keyboard Navigation (5 shortcuts), Matrix View (4 shortcuts), and Filtering. Toggled with `?` key. |
| **Key I/O** | Listens for `?` keydown via `@HostListener` |

---

### DataHealthComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-data-health` |
| **File** | `src/app/components/data-health/data-health.component.ts` |
| **Purpose** | Compact inline ribbon of colored dots showing the loading status of all external data sources. Each dot represents one service (Atomic, Sigma, CVE, CAPEC, MISP, NIST, CRI, Cloud Controls, VERIS, D3FEND, CAR, Elastic, Splunk, ExploitDB, Nuclei) with states: green (loaded), yellow-pulsing (loading), red (failed). Inline template component. |
| **Key I/O** | Subscribes to 15 service `loaded$`/`ready$` observables |

---

### DashboardPanelComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-dashboard-panel` |
| **File** | `src/app/components/dashboard-panel/dashboard-panel.component.ts` |
| **Panel ID** | `dashboard` |
| **Purpose** | Executive KPI dashboard. Displays coverage stats (total, covered, percentage), implementation breakdown (implemented/in-progress/planned/not-started), detection coverage (CAR/Atomic/D3FEND), risk indicators (critical-risk count, CVE-exposed count), coverage trend from timeline snapshots, per-tactic bar chart, and top-risk techniques. Supports HTML report export. |
| **Key I/O** | Subscribes to `DataService`, `ImplementationService`, `TimelineService`, `AttackCveService`, `CARService`, `AtomicService`, `D3fendService`, `HtmlReportService` |

---

### UniversalSearchComponent

| Property | Value |
|----------|-------|
| **Selector** | `app-universal-search` |
| **File** | `src/app/components/universal-search/universal-search.component.ts` |
| **Panel ID** | `search` |
| **Purpose** | Global search overlay searching across eight categories: techniques, mitigations, threat groups, software, D3FEND countermeasures, CAR analytics, Atomic tests, and Engage activities. Debounced input with category filter tabs, scored results, and direct navigation to the selected item. Opened with `Ctrl+K`. |
| **Key I/O** | Subscribes to `DataService.domain$`, `D3fendService`, `CARService`, `AtomicService`, `EngageService` |

---

## Architecture Notes

### State Management

All panels subscribe to `FilterService.activePanel$` (type `ActivePanel`) to toggle their visibility. The `ActivePanel` union type defines all valid panel IDs:

```typescript
export type ActivePanel =
  | 'dashboard' | 'threats' | 'priority' | 'whatif' | 'report'
  | 'controls' | 'software' | 'comparison' | 'layers' | 'cve'
  | 'analytics' | 'sigma' | 'purple' | 'actor' | 'search'
  | 'yara' | 'roadmap' | 'detection' | 'compliance' | 'actor-compare'
  | 'timeline' | 'settings' | 'custom-mit' | 'killchain' | 'risk-matrix'
  | 'scenario' | 'siem' | 'datasources' | 'watchlist' | 'changelog'
  | 'tags' | 'target' | 'campaign-timeline' | 'technique-graph'
  | 'coverage-diff' | 'intelligence'
  | null;
```

### Component Conventions

- All components are **standalone** (no NgModules).
- All use **OnPush** change detection for performance.
- Panel components follow the pattern: subscribe to `activePanel$`, set `visible`/`open` flag, call `cdr.markForCheck()`.
- Cleanup is handled via a `Subscription` bag (`private subs = new Subscription()`) unsubscribed in `ngOnDestroy`.
- Matrix score data flows from `MatrixComponent` to `TechniqueCellComponent` via `@Input()` bindings (one input per heatmap mode's score).
