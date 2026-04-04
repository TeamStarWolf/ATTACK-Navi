# Architecture

## 1. Overview

The MITRE ATT&CK Navi is a single-page Angular 19 application that visualizes
the full ATT&CK matrix, overlays mitigation coverage data, and integrates 40+ external threat
intelligence, detection, vulnerability, and compliance data sources into a unified analyst
workspace.

Key technical characteristics:

- **Angular 19 standalone components** -- every component uses `standalone: true`; there are no
  NgModules.
- **OnPush change detection** -- all components set `changeDetection: ChangeDetectionStrategy.OnPush`
  and call `ChangeDetectorRef.markForCheck()` explicitly when async state arrives.
- **RxJS BehaviorSubject state** -- the application has no NgRx or other store library.  All shared
  state lives in singleton services that expose `BehaviorSubject` observables and plain getters.
- **Dark-first theming** -- the default palette is dark (`#070d14` base).  A `light-mode` CSS class
  on `<body>` flips to the light theme.  Theme choice persists in `localStorage`.

The application ships as a static SPA with no backend.  All data is fetched client-side from
public GitHub-hosted STIX bundles, CTID mapping files, and vendor-published Navigator layers.

---

## 2. Application Shell

**File:** `src/app/app.component.ts`

`AppComponent` is the composition root.  It is the only component that directly touches the DOM
(`document.body`, `document.querySelector`) and `window` APIs (clipboard, scroll).

### Responsibilities

| Concern | How |
|---|---|
| Domain loading | Subscribes to `DataService.domain$`, `loading$`, `error$`, `currentDomain$` and calls `loadDomain()` on init. |
| Panel orchestration | Wires `FilterService.activePanel$` to conditionally render 35+ overlay panel components. |
| Keyboard shortcuts | `@HostListener('document:keydown')` handles `Escape`, `Ctrl+F`, `Ctrl+K`, `Ctrl+E`, and single-key shortcuts `d`, `t`, `w`, `r`, `c`. |
| Domain switching | `onDomainChange()` calls `FilterService.clearAll()` then `DataService.switchDomain()`. |
| URL state | Instantiates `UrlStateService` and calls `restoreFromUrl()` on init. |
| Export flows | Nine export methods (CSV, XLSX, HTML report, PNG, JSON state, Navigator layer) and two import methods (state JSON, Navigator layer). |
| Bulk actions | Delegates multi-select operations (watchlist, status, tag) to `MatrixComponent` via `@ViewChild`. |
| Theme toggle | Adds/removes `light-mode` on `document.body`; persists to `localStorage('mitre-nav-theme')`. |
| Tactic summary popup | `TacticSummaryComponent` shown on tactic header click. |

### Imports (standalone)

The component imports 49 child components inline in its `@Component.imports` array, including all
panel components, the nav rail, toolbar, matrix, sidebar, stats bar, filter chips, gap view, legend,
data health, and more.

### Constructor injections

`DataService`, `FilterService`, `ImplementationService`, `DocumentationService`,
`MatrixExportService`, `HtmlReportService`, `ChangeDetectorRef`, `UrlStateService`,
`XlsxExportService`, `CustomMitigationService`, `TimelineService`.

---

## 3. State Management

### FilterService -- the central state store

**File:** `src/app/services/filter.service.ts`

`FilterService` is a `providedIn: 'root'` singleton that holds all user interaction state as
`BehaviorSubject` instances.  It has no external dependencies other than `DataService` (injected
to resolve STIX IDs from the loaded domain).

#### BehaviorSubjects

| Subject | Type | Purpose |
|---|---|---|
| `selectedTechniqueSubject` | `Technique \| null` | Currently selected technique (drives sidebar). |
| `activeMitigationFiltersSubject` | `Mitigation[]` | Active mitigation highlight filters. |
| `techniqueQuerySubject` | `string` | Free-text search query across techniques. |
| `sortModeSubject` | `SortMode` (`'alpha' \| 'coverage'`) | Matrix column sort order. |
| `dimUncoveredSubject` | `boolean` | Whether uncovered techniques are dimmed. |
| `platformFilterSubject` | `string \| null` | Single-platform filter (legacy). |
| `platformMultiSubject` | `Set<string>` | Multi-platform filter (current). |
| `hiddenTacticIdsSubject` | `Set<string>` | Tactic columns hidden from the matrix. |
| `searchScopeSubject` | `SearchScope` (`'name' \| 'full'`) | Whether search matches name only or full description. |
| `activeThreatGroupIdsSubject` | `Set<string>` | Active threat group filter (STIX IDs). |
| `whatIfMitigationIdsSubject` | `Set<string>` | "What-if" scenario mitigation IDs. |
| `activeSoftwareIdsSubject` | `Set<string>` | Active software/malware filter. |
| `activeCampaignIdsSubject` | `Set<string>` | Active campaign filter. |
| `activeDataSourceSubject` | `string \| null` | Active ATT&CK data source name filter. |
| `activePanelSubject` | `ActivePanel` | Currently visible overlay panel (or `null`). |
| `heatmapModeSubject` | `HeatmapMode` | Active heatmap coloring mode (23 modes). |
| `implStatusFilterSubject` | `string \| null` | Filter techniques by implementation status. |
| `searchFilterModeSubject` | `boolean` | When true, search acts as a filter (hides non-matches). |
| `cveTechniqueIdsSubject` | `Set<string>` | Technique IDs highlighted by CVE panel clicks. |
| `techniqueSearchSubject` | `string` | Matrix-local search text (distinct from global query). |

#### Derived Observables

Computed via `combineLatest` + `map` in the constructor:

| Observable | Derivation |
|---|---|
| `highlightedTechniqueIds$` | Union of technique IDs covered by `activeMitigationFilters` (resolved via `domain.techniquesByMitigation`). |
| `matchedTechniqueIds$` | Technique IDs matching `techniqueQuery` (name-only or full-text depending on `searchScope`). |
| `platformFilteredIds$` | Technique IDs matching the single-platform filter. |
| `threatGroupTechniqueIds$` | Techniques used by any selected threat group. |
| `softwareTechniqueIds$` | Techniques used by any selected software family. |
| `campaignTechniqueIds$` | Techniques used by any selected campaign. |
| `dataSourceFilteredIds$` | Techniques detectable via the selected data source. |

#### Type Definitions

```typescript
type ActivePanel = 'dashboard' | 'threats' | 'priority' | 'whatif' | 'report'
  | 'controls' | 'software' | 'comparison' | 'layers' | 'cve' | 'analytics'
  | 'sigma' | 'purple' | 'actor' | 'search' | 'yara' | 'roadmap'
  | 'detection' | 'compliance' | 'actor-compare' | 'timeline' | 'settings'
  | 'custom-mit' | 'killchain' | 'risk-matrix' | 'scenario' | 'siem'
  | 'datasources' | 'watchlist' | 'changelog' | 'tags' | 'target'
  | 'campaign-timeline' | 'technique-graph' | 'coverage-diff'
  | 'intelligence' | null;

type HeatmapMode = 'coverage' | 'exposure' | 'status' | 'controls'
  | 'software' | 'campaign' | 'risk' | 'kev' | 'd3fend' | 'atomic'
  | 'engage' | 'car' | 'cve' | 'detection' | 'frequency' | 'cri'
  | 'unified' | 'sigma' | 'nist' | 'veris' | 'epss' | 'elastic'
  | 'splunk' | 'intelligence';
```

#### URL Hash Sync

All filter state is bidirectionally synchronized with `window.location.hash` using URL-encoded
query parameters (e.g. `#mit=M1036,M1049&heat=exposure&dim=1`).

- **Write path:** A `combineLatest` of 15 subjects pipes through `debounceTime(300)` and calls
  `history.replaceState()` to update the hash without navigation.
- **Read path:** `readUrlState()` runs in the constructor, parses the hash with `URLSearchParams`,
  and pushes restored values into the appropriate subjects.  Entity IDs (mitigations, groups,
  software, campaigns) are resolved from their ATT&CK IDs via `DataService.domain$` once the
  domain loads.

This makes every filter combination shareable as a URL.

---

## 4. Component Architecture

### Component Tree

```
AppComponent
  +-- ToolbarComponent              (search, domain selector, export/import, theme toggle)
  +-- NavRailComponent              (left icon sidebar, panel toggles)
  +-- StatsBarComponent             (coverage statistics bar)
  +-- FilterChipsComponent          (active filter chips with remove buttons)
  +-- QuickFiltersComponent         (preset filter shortcuts)
  +-- MatrixComponent               (ATT&CK tactic/technique grid)
  |     +-- TechniqueCellComponent  (individual technique cell, heatmap color)
  |     +-- TechniqueTooltipComponent (hover tooltip)
  +-- SidebarComponent              (technique detail drawer, 25+ sections)
  +-- LegendComponent               (heatmap color legend)
  +-- TacticSummaryComponent        (tactic header click popup)
  +-- DataHealthComponent           (data source load status indicators)
  +-- [35 overlay panel components] (each conditionally rendered by activePanel$)
```

### Core Components

**ToolbarComponent** (`src/app/components/toolbar/`)
Top bar with technique search input, domain selector (Enterprise/ICS/Mobile), heatmap mode
picker, export/import menus, theme toggle, and share-link button.  Communicates exclusively
through `FilterService` setters and `@Output()` events to `AppComponent`.

**NavRailComponent** (`src/app/components/nav-rail/`)
Vertical icon rail on the left edge.  Each icon toggles a specific panel via
`FilterService.togglePanel()`.  Active panel is highlighted via `activePanel$` subscription.

**MatrixComponent** (`src/app/components/matrix/`)
The main workspace.  Receives `domain: Domain` as `@Input()` from `AppComponent`.  Subscribes
to a `combineLatest` of all FilterService observables to build the display state:

- Sorts `domain.tacticColumns` into `sortedColumns` (alpha or coverage order).
- Computes per-technique score maps for the active heatmap mode (coverage, exposure, status,
  controls, software, campaign, risk, KEV, D3FEND, Atomic, Engage, CAR, CVE, detection,
  frequency, CRI, unified, Sigma, NIST, VERIS, EPSS, Elastic, Splunk, intelligence).
- Manages sub-technique expansion (`expandedParents` set), keyboard navigation, multi-select,
  zoom, minimap, and cell size settings.
- Emits `tacticClicked` and `focusSearch` events to `AppComponent`.

**SidebarComponent** (`src/app/components/sidebar/`)
Sliding detail drawer that reacts to `FilterService.selectedTechnique$`.  Injects 23 services
to hydrate 25+ collapsible sections for the selected technique.  Computes a completeness score
(0-100) and renders signal summary pills.

### Communication Pattern

Components never communicate directly with each other.  All inter-component communication flows
through `FilterService`:

1. User action in Component A calls a `FilterService` setter.
2. `FilterService` BehaviorSubject emits.
3. Component B's subscription fires, updates local state, calls `cdr.markForCheck()`.

---

## 5. Data Loading

### DataService

**File:** `src/app/services/data.service.ts`

Responsible for fetching, caching, and parsing the MITRE ATT&CK STIX 2.1 bundle.

#### Domain Configuration

Three domains are supported:

| Domain | Live URL | Bundled Fallback | IDB Cache Key |
|---|---|---|---|
| Enterprise | `mitre-attack/attack-stix-data/.../enterprise-attack.json` | `assets/enterprise-attack.json` | `enterprise-attack-v2` |
| ICS | `mitre-attack/attack-stix-data/.../ics-attack.json` | (none) | `ics-attack-v1` |
| Mobile | `mitre-attack/attack-stix-data/.../mobile-attack.json` | (none) | `mobile-attack-v1` |

#### Loading Pipeline

1. `loadDomain()` is called (either on init or on domain switch).
2. The service checks `DataSourceMode`: `'live'` (default) or `'bundled'`.
3. **Live path:** Opens IndexedDB (`mitre-navigator-cache` / `stix-bundles`), checks for a cached
   entry with the domain's `idbKey`.  If the cached entry exists and is less than 24 hours old
   (`CACHE_TTL_MS = 24 * 60 * 60 * 1000`), uses it.  Otherwise fetches from GitHub, stores the
   result in IDB, and proceeds.
4. **Bundled path:** Fetches from `assets/enterprise-attack.json` (Enterprise only).
5. The raw STIX JSON is parsed into a `Domain` model object.

#### Domain Model

The `Domain` class (`src/app/models/domain.ts`) is the fully-indexed in-memory representation:

- `techniques: Technique[]` -- all techniques and sub-techniques.
- `mitigations: Mitigation[]` -- all mitigations.
- `groups: ThreatGroup[]` -- all threat groups.
- `software: AttackSoftware[]` -- all software/malware entries.
- `campaigns: Campaign[]` -- all campaign objects.
- `dataSources: MitreDataSource[]` / `dataComponents: MitreDataComponent[]`
- `tacticColumns: TacticColumn[]` -- techniques grouped by tactic for matrix rendering.
- Relationship indexes (all `Map` objects):
  - `mitigationsByTechnique`, `techniquesByMitigation`
  - `groupsByTechnique`, `techniquesByGroup`
  - `softwareByTechnique`, `techniquesBySoftware`
  - `campaignsByTechnique`, `techniquesByCampaign`
  - `techniquesByDataComponent`

#### Key Methods

- `switchDomain(domain)` -- clears current domain, updates `currentDomain$`, reloads.
- `forceRefresh()` -- deletes the IDB cache entry and reloads.
- `getMitigationsForTechnique(id)` -- synchronous lookup from the domain Map.
- `getTechniquesForMitigation(id)` -- synchronous reverse lookup.
- `getGroupsForTechnique(id)` / `getTechniquesForGroup(id)` -- group lookups.

---

## 6. Heatmap Pipeline

The heatmap pipeline transforms raw data from 23+ sources into per-cell background colors in the
matrix.  Here is the seven-step flow:

### Step 1: Service Loading

Each data service (e.g. `SigmaService`, `D3fendService`, `AtomicService`) fetches its data
source on construction and builds an internal lookup index (typically `Map<string, T[]>` keyed
by ATT&CK technique ID).

**Files:** All files in `src/app/services/` (see SERVICES.md for the complete catalog).

### Step 2: Heatmap Mode Selection

The user selects a heatmap mode from the toolbar dropdown.  This calls
`FilterService.setHeatmapMode(mode)`, which pushes the new `HeatmapMode` value onto
`heatmapModeSubject`.

**File:** `src/app/services/filter.service.ts` (line 28: `heatmapModeSubject`).

### Step 3: Score Map Computation

`MatrixComponent` subscribes to `FilterService.heatmapMode$` and, on each change, iterates
every technique in the domain to compute a numeric score.  Each mode has its own scoring logic:

| Mode | Score Source | Score Meaning |
|---|---|---|
| `coverage` | `technique.mitigationCount` | Number of mitigations |
| `exposure` | `domain.groupsByTechnique.get(id).length` | Threat groups using technique |
| `status` | `ImplementationService.getStatusMap()` | Best implementation status across mitigations |
| `controls` | `ControlsService.controls$` | Mapped/planned security controls |
| `software` | `domain.softwareByTechnique.get(id).length` | Software families using technique |
| `campaign` | `domain.campaignsByTechnique.get(id).length` | Campaigns using technique |
| `risk` | Composite: exposure * (1 - coverage_ratio) | Weighted risk score |
| `kev` | `AttackCveService` KEV CVE count | Known exploited vulnerabilities |
| `d3fend` | `D3fendService.getCountermeasures(id).length` | D3FEND countermeasures |
| `atomic` | `AtomicService` test count from Navigator layer | Atomic Red Team tests |
| `engage` | `EngageService` activity count | MITRE Engage activities |
| `car` | `CARService` analytic count | CAR analytics |
| `cve` | `AttackCveService` CVE mapping count | CVE exposures |
| `detection` | Weighted CAR + Atomic + D3FEND | Combined detection coverage |
| `sigma` | `SigmaService.getRuleCount()` | SigmaHQ rule count |
| `nist` | `NistMappingService` control count | NIST 800-53 controls |
| `veris` | `VerisService` action count | VERIS incident actions |
| `epss` | `EpssService` average EPSS score | Exploitation probability |
| `elastic` | `ElasticService.getRuleCount()` | Elastic detection rules |
| `splunk` | `SplunkContentService.getRuleCount()` | Splunk content rules |
| `cri` | `CriProfileService` control count | CRI Profile controls |
| `unified` | Weighted composite of all sources | 0-100 unified risk score |
| `intelligence` | Threat intelligence indicators | CTI indicator count |

Results are stored in per-mode `Map<string, number>` fields on `MatrixComponent` (e.g.
`exposureScores`, `sigmaScoreMap`, `nistScoreMap`) along with a `maxScore` value for
normalization.

**File:** `src/app/components/matrix/matrix.component.ts`

### Step 4: Score Normalization

Each score is normalized to a 0-4 integer bucket (or 0.0-1.0 float for continuous modes) by
dividing by the mode's `maxScore`.  The normalized value selects one of five colors from the
active color theme.

### Step 5: Color Resolution

`SettingsService` provides five configurable color themes:
- `default`: `['#d32f2f', '#e65100', '#f9a825', '#558b2f', '#1b5e20']`
- `redgreen`, `blueorange`, `monochrome`, `accessible`

The `TechniqueCellComponent` receives the score and heatmap mode as `@Input()` properties and
uses the `tinycolor2` library to compute the final background color with appropriate contrast.

**File:** `src/app/components/technique-cell/technique-cell.component.ts`

### Step 6: Cell Rendering

`TechniqueCellComponent` renders a single matrix cell.  It applies the heatmap background color
via inline `[style.background]`, displays the technique ID, name, mitigation count badge, and
optional indicator icons (notes, annotations, watchlist, tags).

### Step 7: Legend Update

`LegendComponent` reads the current heatmap mode and color theme to render a matching color
legend below the matrix.

### Adding a New Heatmap Mode

1. Add the mode name to the `HeatmapMode` union in `src/app/services/filter.service.ts`.
2. Add a new `Map<string, number>` score field and `maxScore` field on `MatrixComponent`.
3. Add scoring logic in the `ngOnChanges` / `combineLatest` subscription block in
   `MatrixComponent` that populates the score map.
4. Add a `case` in the `TechniqueCellComponent` color resolution logic.
5. Add the mode to the toolbar heatmap dropdown in `ToolbarComponent`.
6. Add a legend entry in `LegendComponent`.

---

## 7. Sidebar Architecture

**File:** `src/app/components/sidebar/sidebar.component.ts`

The sidebar is the richest single component in the application.  It injects 23 services and
renders 25+ data sections for the selected technique.

### Service Injections

`FilterService`, `DataService`, `ImplementationService`, `DocumentationService`,
`D3fendService`, `EngageService`, `CARService`, `AtomicService`, `TaggingService`,
`AttackCveService`, `NistMappingService`, `CisControlsService`, `CloudControlsService`,
`VerisService`, `CriProfileService`, `CapecService`, `SettingsService`,
`CustomMitigationService`, `AnnotationService`, `WatchlistService`, `MispService`,
`SigmaService`, `OpenCtiService`, `CweService`, `EpssService`, `ExploitdbService`,
`NucleiService`, `ChangeDetectorRef`.

### Data Sections

| Section | Data Source | Content |
|---|---|---|
| Completeness Score | Computed locally | 0-100 score with letter grade and color ring |
| Signal Pills | Aggregated counts | Compact badges: mitigations, groups, CVEs, D3FEND, etc. |
| Annotation | `AnnotationService` | Color-coded note with pin toggle |
| Mitigations | `DataService` (domain maps) | Direct + parent mitigations with impl status badges |
| Custom Mitigations | `CustomMitigationService` | User-defined mitigations linked to technique |
| Threat Groups | `DataService` (domain maps) | Groups known to use this technique |
| Software | `DataService` (domain maps) | Malware/tools using this technique |
| Campaigns | `DataService` (domain maps) | Campaigns using this technique |
| Procedures | `DataService` (domain maps) | Procedure examples from groups/software |
| Sub-techniques | `DataService` | Child techniques (if parent) |
| Detection / Data Components | `DataService` | ATT&CK data sources and components |
| D3FEND | `D3fendService` | Defensive countermeasures (Harden/Detect/Isolate/Deceive/Evict) |
| Engage | `EngageService` | MITRE Engage activities (Expose/Affect/Elicit/Prepare/Understand) |
| CAR | `CARService` | Cyber Analytics Repository analytics with pseudocode |
| Atomic Red Team | `AtomicService` | Red team test procedures; live YAML fetching |
| Sigma | `SigmaService` | SigmaHQ detection rule count |
| CVE Exposure | `AttackCveService` | CTID ATT&CK-to-CVE + KEV mappings |
| EPSS | `EpssService` | Average EPSS score for technique's CVEs |
| NIST 800-53 | `NistMappingService` | Mapped NIST controls (family, description) |
| CIS + Cloud Controls | `CisControlsService`, `CloudControlsService` | AWS/Azure/GCP/CIS mappings |
| VERIS | `VerisService` | VERIS incident action mappings |
| CRI Profile | `CriProfileService` | Cyber Risk Institute profile controls |
| CAPEC | `CapecService` | Common Attack Pattern Enumeration entries |
| ExploitDB | `ExploitdbService` | Public exploit count |
| Nuclei | `NucleiService` | Nuclei template count |
| MISP | `MispService` | Galaxy cluster data, tags for hunting |
| OpenCTI | `OpenCtiService` | Live indicators and threat actors (requires API config) |
| Tags | `TaggingService` | User-assigned tags with presets |
| Notes | `DocumentationService` | Free-form analyst notes |
| Relationship Graph | Computed locally | Force-directed graph of technique relationships |

### Collapsible Sections

Every section is independently collapsible.  State is tracked in a `Set<string>` called
`collapsedSections`.  The `expandRelevant()` method auto-collapses sections with no data and
expands those with content.

### Completeness Score

Computed in `computeCompleteness()` as a weighted sum:

| Factor | Points |
|---|---|
| Has mitigations | +15 |
| Has CVE exposures | +10 |
| Has NIST controls | +10 |
| Has D3FEND countermeasures | +10 |
| Has Atomic Red Team tests | +10 |
| Has Sigma rules | +10 |
| Has threat groups | +5 |
| Has software | +5 |
| Has CAPEC entries | +5 |
| Has CIS/Cloud controls | +5 |
| Has Engage activities | +5 |
| Has CAR analytics | +5 |
| Has data components | +5 |

Maximum is capped at 100.

### Signal Pills

Compact colored badges displayed at the top of the sidebar summarizing key counts (e.g.
"3 mitigations", "5 CVEs", "2 D3FEND") with color-coded severity.

---

## 8. Panel System

### ActivePanel Type

The `ActivePanel` type union (defined in `FilterService`) lists 36 named panel identifiers plus
`null` (no panel open).  At most one panel is visible at a time.

### Visibility Control

Panel visibility is driven entirely by `FilterService.activePanel$`:

1. `NavRailComponent` icon click calls `FilterService.togglePanel('panelName')`.
2. `AppComponent` subscribes to `activePanel$` and uses `*ngIf` to conditionally render the
   matching panel component.
3. Only the active panel's component is instantiated; all others are destroyed.

### Opening and Closing

- **Toggle:** `togglePanel(name)` -- if already open, sets to `null`; otherwise sets to `name`.
- **Set:** `setActivePanel(panel)` -- forces a specific panel (or `null` to close).
- **Escape:** Global `keydown` handler in `AppComponent` calls `setActivePanel(null)` on Escape.

### Dark Theme Overlay Pattern

Panels render as full-height overlays on top of the matrix workspace.  The overlay uses a
semi-transparent dark backdrop consistent with the application's dark theme (`#070d14` base).
Each panel component manages its own SCSS scoped styles.

---

## 9. Service Layer Patterns

All 43 services follow a small set of repeating patterns.

### Pattern A: HTTP-Fetched Reference Data

Used by: `NistMappingService`, `VerisService`, `CisControlsService`, `CriProfileService`,
`AttackCveService`, `CapecService`, `D3fendService`, `SigmaService`, `ElasticService`,
`SplunkContentService`, `AtomicService`, `ExploitdbService`, `NucleiService`, `CweService`,
`CloudControlsService`, `ChangelogService`, `NvdBulkService`.

```
@Injectable({ providedIn: 'root' })
export class ExampleService {
  private static readonly URL = 'https://...';

  // Lookup index: ATT&CK technique ID -> data items
  private byTechniqueId = new Map<string, ExampleItem[]>();

  // Standard progress observables
  private loadedSubject = new BehaviorSubject<boolean>(false);
  loaded$ = this.loadedSubject.asObservable();

  private totalSubject = new BehaviorSubject<number>(0);
  total$ = this.totalSubject.asObservable();

  private coveredSubject = new BehaviorSubject<number>(0);
  covered$ = this.coveredSubject.asObservable();

  constructor(private http: HttpClient) {
    this.load();
  }

  private load(): void {
    this.http.get<any>(ExampleService.URL)
      .pipe(catchError(() => of(null)))
      .subscribe(data => {
        if (!data) { this.loadedSubject.next(true); return; }
        this.parseAndIndex(data);
        this.loadedSubject.next(true);
      });
  }

  getForTechnique(attackId: string): ExampleItem[] {
    return this.byTechniqueId.get(attackId) ?? [];
  }
}
```

### Pattern B: localStorage-Persisted User Data

Used by: `ImplementationService`, `DocumentationService`, `ControlsService`, `TaggingService`,
`AnnotationService`, `WatchlistService`, `CustomMitigationService`, `LayersService`,
`SavedViewsService`, `TimelineService`, `SettingsService`.

```
@Injectable({ providedIn: 'root' })
export class ExampleUserService {
  private readonly STORAGE_KEY = 'mitre-nav-example-v1';
  private dataSubject = new BehaviorSubject<DataType>(this.load());
  data$ = this.dataSubject.asObservable();

  private load(): DataType {
    try { return JSON.parse(localStorage.getItem(this.STORAGE_KEY) ?? '...'); }
    catch { return defaultValue; }
  }

  private save(): void {
    localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.dataSubject.value));
  }

  update(newData: DataType): void {
    this.dataSubject.next(newData);
    this.save();
  }
}
```

### Pattern C: Bundled Static Data

Used by: `EngageService`, `CARService`, `YaraService`, `SuricataService`, `ZeekService`.

These services embed their data as TypeScript const arrays (e.g. `const ENGAGE_ACTIVITIES`).
No HTTP fetching is required.  They provide synchronous lookup methods (e.g.
`getForAttackId(id)`).

### Pattern D: External API Integration

Used by: `OpenCtiService`, `MispService`, `EpssService`, `CveService`.

These services require user-configured API credentials (URL + token).  Configuration is stored
in `SettingsService`.  They expose `connect()` / `disconnect()` methods and a `connected`
boolean.  Queries are made on demand (not on construction).

---

## 10. Styling Conventions

### Dark Theme

The default color system is built on a dark base:

| Token | Value | Usage |
|---|---|---|
| Background base | `#070d14` | Page and panel backgrounds |
| Surface | `#0f1923` | Cards, sidebar, overlays |
| Border | `#1a2332` | Section dividers |
| Text primary | `#e0e6ed` | Body text |
| Text secondary | `#8899aa` | Labels, muted text |
| Accent | `#64b5f6` | Links, active states |

A `.light-mode` class on `<body>` inverts the palette.

### SCSS Component Scoping

Every component has a colocated `.scss` file that uses Angular's default `ViewEncapsulation.Emulated`
(attribute-scoped selectors).  No global styles leak between components.

### Mobile Breakpoints

| Breakpoint | Target |
|---|---|
| `@media (max-width: 768px)` | Tablet -- nav rail collapses, matrix scrolls horizontally |
| `@media (max-width: 480px)` | Phone -- single-column layout, sidebar becomes full-screen |

### Heatmap Color Themes

Five themes available via `SettingsService`:

| Theme | Colors (low to high) |
|---|---|
| `default` | `#d32f2f` - `#e65100` - `#f9a825` - `#558b2f` - `#1b5e20` |
| `redgreen` | `#dc2626` - `#f97316` - `#eab308` - `#16a34a` - `#15803d` |
| `blueorange` | `#1d4ed8` - `#2563eb` - `#0ea5e9` - `#f59e0b` - `#d97706` |
| `monochrome` | `#111827` - `#374151` - `#6b7280` - `#9ca3af` - `#e5e7eb` |
| `accessible` | `#cc0000` - `#ff6600` - `#ffcc00` - `#006600` - `#003300` |

### CSS Custom Properties

The matrix uses `--mz` (matrix zoom) as a CSS custom property bound via `@HostBinding` to
control cell scaling.  Technique cells use `tinycolor2` for runtime contrast calculations.
