# Service API Reference

Complete reference for all 43 services in `src/app/services/`. Each entry documents the class
name, file path, data source, key methods, observables, and injected dependencies.

---

## Table of Contents

1. [Core](#1-core)
2. [Threat Intelligence](#2-threat-intelligence)
3. [Detection](#3-detection)
4. [Vulnerability](#4-vulnerability)
5. [Compliance](#5-compliance)
6. [Defense](#6-defense)
7. [User Data](#7-user-data)
8. [Export](#8-export)
9. [Metadata](#9-metadata)

---

## 1. Core

### DataService

| | |
|---|---|
| **File** | `src/app/services/data.service.ts` |
| **Data Source** | GitHub STIX bundles (live) or `assets/enterprise-attack.json` (bundled) |
| **Cache** | IndexedDB `mitre-navigator-cache` / `stix-bundles`, 24-hour TTL |

**Observables**

| Name | Type | Description |
|---|---|---|
| `domain$` | `Observable<Domain \| null>` | Parsed ATT&CK domain model |
| `loading$` | `Observable<boolean>` | True while STIX bundle is being fetched/parsed |
| `error$` | `Observable<string \| null>` | Error message if loading failed |
| `currentDomain$` | `BehaviorSubject<AttackDomain>` | Active domain identifier (`'enterprise'`, `'ics'`, `'mobile'`) |

**Key Methods**

| Method | Description |
|---|---|
| `loadDomain()` | Fetch and parse the active domain's STIX bundle |
| `switchDomain(domain)` | Clear current domain and reload with a new domain |
| `forceRefresh()` | Delete IDB cache entry and reload from network |
| `setDataSourceMode(mode)` | Switch between `'live'` and `'bundled'` fetch modes |
| `getMitigationsForTechnique(id)` | Synchronous lookup: technique STIX ID to mitigation relationships |
| `getTechniquesForMitigation(id)` | Reverse lookup: mitigation STIX ID to techniques |
| `getGroupsForTechnique(id)` | Lookup threat groups associated with a technique |
| `getTechniquesForGroup(id)` | Lookup techniques used by a threat group |
| `getSoftwareForGroup(id)` | Lookup software that shares techniques with a group |

**Dependencies:** `HttpClient`

---

### FilterService

| | |
|---|---|
| **File** | `src/app/services/filter.service.ts` |
| **Data Source** | In-memory BehaviorSubjects; synced to `window.location.hash` |

**Observables** -- see [ARCHITECTURE.md Section 3](../ARCHITECTURE.md#3-state-management) for the
full list of 20 BehaviorSubjects and 7 derived observables.

**Key Methods**

| Method | Description |
|---|---|
| `selectTechnique(technique)` | Set the selected technique (drives sidebar) |
| `filterByMitigation(mitigation)` | Replace mitigation filter with a single entry (or clear) |
| `addMitigationFilter(mitigation)` | Add a mitigation to the active filter set |
| `removeMitigationFilter(mitigation)` | Remove a mitigation from the active filter set |
| `setTechniqueQuery(q)` | Set the free-text technique search query |
| `setSortMode(mode)` | Set matrix sort order (`'alpha'` or `'coverage'`) |
| `toggleDimUncovered()` | Toggle dimming of uncovered techniques |
| `setPlatformFilter(platform)` | Set single-platform filter |
| `togglePlatform(platform)` | Toggle a platform in multi-platform filter |
| `toggleTacticVisibility(tacticId)` | Show/hide a tactic column |
| `toggleThreatGroup(groupId)` | Toggle a threat group filter |
| `toggleSoftware(softwareId)` | Toggle a software filter |
| `toggleCampaign(campaignId)` | Toggle a campaign filter |
| `setDataSourceFilter(name)` | Set the data source name filter |
| `setActivePanel(panel)` | Set the visible overlay panel |
| `togglePanel(panel)` | Toggle an overlay panel on/off |
| `setHeatmapMode(mode)` | Set the active heatmap coloring mode |
| `setImplStatusFilter(status)` | Filter by implementation status |
| `setCveFilter(techniqueIds)` | Highlight techniques from CVE panel |
| `clearAll()` | Reset all filters to defaults |
| `getStateSnapshot()` | Serialize current state for layer save |
| `restoreStateSnapshot(state)` | Restore state from a saved layer |

**Dependencies:** `DataService`

---

### UrlStateService

| | |
|---|---|
| **File** | `src/app/services/url-state.service.ts` |
| **Data Source** | `window.location.hash` |

**Key Methods**

| Method | Description |
|---|---|
| `restoreFromUrl()` | Restore filter state from the current URL hash |
| `syncToUrl()` | Force a URL sync on the next tick |
| `getShareUrl()` | Return the full shareable URL with current filter state |

**Dependencies:** `FilterService`

---

### SettingsService

| | |
|---|---|
| **File** | `src/app/services/settings.service.ts` |
| **Data Source** | `localStorage('mitre-nav-settings-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `settings$` | `Observable<AppSettings>` | Current application settings |

**Key Methods**

| Method | Description |
|---|---|
| `current` | Getter returning the current `AppSettings` snapshot |
| `update(partial)` | Merge partial settings and persist |
| `setNvdApiKey(key)` | Update the NVD API key |
| `updateWeights(weights)` | Update scoring weights (auto-normalized to sum 100) |
| `getNormalizedWeights()` | Return weights normalized to sum to 100 |
| `getCoverageColors()` | Return the 5-color array for the active heatmap theme |

**Dependencies:** None (standalone)

---

## 2. Threat Intelligence

### MispService

| | |
|---|---|
| **File** | `src/app/services/misp.service.ts` |
| **Data Source** | MISP Galaxy JSON from GitHub (bundled); live MISP API (configurable) |

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when galaxy data is indexed |
| `total$` | `Observable<number>` | Total galaxy cluster count |

**Key Methods**

| Method | Description |
|---|---|
| `getCluster(attackId)` | Return the MISP galaxy cluster for a technique |
| `getAll()` | Return all galaxy clusters |
| `getMispTags(attackId)` | Generate MISP-format tags for a technique |
| `generateEventTemplate(attackId, name)` | Create a MISP event JSON template |
| `search(query)` | Search clusters by name or description |
| `getAttributesForTechnique(attackId)` | Fetch attributes from live MISP instance |
| `getEventsForTechnique(attackId)` | Fetch events from live MISP instance |
| `saveConfig(config)` | Save MISP API configuration |
| `getConfig()` | Retrieve current MISP API configuration |

**Dependencies:** `HttpClient`

---

### OpenCtiService

| | |
|---|---|
| **File** | `src/app/services/opencti.service.ts` |
| **Data Source** | OpenCTI GraphQL API (user-configured URL + token) |

**Observables**

| Name | Type | Description |
|---|---|---|
| `config$` | `Observable<OpenCtiConfig>` | Current connection configuration |

**Key Methods**

| Method | Description |
|---|---|
| `saveConfig(url, token)` | Save OpenCTI API credentials and test connection |
| `getConfig()` | Retrieve current configuration |
| `getIndicatorsForTechnique(attackId)` | Query indicators mapped to a technique |
| `getThreatActorsForTechnique(attackId)` | Query threat actors using a technique |
| `importStixBundle(stixJson)` | Push a STIX bundle to the OpenCTI instance |
| `getDemoUrl()` | Return the OpenCTI demo instance URL |

**Dependencies:** `HttpClient`

---

### AttackCveService

| | |
|---|---|
| **File** | `src/app/services/attack-cve.service.ts` |
| **Data Source** | CTID ATT&CK-to-CVE CSV + CTID KEV-to-ATT&CK JSON (GitHub) |

**URLs**
- CSV: `center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv`
- KEV: `center-for-threat-informed-defense/mappings-explorer/.../kev-07.28.2025_attack-16.1-enterprise.json`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when both datasets are indexed |
| `total$` | `Observable<number>` | Total CVE-to-technique mapping count |
| `covered$` | `Observable<number>` | Techniques with at least one CVE mapping |

**Key Methods**

| Method | Description |
|---|---|
| `getCvesForTechnique(attackId)` | Return all CVE mappings for a technique |
| `getMappingForCve(cveId)` | Reverse lookup: CVE ID to its mapping record |
| `getExploitCvesForTechnique(attackId)` | Return exploitation-phase CVE IDs for a technique |
| `getKevCvesForTechnique(attackId)` | Return KEV-sourced mappings for a technique |

**Dependencies:** `HttpClient`

---

### EpssService

| | |
|---|---|
| **File** | `src/app/services/epss.service.ts` |
| **Data Source** | FIRST.org EPSS API (`https://api.first.org/data/v1/epss`) |

**Key Methods**

| Method | Description |
|---|---|
| `fetchScores(cveIds)` | Batch-fetch EPSS scores for CVE IDs (groups of 100); returns cached results when available |

**Dependencies:** `HttpClient`

---

## 3. Detection

### SigmaService

| | |
|---|---|
| **File** | `src/app/services/sigma.service.ts` |
| **Data Source** | SigmaHQ Navigator layer JSON (GitHub); bundled logsource mappings |

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when live layer is loaded |
| `total$` | `Observable<number>` | Total Sigma rule count |
| `covered$` | `Observable<number>` | Techniques with at least one Sigma rule |

**Key Methods**

| Method | Description |
|---|---|
| `getRuleCount(techniqueId)` | Return the number of Sigma rules for a technique |
| `getHeatScore(techniqueId)` | Alias for `getRuleCount` (used by heatmap) |
| `getLiveCounts()` | Return the full live count map |
| `generateRuleForTechnique(tech)` | Generate a Sigma rule YAML for a technique |
| `generateRulesForTechniques(techs)` | Batch generate rules as a single YAML string |
| `exportRules(techs)` | Download generated rules as a `.yml` file |

**Dependencies:** `HttpClient`

---

### ElasticService

| | |
|---|---|
| **File** | `src/app/services/elastic.service.ts` |
| **Data Source** | Elastic detection-rules Navigator layer JSON (GitHub) |

**URL:** `elastic/detection-rules/main/etc/attack-navigator-layer.json`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when layer is loaded |
| `total$` | `Observable<number>` | Total Elastic detection rule count |
| `covered$` | `Observable<number>` | Techniques with at least one Elastic rule |

**Key Methods**

| Method | Description |
|---|---|
| `getRuleCount(attackId)` | Return the Elastic rule count for a technique |
| `getHeatScore(attackId)` | Alias for `getRuleCount` |

**Dependencies:** `HttpClient`

---

### SplunkContentService

| | |
|---|---|
| **File** | `src/app/services/splunk-content.service.ts` |
| **Data Source** | Splunk security_content Navigator layer JSON (GitHub) |

**URL:** `splunk/security_content/develop/dist/attack_navigator_layer.json`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when layer is loaded |
| `total$` | `Observable<number>` | Total Splunk content rule count |
| `covered$` | `Observable<number>` | Techniques with at least one Splunk rule |

**Key Methods**

| Method | Description |
|---|---|
| `getRuleCount(attackId)` | Return the Splunk rule count for a technique |
| `getHeatScore(attackId)` | Alias for `getRuleCount` |

**Dependencies:** `HttpClient`

---

### CARService

| | |
|---|---|
| **File** | `src/app/services/car.service.ts` |
| **Data Source** | Bundled static array + live CAR Navigator layer JSON (GitHub) |

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when live layer is loaded |
| `total$` | `Observable<number>` | Total CAR analytic count |
| `covered$` | `Observable<number>` | Techniques with at least one CAR analytic |

**Key Methods**

| Method | Description |
|---|---|
| `getAnalytics(attackId)` | Return bundled CAR analytics for a technique |
| `getLiveCount(attackId)` | Return the live count from the Navigator layer |
| `getAll()` | Return all bundled CAR analytics |

**Dependencies:** `HttpClient`

---

### AtomicService

| | |
|---|---|
| **File** | `src/app/services/atomic.service.ts` |
| **Data Source** | Bundled test records + Atomic Red Team Navigator layer JSON (GitHub) |

**URLs**
- Navigator layer: `redcanaryco/atomic-red-team/.../layer.json`
- Live YAML: Individual technique YAML files on GitHub

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when Navigator layer is loaded |
| `total$` | `Observable<number>` | Total Atomic test count |
| `covered$` | `Observable<number>` | Techniques with at least one Atomic test |

**Key Methods**

| Method | Description |
|---|---|
| `getTestCount(attackId)` | Return the test count for a technique |
| `getHeatScore(attackId)` | Alias for `getTestCount` |
| `getTests(attackId)` | Return bundled test records for a technique |
| `getAtomicUrl(attackId)` | Return the GitHub URL for a technique's tests |
| `getLiveCounts()` | Return the full live count map |
| `getAll()` | Return all bundled test records |
| `fetchLiveTests(attackId, limit)` | Fetch live YAML test details from GitHub |

**Dependencies:** `HttpClient`

---

## 4. Vulnerability

### CveService

| | |
|---|---|
| **File** | `src/app/services/cve.service.ts` |
| **Data Source** | NVD 2.0 API + CISA KEV JSON |

**URLs**
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**Observables**

| Name | Type | Description |
|---|---|---|
| `kevEntries$` | `Observable<KevEntry[]>` | All CISA KEV entries |
| `searchResults$` | `Observable<NvdCveItem[]>` | NVD search results |
| `loading$` | `Observable<boolean>` | True during NVD API calls |

**Key Methods**

| Method | Description |
|---|---|
| `loadKev()` | Fetch and index the CISA KEV catalog |
| `searchCves(query)` | Search NVD for CVEs by keyword |
| `getKevScoresFromCtid(kevCveIds)` | Compute per-technique KEV CVE counts |
| `getAttackToCweIds(attackId)` | Reverse-lookup CWE IDs that map to a technique |
| `fetchNvdCvesByAttackId(attackId, apiKey)` | Fetch NVD CVEs mapped to a technique via CWE bridge |
| `getKevEntry(cveId)` | Lookup a single KEV entry by CVE ID |

**Exports:** `CWE_TO_ATTACK` constant (200+ CWE-to-ATT&CK mappings), `mapCwesToAttackIds()` function.

**Dependencies:** `HttpClient`, `AttackCveService`

---

### CweService

| | |
|---|---|
| **File** | `src/app/services/cwe.service.ts` |
| **Data Source** | Bundled static map + `assets/data/cwe-catalog.json` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when catalog is loaded |

**Key Methods**

| Method | Description |
|---|---|
| `getInfo(cweId)` | Return name, description, and URL for a CWE ID |
| `getUrl(cweId)` | Return the MITRE CWE page URL |

**Dependencies:** `HttpClient`

---

### NvdBulkService

| | |
|---|---|
| **File** | `src/app/services/nvd-bulk.service.ts` |
| **Data Source** | NVD 2.0 API (last 120 days of CVEs) |

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when bulk fetch is complete |
| `total$` | `Observable<number>` | Total CVEs fetched |
| `covered$` | `Observable<number>` | Techniques with at least one supplementary CVE |

**Key Methods**

| Method | Description |
|---|---|
| `getCveCountForTechnique(attackId)` | Return supplementary CVE count for a technique |
| `getCvesForTechnique(attackId)` | Return supplementary CVE IDs for a technique |

**Dependencies:** `HttpClient`, `AttackCveService`, `SettingsService`

---

### ExploitdbService

| | |
|---|---|
| **File** | `src/app/services/exploitdb.service.ts` |
| **Data Source** | ExploitDB `files_exploits.csv` (GitLab) |

**URL:** `exploit-database/exploitdb/-/raw/main/files_exploits.csv`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when CSV is parsed |
| `total$` | `Observable<number>` | Exploits mapped to at least one technique |

**Key Methods**

| Method | Description |
|---|---|
| `getExploitCount(attackId)` | Return the exploit count for a technique |

**Dependencies:** `HttpClient`, `AttackCveService`

---

### NucleiService

| | |
|---|---|
| **File** | `src/app/services/nuclei.service.ts` |
| **Data Source** | GitHub API tree of `projectdiscovery/nuclei-templates` |

**URL:** `api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when tree is indexed |
| `total$` | `Observable<number>` | Nuclei CVE templates mapped to techniques |
| `covered$` | `Observable<number>` | Techniques with at least one Nuclei template |

**Key Methods**

| Method | Description |
|---|---|
| `getTemplateCount(attackId)` | Return the Nuclei template count for a technique |

**Dependencies:** `HttpClient`, `AttackCveService`

---

### CapecService

| | |
|---|---|
| **File** | `src/app/services/capec.service.ts` |
| **Data Source** | CAPEC 3.x STIX bundle from MITRE CTI repo (GitHub) |

**URL:** `mitre/cti/master/capec/2.1/stix-capec.json`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when bundle is parsed |
| `total$` | `Observable<number>` | Total CAPEC entries indexed |

**Key Methods**

| Method | Description |
|---|---|
| `getCapecForTechnique(attackId)` | Return CAPEC entries mapped to a technique |
| `getCapecCount(attackId)` | Return the count of CAPEC entries for a technique |
| `getCapecForCwe(cweId)` | Return CAPEC entries related to a CWE |

**Dependencies:** `HttpClient`

---

## 5. Compliance

### NistMappingService

| | |
|---|---|
| **File** | `src/app/services/nist-mapping.service.ts` |
| **Data Source** | CTID mappings-explorer NIST 800-53 Rev5 JSON (GitHub) |

**URL:** `center-for-threat-informed-defense/mappings-explorer/.../nist_800_53-rev5_attack-16.1-enterprise.json`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when mapping is indexed |
| `total$` | `Observable<number>` | Total unique NIST control mappings |

**Key Methods**

| Method | Description |
|---|---|
| `getControlsForTechnique(attackId)` | Return NIST 800-53 controls mapped to a technique |
| `getControlCount(attackId)` | Return the control count for a technique |

**Dependencies:** `HttpClient`

---

### CisControlsService

| | |
|---|---|
| **File** | `src/app/services/cis-controls.service.ts` |
| **Data Source** | Currently unavailable (CIS Controls removed from CTID as of ATT&CK v16) |

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | Always `true` (loads empty) |
| `total$` | `Observable<number>` | Always `0` |

**Key Methods**

| Method | Description |
|---|---|
| `getControlsForTechnique(attackId)` | Return CIS controls for a technique (currently empty) |

**Dependencies:** `HttpClient`

---

### CloudControlsService

| | |
|---|---|
| **File** | `src/app/services/cloud-controls.service.ts` |
| **Data Source** | CTID mappings-explorer: AWS, Azure, and GCP control mapping JSONs (GitHub) |

**URLs**
- AWS: `center-for-threat-informed-defense/mappings-explorer/.../aws-12.12.2024_attack-16.1-enterprise.json`
- Azure: `center-for-threat-informed-defense/mappings-explorer/.../azure-04.26.2025_attack-16.1-enterprise.json`
- GCP: `center-for-threat-informed-defense/mappings-explorer/.../gcp-03.06.2025_attack-16.1-enterprise.json`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when all three providers are loaded (combined) |
| `awsTotalSubject` / `azureTotalSubject` / `gcpTotalSubject` | `BehaviorSubject<number>` | Per-provider control counts |

**Key Methods**

| Method | Description |
|---|---|
| `getControlsForTechnique(attackId, provider?)` | Return cloud controls, optionally filtered by provider |
| `getProviderTotal(provider)` | Return total control count for a specific provider |

**Dependencies:** `HttpClient`

---

### CriProfileService

| | |
|---|---|
| **File** | `src/app/services/cri-profile.service.ts` |
| **Data Source** | CTID mappings-explorer CRI Profile v2.1 JSON (GitHub) |

**URL:** `center-for-threat-informed-defense/mappings-explorer/.../cri_profile-v2.1_attack-16.1-enterprise.json`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when mapping is indexed |
| `total$` | `Observable<number>` | Total CRI control mappings |

**Key Methods**

| Method | Description |
|---|---|
| `getControlsForTechnique(attackId)` | Return CRI controls mapped to a technique |
| `getControlCount(attackId)` | Return the count of CRI controls for a technique |
| `getGroupedControls(attackId)` | Return controls grouped by CRI function (GV/ID/PR/DE/RS/RC) |

**Dependencies:** `HttpClient`

---

### VerisService

| | |
|---|---|
| **File** | `src/app/services/veris.service.ts` |
| **Data Source** | CTID mappings-explorer VERIS 1.4.0 JSON (GitHub) |

**URL:** `center-for-threat-informed-defense/mappings-explorer/.../veris-1.4.0_attack-16.1-enterprise.json`

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `Observable<boolean>` | True when mapping is indexed |
| `total$` | `Observable<number>` | Total VERIS action mappings |

**Key Methods**

| Method | Description |
|---|---|
| `getActionsForTechnique(attackId)` | Return VERIS incident actions mapped to a technique |

**Dependencies:** `HttpClient`

---

## 6. Defense

### D3fendService

| | |
|---|---|
| **File** | `src/app/services/d3fend.service.ts` |
| **Data Source** | Bundled static mapping (~100 countermeasures) + live D3FEND ontology fetch |

**Observables**

| Name | Type | Description |
|---|---|---|
| `loaded$` | `BehaviorSubject<boolean>` | True (bundled data is immediately available) |
| `total$` | `Observable<number>` | Total D3FEND countermeasures indexed |

**Key Methods**

| Method | Description |
|---|---|
| `getCountermeasures(attackId)` | Return D3FEND techniques that counter an ATT&CK technique |
| `getAllTechniques()` | Return all D3FEND countermeasures |
| `getAllByCategory()` | Return countermeasures grouped by category (Harden/Detect/Isolate/Deceive/Evict) |
| `loadLiveOntology()` | Fetch and merge the live D3FEND OWL ontology |

**Dependencies:** `HttpClient`

---

### EngageService

| | |
|---|---|
| **File** | `src/app/services/engage.service.ts` |
| **Data Source** | Bundled static array of MITRE Engage activities |

**Key Methods**

| Method | Description |
|---|---|
| `getActivities(attackId)` | Return Engage activities targeting a technique |

**Dependencies:** None (standalone, bundled data)

---

### ZeekService

| | |
|---|---|
| **File** | `src/app/services/zeek.service.ts` |
| **Data Source** | Bundled Zeek script templates |

**Key Methods**

| Method | Description |
|---|---|
| `getScripts(attackId)` | Return Zeek detection scripts for a technique |
| `generateScriptsForTechnique(tech)` | Generate Zeek scripts for a technique |
| `generatePackageForTechniques(techniques)` | Generate a combined Zeek package |
| `exportScripts(techniques)` | Download Zeek scripts as a file |
| `getSupportedTechniqueIds()` | Return all technique IDs with Zeek coverage |
| `getScriptCount()` | Return total available script count |

**Dependencies:** None (standalone, bundled data)

---

### SuricataService

| | |
|---|---|
| **File** | `src/app/services/suricata.service.ts` |
| **Data Source** | Bundled Suricata rule templates |

**Key Methods**

| Method | Description |
|---|---|
| `getRules(attackId)` | Return Suricata rules for a technique |
| `generateRulesForTechnique(tech)` | Generate Suricata rules for a technique |
| `generateRulesForTechniques(techniques)` | Generate combined Suricata rules as a string |
| `exportRules(techniques)` | Download Suricata rules as a `.rules` file |
| `getSupportedTechniqueIds()` | Return all technique IDs with Suricata coverage |
| `getRuleCount()` | Return total available rule count |

**Dependencies:** None (standalone, bundled data)

---

### YaraService

| | |
|---|---|
| **File** | `src/app/services/yara.service.ts` |
| **Data Source** | Bundled YARA pattern templates |

**Key Methods**

| Method | Description |
|---|---|
| `getPattern(attackId)` | Return the YARA pattern for a technique |
| `generateRule(tech)` | Generate a complete YARA rule for a technique |
| `generateRules(techniques)` | Batch generate YARA rules |
| `exportRules(rules)` | Download YARA rules as a `.yar` file |
| `getAllPatterns()` | Return all bundled patterns |

**Dependencies:** None (standalone, bundled data)

---

## 7. User Data

### AnnotationService

| | |
|---|---|
| **File** | `src/app/services/annotation.service.ts` |
| **Data Source** | `localStorage('mitre-nav-annotations-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `annotations$` | `Observable<Map<string, TechniqueAnnotation>>` | All annotations keyed by technique ID |

**Key Methods**

| Method | Description |
|---|---|
| `setAnnotation(techniqueId, note, color?, isPinned?)` | Create or update an annotation |
| `getAnnotation(techniqueId)` | Retrieve an annotation by technique ID |
| `deleteAnnotation(techniqueId)` | Remove an annotation |
| `all` | Getter returning the full annotation map |

**Dependencies:** None

---

### TaggingService

| | |
|---|---|
| **File** | `src/app/services/tagging.service.ts` |
| **Data Source** | `localStorage('mitre-nav-tags-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `tags$` | `Observable<Map<string, Set<string>>>` | Technique ID to tag set mapping |

**Key Methods**

| Method | Description |
|---|---|
| `getTags(techniqueId)` | Return tags for a technique |
| `addTag(techniqueId, tag)` | Add a tag to a technique |
| `removeTag(techniqueId, tag)` | Remove a tag from a technique |
| `toggleTag(techniqueId, tag)` | Toggle a tag on/off |
| `clearTags(techniqueId)` | Remove all tags from a technique |
| `getAllUsedTags()` | Return all tags currently in use |
| `getTechniquesWithTag(tag)` | Return technique IDs that have a specific tag |
| `exportTags()` | Download tags as a JSON file |

**Preset tags:** `in-scope`, `out-of-scope`, `priority-q1`, `priority-q2`, `tested`, `excluded`, `review`.

**Dependencies:** None

---

### DocumentationService

| | |
|---|---|
| **File** | `src/app/services/documentation.service.ts` |
| **Data Source** | `localStorage('mitre-nav-docs-mit-v1')` and `localStorage('mitre-nav-docs-tech-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `mitDocs$` | `Observable<Map<string, MitigationDoc>>` | Mitigation documentation records |
| `techNotes$` | `Observable<Map<string, string>>` | Per-technique analyst notes |

**Key Methods**

| Method | Description |
|---|---|
| `getMitDoc(mitigationId)` | Return documentation for a mitigation (or empty default) |
| `setMitDoc(mitigationId, doc)` | Create or update mitigation documentation |
| `getTechNote(techniqueId)` | Return the analyst note for a technique |
| `setTechNote(techniqueId, note)` | Set or clear the analyst note for a technique |
| `exportJson()` | Serialize all documentation as JSON |
| `importJson(json)` | Restore documentation from JSON |

**MitigationDoc fields:** `notes`, `owner`, `dueDate`, `controlRefs`, `evidenceUrl`.

**Dependencies:** None

---

### ImplementationService

| | |
|---|---|
| **File** | `src/app/services/implementation.service.ts` |
| **Data Source** | `localStorage('mitre-nav-impl-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `status$` | `Observable<Map<string, ImplStatus>>` | Mitigation ID to implementation status |

**Key Methods**

| Method | Description |
|---|---|
| `setStatus(mitigationId, status)` | Set or clear the status for a mitigation |
| `getStatus(mitigationId)` | Return the status for a mitigation |
| `getImplementedIds()` | Return the set of mitigation IDs with `'implemented'` status |
| `getStatusMap()` | Return the full status map |
| `exportJson()` | Serialize all statuses as JSON |
| `importJson(json)` | Restore statuses from JSON |

**Status values:** `'implemented'`, `'in-progress'`, `'planned'`, `'not-started'`.

**Dependencies:** None

---

### CustomMitigationService

| | |
|---|---|
| **File** | `src/app/services/custom-mitigation.service.ts` |
| **Data Source** | `localStorage('mitre-nav-custom-mitigations-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `mitigations$` | `Observable<CustomMitigation[]>` | All custom mitigations |

**Key Methods**

| Method | Description |
|---|---|
| `create(data)` | Create a new custom mitigation with auto-generated ID (`CM-001`) |
| `update(id, data)` | Update an existing custom mitigation |
| `delete(id)` | Remove a custom mitigation |
| `getForTechnique(techniqueId)` | Return custom mitigations linked to a technique |
| `getTechniqueIds(mitigationId)` | Return technique IDs linked to a custom mitigation |
| `all` | Getter returning all custom mitigations |

**Dependencies:** None

---

### WatchlistService

| | |
|---|---|
| **File** | `src/app/services/watchlist.service.ts` |
| **Data Source** | `localStorage('mitre-nav-watchlist-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `entries$` | `Observable<WatchlistEntry[]>` | All watchlist entries |

**Key Methods**

| Method | Description |
|---|---|
| `add(technique, priority?)` | Add a technique to the watchlist |
| `remove(techniqueId)` | Remove a technique from the watchlist |
| `toggle(technique)` | Toggle watchlist membership |
| `isWatched(techniqueId)` | Check if a technique is on the watchlist |
| `updateNote(techniqueId, note)` | Update the note for a watchlist entry |
| `updatePriority(techniqueId, priority)` | Update priority (`'high'`, `'medium'`, `'low'`) |
| `all` | Getter returning all entries |

**Dependencies:** None

---

### ControlsService

| | |
|---|---|
| **File** | `src/app/services/controls.service.ts` |
| **Data Source** | `localStorage('mitre-nav-controls-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `controls$` | `Observable<SecurityControl[]>` | All user-defined security controls |

**Key Methods**

| Method | Description |
|---|---|
| `addControl(ctrl)` | Add a new security control |
| `updateControl(id, updates)` | Update an existing control |
| `removeControl(id)` | Delete a control |
| `importFromTemplate(template, domain, status)` | Bulk-import controls from a framework template |
| `clearAll()` | Remove all controls |
| `exportJson()` | Serialize controls as JSON |
| `importJson(json)` | Restore controls from JSON |
| `computeCoverage(controls, domain)` | Compute coverage statistics for a set of controls |

**Dependencies:** None

---

### SavedViewsService

| | |
|---|---|
| **File** | `src/app/services/saved-views.service.ts` |
| **Data Source** | `localStorage('mitre-nav-views-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `views$` | `Observable<SavedView[]>` | All saved views |

**Key Methods**

| Method | Description |
|---|---|
| `saveCurrentView(name, description)` | Save the current URL hash and heatmap mode as a named view |
| `restoreView(view)` | Navigate to a saved view's URL hash |
| `deleteView(id)` | Remove a saved view |
| `all` | Getter returning all saved views |

**Dependencies:** None

---

### LayersService

| | |
|---|---|
| **File** | `src/app/services/layers.service.ts` |
| **Data Source** | `localStorage('mitre-nav-layers-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `layers$` | `Observable<LayerSnapshot[]>` | All saved layer snapshots |

**Key Methods**

| Method | Description |
|---|---|
| `saveLayer(name, description, filterService, implService, docService)` | Capture current state as a layer |
| `deleteLayer(id)` | Remove a saved layer |
| `exportLayer(layer)` | Download a layer as a JSON file |
| `importLayer(json)` | Import a layer from JSON |

**Dependencies:** None (receives services as method arguments)

---

### TimelineService

| | |
|---|---|
| **File** | `src/app/services/timeline.service.ts` |
| **Data Source** | `localStorage('mitre-nav-timeline-v1')` |

**Observables**

| Name | Type | Description |
|---|---|---|
| `snapshots$` | `Observable<CoverageSnapshot[]>` | All coverage snapshots |

**Key Methods**

| Method | Description |
|---|---|
| `takeSnapshot(domain, implStatusMap, label, notes)` | Capture current coverage metrics as a snapshot |
| `deleteSnapshot(id)` | Remove a snapshot |
| `updateLabel(id, label)` | Rename a snapshot |
| `updateNotes(id, notes)` | Update snapshot notes |
| `getAll()` | Return all snapshots |
| `getLatest()` | Return the most recent snapshot |
| `exportCsv()` | Download snapshots as a CSV file |

**CoverageSnapshot fields:** total/covered technique counts, coverage percentage, per-tactic
breakdown, implementation status counts.

**Dependencies:** None

---

## 8. Export

### HtmlReportService

| | |
|---|---|
| **File** | `src/app/services/html-report.service.ts` |
| **Data Source** | Generates HTML from Domain model data |

**Key Methods**

| Method | Description |
|---|---|
| `generateAndOpen(domain, implStatusMap)` | Build a full HTML coverage report and open in a new tab |

**Dependencies:** None (standalone)

---

### MatrixExportService

| | |
|---|---|
| **File** | `src/app/services/matrix-export.service.ts` |
| **Data Source** | Renders Domain model data to a Canvas element |

**Key Methods**

| Method | Description |
|---|---|
| `exportPng(domain, implStatusMap, heatmapMode)` | Render the matrix to a Canvas and download as PNG (2x DPI) |

**Dependencies:** None (standalone)

---

### XlsxExportService

| | |
|---|---|
| **File** | `src/app/services/xlsx-export.service.ts` |
| **Data Source** | Generates Excel workbook from Domain model data |

**Key Methods**

| Method | Description |
|---|---|
| `exportWorkbook(domain, implStatusMap, customMitigations, snapshots)` | Build and download a multi-sheet XLSX workbook (Overview, Techniques, Subtechniques, Mitigations, Custom Mitigations, Timeline) |

**Dependencies:** `xlsx` (SheetJS library)

---

## 9. Metadata

### ChangelogService

| | |
|---|---|
| **File** | `src/app/services/changelog.service.ts` |
| **Data Source** | GitHub API releases endpoint |

**URL:** `https://api.github.com/repos/mitre-attack/attack-stix-data/releases?per_page=5`

**Observables**

| Name | Type | Description |
|---|---|---|
| `releases$` | `Observable<AttackRelease[]>` | Most recent ATT&CK data releases |
| `loaded$` | `Observable<boolean>` | True when releases are fetched |

**Key Methods:** None (data exposed via observables only).

**Dependencies:** `HttpClient`
