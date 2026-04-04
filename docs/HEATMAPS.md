# Heatmap Modes Reference

> Complete reference for all 24 heatmap coloring modes in the MITRE ATT&CK Navi.
> Each mode recolors every technique cell in the matrix to visualize a different security dimension.

---

## Summary Table

| # | Mode ID | Display Label | Legend Label | Scale Type | Data Source Service | What the Score Represents |
|---|---------|--------------|--------------|------------|--------------------|----|
| 1 | `coverage` | Coverage | Mitigations | Gradient (5) | `Domain.mitigationsByTechnique` | Count of mapped ATT&CK mitigations (0, 1, 2, 3, 4+) |
| 2 | `risk` | Risk | Risk Score | Gradient (5) | Computed in `MatrixComponent` | `groupCount * (1 + 1/(mitigationCount+1))` |
| 3 | `exposure` | Exposure | Exposure | Gradient (5) | `FilterService.activeThreatGroupIds$` | Count of selected threat groups using this technique |
| 4 | `frequency` | Frequency | Groups | Gradient (5) | `Domain.groupsByTechnique` | Total unique threat groups using this technique |
| 5 | `software` | Software | Software | Gradient (5) | `Domain.softwareByTechnique` | Count of ATT&CK software entries using this technique |
| 6 | `campaign` | Campaign | Campaigns | Gradient (5) | `Domain.campaignsByTechnique` | Count of ATT&CK campaigns using this technique |
| 7 | `status` | Status | Status | Categorical (5) | `ImplementationService.status$` | Best implementation status across a technique's mitigations |
| 8 | `controls` | Controls | Controls | Categorical (3) | `ControlsService` | Whether technique is covered/planned/none by security controls |
| 9 | `kev` | KEV | KEV CVEs | Gradient (4) | `CveService.kevTechScores$` | Count of CISA KEV CVEs mapped to this technique |
| 10 | `d3fend` | D3FEND | D3FEND | Gradient (5) | `D3fendService` | Count of D3FEND countermeasure techniques |
| 11 | `atomic` | Atomic | Atomic Tests | Gradient (5) | `AtomicService` | Count of Atomic Red Team test cases |
| 12 | `engage` | Engage | Engage | Gradient (5) | `EngageService` | Count of MITRE Engage activities |
| 13 | `car` | CAR | CAR Analytics | Gradient (5) | `CARService` | Count of Cyber Analytics Repository analytics |
| 14 | `cve` | CVE | CVEs | Gradient (5) | `AttackCveService` | Count of CVEs from CTID ATT&CK-to-CVE dataset |
| 15 | `detection` | Detection | Sigma Rules | Gradient (5) | Computed (multi-service) | Weighted: `sigma*3 + d3fend*2 + car*2 + atomic*1` |
| 16 | `cri` | CRI Profile | CRI Controls | Gradient (5) | `CriProfileService` | Count of CRI Profile controls mapped |
| 17 | `unified` | Unified Risk | Unified Risk | Gradient (5) | Computed (multi-service) | Composite 0--100 score across 5 dimensions |
| 18 | `sigma` | Sigma Rules | Sigma Rules | Gradient (5) | `SigmaService` | Count of Sigma detection rules |
| 19 | `nist` | NIST 800-53 | NIST 800-53 | Gradient (5) | `NistMappingService` | Count of mapped NIST 800-53 controls |
| 20 | `veris` | VERIS Actions | VERIS Actions | Gradient (5) | `VerisService` | Count of VERIS incident action mappings |
| 21 | `epss` | EPSS Prob. | EPSS Probability | Gradient (5) | `EpssService` | Average EPSS exploitation probability (0--1) across mapped CVEs |
| 22 | `elastic` | Elastic Rules | Elastic Rules | Gradient (5) | `ElasticService` | Count of Elastic Detection Rules |
| 23 | `splunk` | Splunk Detections | Splunk Detections | Gradient (5) | `SplunkContentService` | Count of Splunk Security Content detections |
| 24 | `intelligence` | Intelligence | Intel Signals | Gradient (5) | Computed (MISP + groups) | `hasMisp (0/1) + threatGroupCount` |

---

## Heatmap Pipeline: How It Works

When a user selects a heatmap mode, the following seven-step pipeline executes:

### Step 1: Mode Selection (Toolbar)

**File:** `src/app/components/toolbar/toolbar.component.ts` (line ~275)

The toolbar maintains the `heatmapModes` array of 24 `{ value, label }` entries. When the user clicks a mode button or calls `cycleHeatmap()`, it calls `FilterService.setHeatmapMode(mode)`.

### Step 2: State Broadcast (FilterService)

**File:** `src/app/services/filter.service.ts` (line ~28)

`FilterService` holds the `heatmapModeSubject: BehaviorSubject<HeatmapMode>` and exposes `heatmapMode$`. All subscribers are notified of the change.

### Step 3: Score Computation (MatrixComponent)

**File:** `src/app/components/matrix/matrix.component.ts` (lines ~465--710)

`MatrixComponent` subscribes to `heatmapMode$`. On each mode change, it runs the mode-specific score computation:
- Iterates over all `domain.techniques`
- Calls the appropriate service method (e.g., `d3fendService.getCountermeasures()`)
- Populates a `Map<string, number>` (e.g., `d3fendScoreMap`)
- Computes `maxScore` for normalization

### Step 4: Score Binding (Template)

**File:** `src/app/components/matrix/matrix.component.html`

The matrix template passes scores to each `<app-technique-cell>` via `@Input()` bindings:
```html
[d3fendScore]="d3fendScoreMap.get(tech.id) ?? 0"
[maxD3fend]="maxD3fend"
[heatmapMode]="heatmapMode"
```

### Step 5: Cell Coloring (TechniqueCellComponent)

**File:** `src/app/components/technique-cell/technique-cell.component.ts`

Each cell computes its background color from the active `heatmapMode` and its score inputs. For gradient modes, it interpolates between the mode's color stops based on the normalized score. For categorical modes (status, controls), it maps directly to a discrete color. Uses `tinycolor2` for contrast-aware text coloring.

### Step 6: Legend Update (LegendComponent)

**File:** `src/app/components/legend/legend.component.ts` (lines 9--249)

The legend subscribes to `heatmapMode$` and looks up the active mode in `MODE_CONFIGS` to render the correct color stops and labels. Categorical modes suppress the "fewer -- more" arrow.

### Step 7: Cell Color Fallback (MatrixComponent.getCellColor)

**File:** `src/app/components/matrix/matrix.component.ts` (line ~1257)

For the `coverage` and `frequency` modes, `MatrixComponent.getCellColor()` provides a fast-path color lookup. The `coverage` mode uses `SettingsService.getCoverageColors()` to support user theme customization.

---

## Adding a New Heatmap Mode

To add a 25th heatmap mode, modify these seven files in order:

1. **`src/app/services/filter.service.ts`** -- Add the new mode string to the `HeatmapMode` union type.

2. **`src/app/components/toolbar/toolbar.component.ts`** -- Add a `{ value, label }` entry to the `heatmapModes` array (~line 275).

3. **`src/app/components/matrix/matrix.component.ts`** -- Add a new score `Map` field, add an `else if (mode === 'new-mode')` branch in the `heatmapMode$` subscription (~line 467), and populate the score map.

4. **`src/app/components/technique-cell/technique-cell.component.ts`** -- Add an `@Input()` for the new score, and add coloring logic in the cell's color computation method.

5. **`src/app/components/matrix/matrix.component.html`** -- Bind the new score map to the `<app-technique-cell>` inputs.

6. **`src/app/components/legend/legend.component.ts`** -- Add a `LegendConfig` entry to the `MODE_CONFIGS` record with label and color stops.

7. **`src/app/components/nav-rail/nav-rail.component.ts`** -- (Optional) If the mode has an associated panel, add a nav-rail entry.

---

## Detailed Mode Documentation

### 1. Coverage (`coverage`)

| Property | Value |
|----------|-------|
| **Display Label** | Coverage |
| **Icon** | (shield) |
| **Legend Label** | Mitigations |
| **Data Source** | `Domain.mitigationsByTechnique` (built-in ATT&CK data) |
| **Score Computation** | `technique.mitigationCount` -- direct count of ATT&CK mitigations mapped to this technique. Uses `SettingsService.getCoverageColors()` for theme-aware color customization. |
| **Color Scale** | `#d32f2f` (0) -> `#ff9800` (1) -> `#ffd54f` (2) -> `#aed581` (3) -> `#4caf50` (4+) |
| **Use Case** | Default view. Quickly identify techniques with zero mitigations (red) vs. well-mitigated techniques (green). The most fundamental analyst view for coverage gap analysis. |

---

### 2. Risk (`risk`)

| Property | Value |
|----------|-------|
| **Display Label** | Risk |
| **Icon** | (fire) |
| **Legend Label** | Risk Score |
| **Data Source** | Computed in `MatrixComponent` from `Domain.groupsByTechnique` and `technique.mitigationCount` |
| **Score Computation** | `groupCount * (1 + 1 / (mitigationCount + 1))`. Techniques used by many threat groups with few mitigations score highest. The inverse-mitigation factor amplifies risk for under-mitigated techniques. Normalized against the global maximum. |
| **Color Scale** | `#eceff1` (0) -> `#ff7043` (low) -> `#e53935` (med) -> `#b71c1c` (high) -> `#4a0000` (critical) |
| **Use Case** | Prioritize remediation by identifying techniques that are both heavily targeted and poorly defended. Critical for risk-based decision making. |

---

### 3. Exposure (`exposure`)

| Property | Value |
|----------|-------|
| **Display Label** | Exposure |
| **Icon** | (radioactive) |
| **Legend Label** | Exposure |
| **Data Source** | `FilterService.activeThreatGroupIds$` cross-referenced with `Domain.techniquesByGroup` |
| **Score Computation** | Count of currently-selected threat groups that use this technique. Only active when threat group filters are applied. Each selected group that includes this technique increments the score by 1. |
| **Color Scale** | `#eceff1` (0) -> `#ffb74d` (low) -> `#ff7043` (med) -> `#e53935` (high) -> `#b71c1c` (critical) |
| **Use Case** | After selecting specific threat actors in the Threats panel, switch to Exposure mode to see which techniques your selected adversaries concentrate on. Hot spots indicate high-priority defensive targets. |

---

### 4. Frequency (`frequency`)

| Property | Value |
|----------|-------|
| **Display Label** | Frequency |
| **Icon** | (bar chart) |
| **Legend Label** | Groups |
| **Data Source** | `Domain.groupsByTechnique` |
| **Score Computation** | Total count of unique threat groups that use this technique across the entire ATT&CK knowledge base (not filtered). Bucketed: 0, 1--2, 3--5, 6--10, 11+. |
| **Color Scale** | `#1c2a38` (0) -> `#1e3a5f` (1--2) -> `#1565c0` (3--5) -> `#0ea5e9` (6--10) -> `#38bdf8` (11+) |
| **Use Case** | Identify the most commonly used techniques across all known threat actors. High-frequency techniques represent the most popular attack patterns and should be prioritized for detection coverage. |

---

### 5. Software (`software`)

| Property | Value |
|----------|-------|
| **Display Label** | Software |
| **Icon** | (floppy disk) |
| **Legend Label** | Software |
| **Data Source** | `Domain.softwareByTechnique` |
| **Score Computation** | Count of ATT&CK software entries (tools and malware) that implement this technique. |
| **Color Scale** | `#eceff1` (0) -> `#ffb74d` (1) -> `#ff7043` (2) -> `#e53935` (3) -> `#b71c1c` (4+) |
| **Use Case** | Understand which techniques have the richest tooling ecosystem. Techniques implemented by many tools are easier for adversaries to execute and may warrant additional detection investment. |

---

### 6. Campaign (`campaign`)

| Property | Value |
|----------|-------|
| **Display Label** | Campaign |
| **Icon** | (target) |
| **Legend Label** | Campaigns |
| **Data Source** | `Domain.campaignsByTechnique` |
| **Score Computation** | Count of ATT&CK campaign entries that used this technique. |
| **Color Scale** | `#eceff1` (0) -> `#ce93d8` (1) -> `#ab47bc` (2) -> `#7b1fa2` (3) -> `#4a148c` (4+) |
| **Use Case** | Highlight techniques that appear across multiple real-world campaigns. High-campaign techniques have demonstrated operational use and represent proven attack patterns. Purple gradient distinguishes it from the threat-group views. |

---

### 7. Status (`status`)

| Property | Value |
|----------|-------|
| **Display Label** | Status |
| **Icon** | (checkmark) |
| **Legend Label** | Status |
| **Data Source** | `ImplementationService.status$` |
| **Score Computation** | Categorical. For each technique, examines all mapped mitigations and takes the "best" implementation status using a rank order: implemented (4) > in-progress (3) > planned (2) > not-started (1) > none (0). |
| **Color Scale** | `#90a4ae` (none) -> `#e53935` (not-started !) -> `#ff9800` (in-progress) -> `#2196f3` (planned) -> `#4caf50` (implemented) |
| **Scale Type** | Categorical (no gradient interpolation) |
| **Use Case** | Track implementation progress across the matrix. Quickly see which techniques have at least one implemented mitigation (green), which are in progress (orange), and which have no implementation started (red). Essential for program management reporting. |

---

### 8. Controls (`controls`)

| Property | Value |
|----------|-------|
| **Display Label** | Controls |
| **Icon** | (lock) |
| **Legend Label** | Controls |
| **Data Source** | `ControlsService` |
| **Score Computation** | Categorical (3 states). Checks whether the technique has at least one security control marked "implemented" (covered), at least one marked "planned" (planned), or none at all. |
| **Color Scale** | `#1c2b30` (none) -> `#1565c0` (planned) -> `#00c853` (covered) |
| **Scale Type** | Categorical |
| **Use Case** | Visualize which techniques are addressed by your organization's security control inventory. Pair with the Controls panel to manage control-to-technique mappings across NIST 800-53, CIS, ISO 27001, and custom frameworks. |

---

### 9. KEV (`kev`)

| Property | Value |
|----------|-------|
| **Display Label** | KEV |
| **Icon** | (siren) |
| **Legend Label** | KEV CVEs |
| **Data Source** | `CveService.kevTechScores$` |
| **Score Computation** | Count of CISA Known Exploited Vulnerabilities (KEV) catalog entries mapped to this technique via the ATT&CK-to-CVE dataset. |
| **Color Scale** | `#eceff1` (0) -> `#ffd54f` (1--2) -> `#ff9800` (3--5) -> `#d32f2f` (6+) |
| **Use Case** | Identify techniques with actively exploited vulnerabilities per CISA's KEV catalog. Techniques with high KEV counts represent immediate operational risk and should be prioritized for patching and detection. 4-stop scale for sparser data. |

---

### 10. D3FEND (`d3fend`)

| Property | Value |
|----------|-------|
| **Display Label** | D3FEND |
| **Icon** | (shield) |
| **Legend Label** | D3FEND |
| **Data Source** | `D3fendService.getCountermeasures(attackId)` |
| **Score Computation** | Count of MITRE D3FEND defensive technique countermeasures mapped to this ATT&CK technique. |
| **Color Scale** | `#d32f2f` (0) -> `#e64a19` (1) -> `#f57c00` (2) -> `#1565c0` (3) -> `#1a6fba` (4+) |
| **Use Case** | Assess defensive countermeasure coverage from the D3FEND knowledge graph. Techniques with zero D3FEND mappings (red) lack formalized defensive techniques. Blue indicates strong countermeasure availability. |

---

### 11. Atomic (`atomic`)

| Property | Value |
|----------|-------|
| **Display Label** | Atomic |
| **Icon** | (atom) |
| **Legend Label** | Atomic Tests |
| **Data Source** | `AtomicService.getHeatScore(attackId)` |
| **Score Computation** | Count of Atomic Red Team test cases available for this technique. Uses the service's heat-score method which may weight by test complexity. |
| **Color Scale** | `#1a1a0a` (0) -> `#6d3a10` (1) -> `#c06020` (2) -> `#e08030` (3) -> `#f0a040` (4+) |
| **Use Case** | Identify which techniques have Atomic Red Team tests available for purple-team validation. Dark cells indicate no tests available -- these are blind spots in your validation program. Warm amber tones for the Atomic brand. |

---

### 12. Engage (`engage`)

| Property | Value |
|----------|-------|
| **Display Label** | Engage |
| **Icon** | (theater masks) |
| **Legend Label** | Engage |
| **Data Source** | `EngageService.getActivities(attackId)` |
| **Score Computation** | Count of MITRE Engage activities (denial, deception, adversary engagement) mapped to this technique. |
| **Color Scale** | `#0a1a0a` (0) -> `#4a3a10` (1) -> `#906020` (2) -> `#c08030` (3) -> `#f0a040` (4+) |
| **Use Case** | Visualize which techniques have active defense and adversary engagement options available. Useful for planning deception operations and proactive defense strategies. |

---

### 13. CAR (`car`)

| Property | Value |
|----------|-------|
| **Display Label** | CAR |
| **Icon** | (microscope) |
| **Legend Label** | CAR Analytics |
| **Data Source** | `CARService.getLiveCount(attackId)` |
| **Score Computation** | Count of MITRE Cyber Analytics Repository (CAR) analytics covering this technique. Uses the live navigator layer count when available for broader coverage. |
| **Color Scale** | `#0a0a1a` (0) -> `#0d2a4a` (1) -> `#1a4a7a` (2) -> `#2a6aaa` (3) -> `#58a6ff` (4+) |
| **Use Case** | See which techniques have formal CAR analytics available. CAR analytics are platform-agnostic detection pseudocode that can be translated to SIEM queries. Blue scale for the CAR brand. |

---

### 14. CVE (`cve`)

| Property | Value |
|----------|-------|
| **Display Label** | CVE |
| **Icon** | (red circle) |
| **Legend Label** | CVEs |
| **Data Source** | `AttackCveService.getCvesForTechnique(attackId)` |
| **Score Computation** | Count of CVEs mapped to this technique from the CTID ATT&CK-to-CVE dataset. Bucketed: 0, 1--2, 3--5, 6--10, 11+. |
| **Color Scale** | `#1a2332` (0) -> `#4a1a4a` (1--2) -> `#7b2d8b` (3--5) -> `#a855b5` (6--10) -> `#d946ef` (11+) |
| **Use Case** | Understand the vulnerability exposure surface per technique. Techniques with many mapped CVEs represent broad attack surfaces. Purple/magenta scale for vulnerability-focused analysis. |

---

### 15. Detection (`detection`)

| Property | Value |
|----------|-------|
| **Display Label** | Detection |
| **Icon** | (magnifying glass) |
| **Legend Label** | Sigma Rules |
| **Data Source** | Composite: `SigmaService`, `D3fendService`, `CARService`, `AtomicService` |
| **Score Computation** | Weighted composite: `(sigmaCount * 3) + (d3fendCount * 2) + (carCount * 2) + (atomicCount * 1)`. Sigma rules are weighted highest as direct detection content. Normalized against the global maximum score. |
| **Color Scale** | `#1a2332` (0) -> `#0c2d2d` (1--3) -> `#0d5e5e` (4--8) -> `#0e8a7a` (9--15) -> `#10b981` (16+) |
| **Use Case** | Comprehensive detection coverage assessment combining all detection sources with weighted scoring. The most holistic view of detection readiness. Teal-green scale suggests detection health. |

---

### 16. CRI Profile (`cri`)

| Property | Value |
|----------|-------|
| **Display Label** | CRI Profile |
| **Icon** | (bank) |
| **Legend Label** | CRI Controls |
| **Data Source** | `CriProfileService.getControlCount(attackId)` |
| **Score Computation** | Count of Cyber Risk Institute (CRI) Profile controls mapped to this technique. |
| **Color Scale** | `#1a0a2e` (0) -> `#ce93d8` (low) -> `#ab47bc` (med) -> `#8e24aa` (high) -> `#6a1b9a` (max) |
| **Use Case** | Financial sector compliance view. Shows how well each technique is addressed by the CRI Profile (formerly FSSCC Cybersecurity Profile), which maps financial sector regulatory requirements to ATT&CK. Purple scale for the compliance domain. |

---

### 17. Unified Risk (`unified`)

| Property | Value |
|----------|-------|
| **Display Label** | Unified Risk |
| **Icon** | (target) |
| **Legend Label** | Unified Risk |
| **Data Source** | Composite: multi-service computation in `MatrixComponent` |
| **Score Computation** | Composite 0--100 score across five weighted dimensions: |
| | - Mitigation coverage (weight 30): `min(mitigationCount / 4, 1) * 30` |
| | - Detection (weight 20): `min((sigmaCount + carCount) / 5, 1) * 20` |
| | - Atomic test validation (weight 15): `min(atomicCount / 3, 1) * 15` |
| | - D3FEND countermeasures (weight 10): `min(d3fendCount / 2, 1) * 10` |
| | - KEV exposure penalty (weight 25): `25 - min(kevCount * 5, 25)` (inverted: more KEVs = lower score = more risk) |
| | Higher scores indicate better overall defense posture. |
| **Color Scale** | `#7f0000` (critical, 0--20) -> `#c62828` (high, 21--40) -> `#f9a825` (medium, 41--60) -> `#558b2f` (good, 61--80) -> `#1b5e20` (strong, 81--100) |
| **Use Case** | The most comprehensive single-number risk assessment. Balances mitigation coverage, detection depth, test validation, defensive techniques, and active exploitation. Ideal for executive reporting and dashboard views. Red-to-green scale for intuitive risk communication. |

---

### 18. Sigma Rules (`sigma`)

| Property | Value |
|----------|-------|
| **Display Label** | Sigma Rules |
| **Icon** | (sigma symbol) |
| **Legend Label** | Sigma Rules |
| **Data Source** | `SigmaService.getRuleCount(attackId)` |
| **Score Computation** | Count of Sigma detection rules mapped to this technique from the SigmaHQ rule repository. |
| **Color Scale** | `#0a1a1a` (0) -> `#0d4a3a` (1--3) -> `#0d7a5e` (4--8) -> `#0ea87a` (9--15) -> `#10b981` (16+) |
| **Use Case** | Focused Sigma rule coverage view. Identify techniques lacking Sigma detection rules for rule development prioritization. Green scale for detection-positive framing. |

---

### 19. NIST 800-53 (`nist`)

| Property | Value |
|----------|-------|
| **Display Label** | NIST 800-53 |
| **Icon** | (government building) |
| **Legend Label** | NIST 800-53 |
| **Data Source** | `NistMappingService.getControlCount(attackId)` |
| **Score Computation** | Count of NIST SP 800-53 security controls mapped to this ATT&CK technique. |
| **Color Scale** | `#0d1b2a` (0) -> `#1a4a7a` (1--5) -> `#1565c0` (6--15) -> `#1976d2` (16--30) -> `#42a5f5` (31+) |
| **Use Case** | Federal compliance and NIST RMF alignment. Shows which techniques are well-addressed by NIST 800-53 controls. Blue gradient for the compliance/government domain. Useful for FedRAMP and FISMA reporting. |

---

### 20. VERIS Actions (`veris`)

| Property | Value |
|----------|-------|
| **Display Label** | VERIS Actions |
| **Icon** | (clipboard) |
| **Legend Label** | VERIS Actions |
| **Data Source** | `VerisService.getActionsForTechnique(attackId)` |
| **Score Computation** | Count of VERIS (Vocabulary for Event Recording and Incident Sharing) incident action types mapped to this technique. |
| **Color Scale** | `#1a0a0a` (0) -> `#5c1a1a` (1--2) -> `#a83232` (3--5) -> `#d64e4e` (6--10) -> `#f28b8b` (11+) |
| **Use Case** | Map ATT&CK techniques to real-world incident data patterns from the DBIR (Data Breach Investigations Report) taxonomy. Techniques with high VERIS action counts correlate with frequently observed breach patterns. Red scale for incident/breach connotation. |

---

### 21. EPSS Probability (`epss`)

| Property | Value |
|----------|-------|
| **Display Label** | EPSS Prob. |
| **Icon** | (target) |
| **Legend Label** | EPSS Probability |
| **Data Source** | `EpssService.fetchScores()` via `AttackCveService` |
| **Score Computation** | Average EPSS (Exploit Prediction Scoring System) exploitation probability across all CVEs mapped to this technique. Fetched asynchronously from the FIRST.org EPSS API. Value range 0.0--1.0 (displayed as percentage). Bucketed: None, <1%, 1--5%, 5--20%, 20%+. |
| **Color Scale** | `#1a1a0a` (None) -> `#5c4a00` (<1%) -> `#c17900` (1--5%) -> `#e65100` (5--20%) -> `#d32f2f` (20%+) |
| **Use Case** | Predict which techniques are most likely to be exploited in the near future based on EPSS probability scores. Techniques with high EPSS averages represent imminent exploitation risk. Amber-to-red scale for urgency. Shows a loading state while EPSS data is fetched. |

---

### 22. Elastic Rules (`elastic`)

| Property | Value |
|----------|-------|
| **Display Label** | Elastic Rules |
| **Icon** | (green circle) |
| **Legend Label** | Elastic Rules |
| **Data Source** | `ElasticService.getRuleCount(attackId)` |
| **Score Computation** | Count of Elastic Detection Rules from the elastic/detection-rules repository mapped to this technique. |
| **Color Scale** | `#0a1a0a` (0) -> `#1a3a1a` (1--3) -> `#2a6a2a` (4--8) -> `#3a9a3a` (9--15) -> `#4caf50` (16+) |
| **Use Case** | Elastic SIEM-specific detection coverage. Shows which techniques have pre-built Elastic detection rules available. Green scale matches the Elastic brand. Useful for Elastic Security customers planning detection rule deployment. |

---

### 23. Splunk Detections (`splunk`)

| Property | Value |
|----------|-------|
| **Display Label** | Splunk Detections |
| **Icon** | (orange circle) |
| **Legend Label** | Splunk Detections |
| **Data Source** | `SplunkContentService.getRuleCount(attackId)` |
| **Score Computation** | Count of Splunk Security Content detections from the splunk/security_content repository mapped to this technique. |
| **Color Scale** | `#1a0a0a` (0) -> `#4a2a0a` (1--3) -> `#7a4a1a` (4--8) -> `#c06a20` (9--15) -> `#ff9800` (16+) |
| **Use Case** | Splunk-specific detection coverage. Shows which techniques have Splunk security content available. Orange scale matches the Splunk brand. Useful for Splunk Enterprise Security customers. |

---

### 24. Intelligence (`intelligence`)

| Property | Value |
|----------|-------|
| **Display Label** | Intelligence |
| **Icon** | (brain) |
| **Legend Label** | Intel Signals |
| **Data Source** | Composite: `MispService.hasMisp()` + `Domain.groupsByTechnique` |
| **Score Computation** | `hasMisp(attackId) ? 1 : 0` + `groupCount`. Combines MISP galaxy cluster presence (binary signal) with total threat group count for a rough intelligence signal strength. |
| **Color Scale** | `#0a1a2e` (0) -> `#1a3a7a` (1--2) -> `#5a2d8b` (3--5) -> `#8b1a5a` (6--10) -> `#d32f2f` (11+) |
| **Use Case** | Threat intelligence enrichment view. Highlights techniques with the strongest intelligence signals from MISP and ATT&CK threat group data. Blue-purple-red gradient suggests increasing intelligence urgency. Useful for CTI analysts prioritizing collection and analysis efforts. |

---

## Color Scale Design Principles

The 24 heatmap modes follow these design conventions:

1. **Dark backgrounds for zero**: All gradient scales use a very dark color (#0a--#1a range) for zero-score cells, maintaining matrix readability.

2. **Brand-aligned palettes**: Vendor-specific modes use brand colors (Elastic = green, Splunk = orange, Sigma = teal, CAR = blue).

3. **Red = risk/urgency**: Risk, KEV, VERIS, and EPSS modes use red-dominant scales for threat-oriented framing.

4. **Green = coverage/health**: Coverage, Detection, Sigma, and Elastic modes use green tones for positive-coverage framing.

5. **Categorical modes**: Only `status` (5 discrete states) and `controls` (3 discrete states) use categorical scales. All others use continuous gradients.

6. **Consistent bucket labels**: Gradient modes use numeric ranges (0, 1--2, 3--5, 6--10, 11+) or semantic labels (low, med, high, critical) with 4--5 stops.

7. **Theme customization**: The `coverage` mode uniquely supports theme-customizable colors via `SettingsService` (5 built-in themes: Default, Vivid, Blue/Orange, Monochrome, High Contrast).
