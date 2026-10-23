# Heatmap Modes Reference

> Reference for the heatmap coloring modes (lenses) in ATT&CK-Navi. There are 36 today; the authoritative count is the Heatmap modes row in [FACTS.md](FACTS.md). The Detailed Mode Documentation below covers the original 24, the Posture lens (25) and the two lenses P2-14 added (26, 27); the other lenses added since are listed in the lens menu and defined in `src/app/models/heatmap-modes.ts`.
> Each mode recolors every technique cell in the matrix to visualize a different security dimension.

---

## Summary Table

| # | Mode ID | Display Label | Legend Label | Scale Type | Data Source Service | What the Score Represents |
|---|---------|--------------|--------------|------------|--------------------|----|
| 1 | `coverage` | Mitigations mapped | Mitigations mapped | Gradient (5) | `Domain.mitigationsByTechnique` | Count of mapped ATT&CK mitigations (0, 1, 2, 3, 4+) |
| 2 | `risk` | Threat-weighted mapping gap | Threat-weighted mapping gap | Gradient (5) | Computed in `MatrixComponent` | `groupCount * (1 + 1/(mitigationCount+1))` |
| 3 | `exposure` | Selected adversaries | Selected adversaries | Gradient (5) | `FilterService.activeThreatGroupIds$` | Count of selected threat groups using this technique |
| 4 | `frequency` | Frequency | Groups | Gradient (5) | `Domain.groupsByTechnique` | Total unique threat groups using this technique |
| 5 | `software` | Software | Software | Gradient (5) | `Domain.softwareByTechnique` | Count of ATT&CK software entries using this technique |
| 6 | `campaign` | Campaign | Campaigns | Gradient (5) | `Domain.campaignsByTechnique` | Count of ATT&CK campaigns using this technique |
| 7 | `status` | Status | Status | Categorical (6) | `PostureService.implViewFor` via the lens's own `project` | Best implementation status across a technique's mitigations and the technique itself, through the breadth guard: `implemented, partial via Mxxxx` when only broad mitigations are implemented |
| 8 | `controls` | Controls | Controls | Categorical (4) | `PostureService.stateFor` (control marks) via the lens's own `project` | Whether a declared security control reaches the technique: covered (self-attested), partial (only a broad mitigation behind it), planned or none |
| 9 | `kev` | KEV | KEV CVEs | Gradient (4) | `CveService.kevTechScores$` | Count of CISA KEV CVEs mapped to this technique |
| 10 | `d3fend` | D3FEND | D3FEND | Gradient (5) | `D3fendService` | Count of D3FEND countermeasure techniques |
| 11 | `atomic` | Atomic | Atomic Tests | Gradient (5) | `AtomicService` | Count of Atomic Red Team test cases |
| 12 | `engage` | Engage | Engage | Gradient (5) | `EngageService` | Count of MITRE Engage activities |
| 13 | `car` | CAR | CAR Analytics | Gradient (5) | `CARService` | Count of Cyber Analytics Repository analytics |
| 14 | `cve` | CVE | CVEs | Gradient (5) | `AttackCveService` | Count of CVEs from CTID ATT&CK-to-CVE dataset |
| 15 | `detection` | Detection content available | Detection content available | Gradient (5) | Computed (multi-service) | Weighted: `sigma*3 + d3fend*2 + car*2 + atomic*1` |
| 16 | `cri` | CRI Profile | CRI Controls | Gradient (5) | `CriProfileService` | Count of CRI Profile controls mapped |
| 17 | `unified` | Reference depth | Reference depth | Threshold (6) | Computed (multi-service) | 0--100 composite of defensive reference inputs only (mitigations, detection content, CTID controls, D3FEND, Atomic) |
| 18 | `sigma` | Sigma Rules | Sigma Rules | Gradient (5) | `SigmaService` | Count of Sigma detection rules |
| 19 | `nist` | NIST 800-53 | NIST 800-53 | Gradient (5) | `NistMappingService` | Count of mapped NIST 800-53 controls |
| 20 | `veris` | VERIS Actions | VERIS Actions | Gradient (5) | `VerisService` | Count of VERIS incident action mappings |
| 21 | `epss` | EPSS Prob. | EPSS Probability | Gradient (5) | `EpssService` | Average EPSS exploitation probability (0--1) across mapped CVEs |
| 22 | `elastic` | Elastic Rules | Elastic Rules | Relative (5) | `ElasticService` (bundled rule-coverage snapshot) | Rules in `elastic/detection-rules` at the pinned commit whose threat mapping names the technique or one of its sub-techniques |
| 23 | `splunk` | Splunk Detections | Splunk Detections | Relative (5) | `SplunkContentService` (bundled rule-coverage snapshot) | Detections in `splunk/security_content` at the pinned commit whose `mitre_attack_id` list names the technique or one of its sub-techniques |
| 24 | `intelligence` | Intelligence | Intel Signals | Gradient (5) | Computed (MISP + groups) | `hasMisp (0/1) + threatGroupCount` |
| 25 | `posture` | Posture | Posture | Categorical (6 + 2 patterns) | `PostureService.stateFor` via the lens's own `project` | Each technique's own posture bucket: `none`, `known`, `partial`, `covered`, `stale` or `proven` |
| 26 | `proven` | Proven | Proven | Categorical (4) | `PostureService.stateFor` via the lens's own `project` | Where a named detection fired or blocked on a recorded date: 3 production, 2 range or your own run, 1 older than its window, 0 none <!-- truth-vocab-allow proven-only -- names the Proven lens --> |
| 27 | `covered` | Covered (self-attested or range) | Covered (self-attested or range) | Categorical (3) | `PostureService.stateFor` via the lens's own `project` | 2 when a full mark (self-attested or range) reaches the technique, 1 when only a broad mitigation or control does (partial), 0 otherwise |

---

## Heatmap Pipeline: How It Works

When a user selects a heatmap mode, the following seven-step pipeline executes:

### Step 1: Mode Selection (Matrix controls)

**File:** `src/app/pages/matrix/matrix-controls.component.ts`

The matrix controls read the `HEATMAP_MODES` table from `src/app/models/heatmap-modes.ts` (36 lenses, grouped by `HEATMAP_GROUPS`) and render the lens menu. When the user picks a lens it calls `FilterService.setHeatmapMode(mode)`.

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

**File:** `src/app/components/legend/legend.component.ts`

The legend subscribes to `heatmapMode$` and renders the active mode's entry in the `HEATMAP_MODES` registry (`src/app/models/heatmap-modes.ts`): the rung badge and the lens question, the colour stops of its `ramp`, an 'n/a for <domain>' line when the lens has no source data for the loaded domain, a source line with each source's vintage (`src/app/models/lens-sources.ts`; the loaded ATT&CK release comes from the bundle's `x-mitre-collection`), and what zero means. Relative ramps are labelled as shares of the highest score; categorical and banded ramps show no scale note.

A **What is this lens?** button in the legend, a **?** next to every lens in the lens menu and the matrix page's n/a banner open the lens definition card (`src/app/components/lens-definition-card/`, a modal dialog with a focus trap that Escape closes): the lens question, rung, formula, each source with its vintage, the domains it has data for, and what zero means.

### Step 6b: Lenses without data for the loaded domain

A lens is available in a domain exactly when that domain is in its `domains` list (`lensAvailability()` in `heatmap-modes.ts`). In any other domain the lens menu disables it (`aria-disabled`, with a stated reason such as 'Sigma Rules is n/a for ICS ATT&CK: its sources (SigmaHQ coverage) have data for Enterprise ATT&CK only.' linked by `aria-describedby`), and if it is the active lens the matrix paints every cell in the neutral, hatched n/a colour (`LENS_NA_COLOR`, in no ramp) instead of the lens's zero colour, the minimap does the same, and a status banner on the matrix page states the reason. On ICS that is 23 of the 36 lenses today. The lens snapshots (`MatrixComponent.getCellColor`) are unaffected: they characterize each lens's own scoring.

### Step 7: Cell Color Fallback (MatrixComponent.getCellColor)

**File:** `src/app/components/matrix/matrix.component.ts` (line ~1257)

For the `coverage` and `frequency` modes, `MatrixComponent.getCellColor()` provides a fast-path color lookup. The `coverage` mode uses `SettingsService.getCoverageColors()` to support user theme customization.

---

## Adding a New Heatmap Mode

To add a heatmap mode (36 exist today), modify these files in order:

1. **`src/app/services/filter.service.ts`** -- Add the new mode string to the `HeatmapMode` union type.

2. **`src/app/models/heatmap-modes.ts`** -- Add a `HeatmapModeDef` entry to the `HEATMAP_MODES` table (`value`, `label`, the required `short` for the trigger button, and `group`); the matrix controls render it from this table, so there is no separate toolbar array. Its legend metadata is step 6, in the same entry.

3. **`src/app/components/matrix/matrix.component.ts`** -- Add a new score `Map` field, add an `else if (mode === 'new-mode')` branch in the `heatmapMode$` subscription (~line 467), and populate the score map.

4. **`src/app/components/technique-cell/technique-cell.component.ts`** -- Add an `@Input()` for the new score, and add coloring logic in the cell's color computation method.

5. **`src/app/components/matrix/matrix.component.html`** -- Bind the new score map to the `<app-technique-cell>` inputs.

6. **`src/app/models/heatmap-modes.ts`** -- Fill in the mode's legend metadata (question, rung, formula, domains, sources, zeroMeaning, ramp). The legend reads it; there is no separate legend table.

7. **`src/app/components/nav-rail/nav-rail.component.ts`** -- (Optional) If the mode has an associated panel, add a nav-rail entry.

---

## Detailed Mode Documentation

### 1. Mitigations mapped (`coverage`)

| Property | Value |
|----------|-------|
| **Display Label** | Mitigations mapped |
| **Icon** | (shield) |
| **Legend Label** | Mitigations mapped |
| **Data Source** | `Domain.mitigationsByTechnique` (built-in ATT&CK data) |
| **Score Computation** | `technique.mitigationCount` -- direct count of ATT&CK mitigations mapped to this technique. Uses `SettingsService.getCoverageColors()` for theme-aware color customization. |
| **Color Scale** | `#d32f2f` (0) -> `#ff9800` (1) -> `#ffd54f` (2) -> `#aed581` (3) -> `#4caf50` (4+) |
| **Use Case** | Quickly identify techniques with zero ATT&CK mitigations mapped vs. techniques with many. A Known-rung (reference) view: it says what the world has mapped, not what is deployed. |

---

### 2. Threat-weighted mapping gap (`risk`)

| Property | Value |
|----------|-------|
| **Display Label** | Threat-weighted mapping gap |
| **Icon** | (fire) |
| **Legend Label** | Threat-weighted mapping gap |
| **Data Source** | Computed in `MatrixComponent` from `Domain.groupsByTechnique` and `technique.mitigationCount` |
| **Score Computation** | `groupCount * (1 + 1 / (mitigationCount + 1))`. Techniques used by many threat groups with few mitigations score highest. The inverse-mitigation factor amplifies risk for under-mitigated techniques. Normalized against the global maximum. |
| **Color Scale** | `#eceff1` (0) -> `#ff7043` (low) -> `#e53935` (med) -> `#b71c1c` (high) -> `#4a0000` (critical) |
| **Use Case** | Find techniques that many groups use but that have few mitigations mapped. It weighs threat against reference mapping; it does not measure deployed defense. |

---

### 3. Selected adversaries (`exposure`)

| Property | Value |
|----------|-------|
| **Display Label** | Selected adversaries |
| **Icon** | (radioactive) |
| **Legend Label** | Selected adversaries |
| **Data Source** | `FilterService.activeThreatGroupIds$` cross-referenced with `Domain.techniquesByGroup` |
| **Score Computation** | Count of currently-selected threat groups that use this technique. Only active when threat group filters are applied. Each selected group that includes this technique increments the score by 1. |
| **Color Scale** | `#eceff1` (0) -> `#ffb74d` (low) -> `#ff7043` (med) -> `#e53935` (high) -> `#b71c1c` (critical) |
| **Use Case** | After selecting specific threat actors in the Threats panel, switch to the Selected adversaries lens to see which techniques your selected adversaries concentrate on. Hot spots indicate high-priority defensive targets. |

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
| **Use Case** | Identify the most commonly used techniques across all known threat actors. High-frequency techniques represent the most popular attack patterns and should be prioritized for detection coverage. Since E1.5 (decision D4) this is the default lens, called Prevalence: until the user records a mitigation's implementation status or a validation run, a one-line banner over the matrix says it is reference data, not a view of their environment. |

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
| **Use Case** | Highlight techniques that appear across multiple real-world campaigns. High-campaign techniques have demonstrated operational use and represent established attack patterns. Purple gradient distinguishes it from the threat-group views. |

---

### 7. Status (`status`)

| Property | Value |
|----------|-------|
| **Display Label** | Status |
| **Icon** | (checkmark) |
| **Legend Label** | Status |
| **Data Source** | `PostureService.implViewFor`, through the lens's own `project` and `color` (`src/app/models/posture/lens-ramps.ts`); registry-hosted since P2-14 |
| **Score Computation** | Categorical. For each technique, the best status over its mapped mitigations and any status set on the technique itself (a confirmation, a bulk set, the wizard), in the rank order implemented > in-progress > planned > not-started > none, through the breadth guard (D16): a mitigation mapped to more techniques than the threshold in Settings > Posture rules (15 by default) counts as partial, so a technique whose only implemented mitigations are broad shows the stop `implemented, partial via Mxxxx` between in-progress and implemented. A confirmed technique shows implemented. |
| **Color Scale** | The blue ordinal ramp shared with the `covered` lens: from the surface (none) through not started, planned, in progress and `implemented, partial via Mxxxx` (also drawn with a dashed outline) to implemented. Luminance rises with the stop, and neighbouring stops differ by at least 1.2:1 under protanopia, deuteranopia and tritanopia, so the colorblind-safe setting does not change it. |
| **Scale Type** | Categorical (ordinal) |
| **Use Case** | Track implementation progress across the matrix. The `impl=` filter reads the same guarded view: `impl=implemented` matches full implementation only, and a technique implemented only through broad mitigations matches none of the four values (the filter's tooltip says so). |

---

### 8. Controls (`controls`)

| Property | Value |
|----------|-------|
| **Display Label** | Controls |
| **Icon** | (lock) |
| **Legend Label** | Controls |
| **Data Source** | `PostureService.stateFor` (the control marks), through the lens's own `project` and `color`; registry-hosted since P2-14 |
| **Score Computation** | Categorical (4 states). Covered (self-attested) when an implemented control lists a mitigation of the technique within the breadth threshold; partial when every such mitigation is broader than the threshold (D16, drawn dashed); planned when only planned controls reach it; none otherwise. |
| **Color Scale** | The blue ordinal ramp shared with the `covered` lens: none (the surface) -> planned -> partial -> covered (self-attested) |
| **Scale Type** | Categorical (ordinal) |
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

### 15. Detection content available (`detection`)

| Property | Value |
|----------|-------|
| **Display Label** | Detection content available |
| **Icon** | (magnifying glass) |
| **Legend Label** | Detection content available |
| **Data Source** | Composite: `SigmaService`, `D3fendService`, `CARService`, `AtomicService` |
| **Score Computation** | Weighted composite: `(sigmaCount * 3) + (d3fendCount * 2) + (carCount * 2) + (atomicCount * 1)`. Sigma rules are weighted highest as direct detection content. Normalized against the global maximum score. |
| **Color Scale** | `#1a2332` (0) -> `#0c2d2d` (1--3) -> `#0d5e5e` (4--8) -> `#0e8a7a` (9--15) -> `#10b981` (16+) |
| **Use Case** | How much public detection and validation content exists for a technique, across Sigma, D3FEND, CAR and Atomic with weighted scoring. Content available is not content deployed. |

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

### 17. Reference depth (`unified`)

| Property | Value |
|----------|-------|
| **Display Label** | Reference depth |
| **Icon** | (target) |
| **Legend Label** | Reference depth |
| **Data Source** | `referenceDepthScore()` in `src/app/models/reference-depth.ts`, fed by `MatrixComponent` |
| **Score Computation** | 0--100 composite of defensive reference inputs only; the weighted sum (out of 70) is rescaled to 100: |
| | - Mitigations (weight 15): `min(mitigationCount / 4, 1) * 15` |
| | - Detection content (weight 20): `min((sigmaCount + carLiveCount) / 5, 1) * 20` |
| | - CTID control mappings (weight 15): `min(controlCount / 4, 1) * 15` (NIST 800-53, CRI, CIS, CSA CCM, M365) |
| | - D3FEND countermeasures (weight 10): `min(d3fendCount / 2, 1) * 10` |
| | - Atomic tests (weight 10): `min(atomicCount / 3, 1) * 10` |
| | Threat intel (groups, software, campaigns) and KEV are not inputs: the Threat lenses (Frequency, Selected adversaries, Intelligence, KEV, Threat-weighted mapping gap) show them. A technique's Reference depth does not change when the number of groups using it changes. |
| **Color Scale** | `#0e1b30` (minimal, 0--15) -> `#143a5c` (thin, 16--30) -> `#1f6aa8` (some, 31--50) -> `#2f95d8` (51--65) -> `#38bdf8` (deep, 66--80) -> `#a78bfa` (deepest, 81--100) |
| **Use Case** | How much defensive reference material (Known rung) exists for each technique. It is not a posture measure and says nothing about what is deployed. It was the default lens until E1.5 (decision D4) made Prevalence (`frequency`) the default. |

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
| **Display Label** | Elastic Rules (lens menu group Detections, rung Known) |
| **Legend Label** | Elastic Rules |
| **Domains** | Enterprise only; n/a (hatched) in ICS, Mobile and F3 |
| **Data Source** | `ElasticService.getRuleCount(attackId)`, which reads the `elastic` section of the bundled `src/assets/data/rule-coverage-snapshot.json` |
| **Score Computation** | The number of rules in `elastic/detection-rules` (`rules/**/*.toml`, not `rules/_deprecated/`) at the pinned commit whose `[[rule.threat.technique]]` or `[[rule.threat.technique.subtechnique]]` entries name the technique. A parent technique's count is the distinct rules naming it or any of its sub-techniques, so a parent is never lower than its sub-techniques. At the 2026-10-21 pin the builder parsed 2,131 rules (the snapshot records that number and lists at most ten rule names per technique), 446 technique and sub-technique ids have at least one rule, and the highest parent count is T1059 with 323. |
| **Color Scale** | Relative to the highest score in the loaded domain: `#0a1a0a` (0), then `#1a3a1a` (<25%), `#2a6a2a` (25-49%), `#3a9a3a` (50-74%), `#4caf50` (75-100%) |
| **What zero means** | No rule names this technique at the pinned commit, or the bundled rule snapshot did not load; in that case the banner above the matrix names the reason (`bundled snapshot missing ...`). The legend ends with "Not known to us, not safe." |
| **Use Case** | Shows where the public Elastic rule repository has rules mapped to a technique, as reference data. It says nothing about which rules run in your environment. |

**Provenance.** The counts are not fetched from GitHub when the app runs. `scripts/build-rule-coverage-snapshot.mjs` reads the rule bodies from the repository's tarball at a pinned commit and writes the snapshot; the monthly `refresh-data.yml` workflow (the 3rd of each month) moves the pin to the branch head and opens a pull request for review. The legend's source line reads "Elastic detection-rules (bundled snapshot of the rule bodies at a pinned commit; commit and date on the Status page)", and the Status page's source table names the commit (`elastic-tree`, kind `bundled`, version `snapshot of <date>, elastic/detection-rules@<sha7> (commit <date>, main)`). See [SERVICES.md](SERVICES.md#rule-coverage-snapshot-elastic-splunk-mdecrevoisier-sigma).

**In the technique drawer.** The drawer's **Rule sources** section has an Elastic detection-rules list for the selected technique: the same count, up to ten rule names, each linked to the rule file at the pinned commit, a line "N of M listed by name; the rest are in the repository at this commit" when there are more, and the pinned repository, commit date and snapshot date. A technique with no rule reads "no rules reference this technique at the pinned commit"; a snapshot that did not load shows "Not loaded:" with the reason, and the section badge reads `not loaded` instead of a count.

---

### 23. Splunk Detections (`splunk`)

| Property | Value |
|----------|-------|
| **Display Label** | Splunk Detections (lens menu group Detections, rung Known) |
| **Legend Label** | Splunk Detections |
| **Domains** | Enterprise only; n/a (hatched) in ICS, Mobile and F3 |
| **Data Source** | `SplunkContentService.getRuleCount(attackId)`, which reads the `splunk` section of the bundled `src/assets/data/rule-coverage-snapshot.json` |
| **Score Computation** | The number of detections in `splunk/security_content` (`detections/**/*.yml`, not `detections/deprecated/`) at the pinned commit whose `mitre_attack_id` list names the technique. A parent technique's count is the distinct detections naming it or any of its sub-techniques. At the 2026-10-21 pin the builder parsed 2,169 detections (the snapshot records that number and lists at most ten detection names per technique), 396 technique and sub-technique ids have at least one detection, and the highest parent count is T1059 with 165. |
| **Color Scale** | Relative to the highest score in the loaded domain: `#1a0a0a` (0), then `#4a2a0a` (<25%), `#7a4a1a` (25-49%), `#c06a20` (50-74%), `#ff9800` (75-100%) |
| **What zero means** | No detection names this technique at the pinned commit, or the bundled rule snapshot did not load; in that case the banner above the matrix names the reason. The legend ends with "Not known to us, not safe." |
| **Use Case** | Shows where the public Splunk security_content repository has detections mapped to a technique, as reference data. It says nothing about which searches run in your environment. |

**Provenance and drawer.** As for Elastic: the same snapshot file, builder and monthly refresh, with the `splunk/security_content` pin on the `develop` branch (`splunk-tree` on the Status page). The drawer's Rule sources section has a Splunk security_content list with the same count, up to ten detection names linked at the pinned commit, and the same empty and not-loaded states.

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

### 25. Posture (`posture`)

| Property | Value |
|----------|-------|
| **Display Label** | Posture |
| **Rung** | Mixed: each cell shows its own rung |
| **Legend Label** | Posture |
| **Data Source** | `PostureService.stateFor`, through the lens's own `project` and `color` (`src/app/models/lens-registry.ts`, `src/app/models/posture/posture-ramp.ts`); the first registry-hosted lens, so the matrix switchboard has no branch for it |
| **Score Computation** | Categorical. The technique's posture bucket from your recorded data: a recorded detection (bucket `proven`, or `stale` once older than its window), else Covered (self-attested or range) from implemented mitigations, declared controls, confirmations and range marks (bucket `covered`, or `partial` when only a mitigation mapped to more techniques than the breadth threshold reaches it), else `known` when reference data exists, else `none`. |
| **Color Scale** | An ordinal ramp kept as theme tokens: `none` is the surface, `known` a neutral blue-grey, `covered` blue, `proven` teal with a check mark; `partial` is the Known fill with a dashed blue outline, `stale` the teal mixed 50% toward the surface with the check mark kept. Two sub-state patterns: a vermilion hatched outline (`contradicted`) and a grey cross-hatch (`not-reproducible`). Contrast from the surface rises `none` < `known` < `covered` < `proven` under protanopia, deuteranopia and tritanopia in both themes, so the colorblind-safe setting does not change it. |
| **Scale Type** | Categorical (ordinal) |
| **Use Case** | One view of what you have recorded per technique. On a fresh profile it shows only `known` and `none`, and its legend shows the ramp without stop words and says "No data of yours recorded". The legend also counts the proofs that go stale within 7 days. |

---

<!-- truth-vocab-allow-next-line proven-only -- names the Proven lens -->
### 26. Proven (`proven`)

| Property | Value |
|----------|-------|
| **Display Label** | `Proven` (from `lensLabel('proven')`; the short label is the same literal) |
| **Rung** | `Proven` |
| **Data Source** | `PostureService.stateFor`, through the lens's own `project` and `color` (`src/app/models/posture/lens-ramps.ts`) |
| **Score Computation** | Categorical. From the validation runs you recorded or imported, the technique's best record of a named detection that fired or blocked: 3 when the record is from production and within its window, 2 when it is from the range or your own run and within its window, 1 when the newest record is older than its window (range 90, production 180, own run 90 days; bucket `stale`), 0 when there is no named detection. A run without a named detection never scores here. |
| **Color Scale** | An ordinal ramp from the surface toward the Posture lens's teal: 0 the surface, 1 the Posture lens's `stale` fill, 2 the teal mixed 25% toward the surface, 3 the teal. Every scored cell shows a check mark, and a `lab` text badge when the best record is from the range. |
| **Scale Type** | Categorical (ordinal) |
| **Use Case** | See where a named detection has fired or blocked, and how fresh and how close to production that record is. Offered only once data of yours exists (`lensNameVisible` in `src/app/models/lens-registry.ts`): on a fresh profile the lens picker does not list it, and a `heat=proven` link opens the default lens instead. |

---

### 27. Covered (self-attested or range) (`covered`)

| Property | Value |
|----------|-------|
| **Display Label** | Covered (self-attested or range) |
| **Rung** | `Covered`, qualifier `self-attested` |
| **Data Source** | `PostureService.stateFor` (the CoveredMarks), through the lens's own `project` and `color` |
| **Score Computation** | Categorical. 2 when a full mark reaches the technique (an implemented mitigation within the breadth threshold, an implemented control, a confirmation, configured telemetry or a range mark) and no later failed run contradicts it; 1 when only partial marks do (a mitigation or control mapped to more techniques than the threshold, D16), drawn with a dashed outline; 0 otherwise. Planned marks score 0. |
| **Color Scale** | The blue ordinal ramp shared with the `status` and `controls` lenses: 0 the surface, 1 the blue mixed 40% toward the surface with the dashed outline, 2 the blue. |
| **Scale Type** | Categorical (ordinal) |
| **Use Case** | The Covered (self-attested or range) rung on its own, without the proof the Posture lens layers on top. Raising the breadth threshold in Settings > Posture rules turns a broad mitigation's partial cells full here and on the Status lens. Offered only once data of yours exists, as lens 26 (`proven`) is: on a fresh profile the lens picker does not list it, and a `heat=covered` link opens the default lens instead. |

---

## Color Scale Design Principles

The 36 heatmap modes follow these design conventions:

1. **Dark backgrounds for zero**: All gradient scales use a very dark color (#0a--#1a range) for zero-score cells, maintaining matrix readability.

2. **Brand-aligned palettes**: Vendor-specific modes use brand colors (Elastic = green, Splunk = orange, Sigma = teal, CAR = blue).

3. **Red = risk/urgency**: Risk, KEV, VERIS, and EPSS modes use red-dominant scales for threat-oriented framing.

4. **Green = coverage/health**: Coverage, Detection, Sigma, and Elastic modes use green tones for positive-coverage framing.

5. **Categorical modes**: `status` (6 ordinal states), `controls` (4), `posture` (6 buckets and 2 patterns), `proven` (4) and `covered` (3) use categorical scales; the five registry-hosted ones share ordinal ramps that are CVD-safe by default. All others use continuous gradients.

6. **Consistent bucket labels**: Gradient modes use numeric ranges (0, 1--2, 3--5, 6--10, 11+) or semantic labels (low, med, high, critical) with 4--5 stops.

7. **Theme customization**: The `coverage` mode uniquely supports theme-customizable colors via `SettingsService` (5 built-in themes: Default, Vivid, Blue/Orange, Monochrome, High Contrast).
