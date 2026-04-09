# Starred Project Integration Analysis

> Analysis of TeamStarWolf's 30 starred GitHub projects and their integration potential with ATTACK-Navi.
> Generated: April 2026

---

## Executive Summary

Of 30 starred repositories, **12 are high-value integration candidates** that directly map to existing ATTACK-Navi services or roadmap items. The integrations fall into 5 categories: enhanced CVE/vulnerability enrichment, expanded detection coverage, threat hunting playbooks, adversary emulation export, and AI-powered analysis. Implementing the top 6 would add **4 new data sources** to the data health ribbon and enhance **3 existing services**.

---

## Starred Projects by Category

### Category 1: MITRE ATT&CK Ecosystem (6 repos)
| Repo | Stars | Integration Value |
|------|-------|-------------------|
| `mitre/caldera` | 6,876 | **HIGH** - Adversary emulation export |
| `mitre-attack/attack-arsenal` | 535 | MEDIUM - Red team resource links |
| `mitre-attack/mitreattack-python` | 680 | LOW - Python library (not web-consumable) |
| `mitre/atomic` | 51 | LOW - Caldera plugin (covered by Caldera) |
| `mitre/caldera-ot` | 244 | MEDIUM - ICS domain Caldera export |
| `mitre/mitre.github.io` | 26 | LOW - Static site, no data |

### Category 2: CVE / Vulnerability Data (8 repos)
| Repo | Stars | Integration Value |
|------|-------|-------------------|
| `Galeax/CVE2CAPEC` | 286 | **HIGH** - Full CVE kill chain enrichment |
| `trickest/cve` | 7,674 | **HIGH** - PoC exploit availability |
| `0xMarcio/cve` | 1,208 | **HIGH** - Latest CVEs with PoCs |
| `CVEProject/cvelistV5` | 2,582 | MEDIUM - Official CVE JSON source |
| `CVEProject/cve-services` | 237 | LOW - API source code, not data |
| `CVEProject/cve-schema` | 405 | LOW - Schema spec, not data |
| `CVEProject/cvelist-bulk-download` | 24 | LOW - Utility tool |
| `CVEProject/cve-website` | 110 | LOW - Website source |

### Category 3: Detection / SIGMA / SIEM (4 repos)
| Repo | Stars | Integration Value |
|------|-------|-------------------|
| `mdecrevoisier/SIGMA-detection-rules` | 423 | **HIGH** - 350+ curated enterprise rules |
| `mdecrevoisier/EVTX-to-MITRE-Attack` | 621 | **HIGH** - 270+ EVTX test samples |
| `edoardogerosa/sentinel-attack` | 1,081 | MEDIUM - Azure Sentinel integration |
| `siriussecurity/tanium-attack-mapping` | 12 | LOW - Navigator layer (already supported) |

### Category 4: Threat Intelligence / Hunting (4 repos)
| Repo | Stars | Integration Value |
|------|-------|-------------------|
| `OTRF/ThreatHunter-Playbook` | 4,527 | **HIGH** - Per-technique hunting playbooks |
| `mukul975/Anthropic-Cybersecurity-Skills` | 4,151 | **HIGH** - AI skill recommendations |
| `nshalabi/ATTACK-Tools` | 1,050 | MEDIUM - Complementary utilities |
| `infosecn1nja/awesome-mitre-attack` | 618 | LOW - Curated link list (manual) |

### Category 5: OWASP / Web Security (4 repos)
| Repo | Stars | Integration Value |
|------|-------|-------------------|
| `OWASP/threat-dragon` | 1,376 | MEDIUM - Threat model export |
| `OWASP/API-Security` | 2,268 | LOW - Reference material |
| `OWASP/DevGuide` | 2,153 | LOW - Reference material |
| `ebranca/owasp-pysec` | 413 | LOW - Python library |
| `stanislav-web/OpenDoor` | 917 | LOW - Scanner tool |

### Category 6: Offensive / CTF / EDR (4 repos)
| Repo | Stars | Integration Value |
|------|-------|-------------------|
| `tkmru/awesome-edr-bypass` | 1,513 | MEDIUM - EDR evasion risk scoring |
| `JohnHammond/katana` | 1,348 | LOW - CTF tool |
| `JohnHammond/recaptcha-phish` | 647 | LOW - Phishing demo |

---

## Top Integration Proposals

### Integration 1: CVE2CAPEC Full Kill Chain Enrichment
**Source**: `Galeax/CVE2CAPEC` (286 stars)
**Roadmap alignment**: Tier 1.2 (Asset Inventory + CVE Exposure Scoring)
**Effort**: Medium | **Impact**: High

#### What it adds
Extends the existing CVE sidebar with a full vulnerability kill chain: **CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND**. Currently ATTACK-Navi maps CVE->ATT&CK via CTID and CWE->ATT&CK via a hardcoded lookup table. This integration creates a richer, more complete mapping chain.

#### Data format
- **Source file**: `results/new_cves.jsonl` (JSONL, updated daily at 00:05 UTC)
- **Schema**:
```json
{
  "CVE-2024-12345": {
    "CWE": ["CWE-79", "CWE-89"],
    "CAPEC": ["63", "88", "100"],
    "TECHNIQUES": ["T1059", "T1190"],
    "DEFEND": ["D3-DE", "D3-NTA"]
  }
}
```

#### Implementation plan
1. **New service**: `cve2capec.service.ts`
   - Fetch `https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/results/new_cves.jsonl`
   - Parse JSONL, build `Map<string, Cve2CapecEntry>` keyed by CVE ID
   - Expose `loaded$`, `total$`, `covered$` per standard pattern
   - Provide `getChainForCve(cveId: string)` returning full kill chain
2. **Sidebar enhancement**: Add "Kill Chain" subsection to CVE sidebar showing:
   - CVE -> CWE weakness class -> CAPEC attack pattern -> ATT&CK technique -> D3FEND countermeasure
   - Visual flow diagram (arrows between each stage)
3. **Heatmap mode**: "CVE Kill Chain Depth" showing techniques reachable via multiple CVE->CWE->CAPEC paths (higher score = more attack surface)
4. **Data health**: Add "CVE2CAPEC" dot to the health ribbon

#### Enhances existing services
- `cve.service.ts`: Cross-reference PoC availability with CAPEC severity
- `capec.service.ts`: Supplement with CVE-sourced CAPEC entries
- `d3fend.service.ts`: Show which D3FEND techniques counter specific CVE chains

---

### Integration 2: Enhanced Detection Coverage (Sigma + EVTX)
**Source**: `mdecrevoisier/SIGMA-detection-rules` (423 stars) + `mdecrevoisier/EVTX-to-MITRE-Attack` (621 stars)
**Roadmap alignment**: Tier 2.2 (SIEM Query Library)
**Effort**: Medium | **Impact**: High

#### What it adds
350+ curated enterprise Sigma rules (supplementing SigmaHQ) plus 270+ EVTX samples for testing those rules. This gives analysts both the detection logic AND sample event data to validate it.

#### Data format
**SIGMA rules** (`mdecrevoisier/SIGMA-detection-rules`):
- Organized by product: `windows-os/`, `windows-defender/`, `cloud-azure/`, etc. (27 directories)
- Standard SIGMA YAML with ATT&CK mapping in `tags` field
- ATT&CK technique IDs as `attack.tXXXX` in rule tags
- No manifest file, but the README contains a comprehensive mapping table

**EVTX samples** (`mdecrevoisier/EVTX-to-MITRE-Attack`):
- Organized by tactic: `TA0001-Initial access/T1078-Valid accounts/`
- Native Windows EVTX format (not parseable in browser)
- README provides comprehensive mapping table: Technique -> Event IDs -> Tool/Threat

#### Implementation plan
1. **Enhance `sigma.service.ts`**:
   - Fetch the GitHub tree for `mdecrevoisier/SIGMA-detection-rules`
   - Count rules per ATT&CK technique (same pattern as `elastic.service.ts`)
   - Merge counts with existing SigmaHQ layer data
   - New metric: `communityRuleCount` alongside `sigmaHqCount`
2. **New service**: `evtx-samples.service.ts`
   - Fetch the GitHub tree for `mdecrevoisier/EVTX-to-MITRE-Attack`
   - Parse directory structure to extract technique->sample mappings
   - Expose `getEvtxSamples(techniqueId: string)` returning sample metadata
   - Expose `loaded$`, `total$`, `covered$` per standard pattern
3. **Sidebar enhancement**: Add "EVTX Samples" section showing:
   - Available sample files for the selected technique
   - Associated Event IDs and tool names
   - Download links to EVTX files for lab testing
4. **Heatmap contribution**: "Detection Test Coverage" mode showing techniques with both rules AND samples
5. **Data health**: Add "Community Sigma" and "EVTX Samples" dots

---

### Integration 3: ThreatHunter Playbook Integration
**Source**: `OTRF/ThreatHunter-Playbook` (4,527 stars)
**Roadmap alignment**: Tier 2.3 (Threat Actor Emulation Plans) + Tier 3.4 (Incident Response Playbooks)
**Effort**: Medium | **Impact**: High

#### What it adds
Per-technique threat hunting playbooks with detection logic, simulation datasets, and SIEM queries (Splunk, Elastic, Azure Sentinel). Transforms ATTACK-Navi from a coverage mapper into an active threat hunting workbench.

#### Data format
- Jupyter notebooks (`.ipynb`) organized by ATT&CK technique ID
- Directory structure: `docs/notebooks/windows/{tactic}/{technique}.ipynb`
- Each playbook contains: analytic description, ATT&CK mapping, detection queries, simulation datasets
- YAML metadata files link notebooks to ATT&CK technique IDs
- Queries available in: Splunk SPL, Elastic DSL, Azure KQL

#### Implementation plan
1. **New service**: `threat-hunter.service.ts`
   - Fetch the GitHub tree for `OTRF/ThreatHunter-Playbook`
   - Parse notebook directory paths to extract technique ID mappings
   - Build `Map<string, PlaybookEntry[]>` with metadata per technique
   - Expose `loaded$`, `total$`, `covered$`
2. **Sidebar section**: "Threat Hunting Playbook"
   - Show playbook availability per technique (title, description)
   - Direct link to Jupyter notebook on GitHub
   - Inline display of key detection queries (SPL, KQL, Elastic)
   - "Copy query" button per SIEM format
3. **Integration with SIEM Query panel**: Merge playbook queries into the existing SIEM query service as a "ThreatHunter" source
4. **Data health**: Add "ThreatHunter Playbooks" dot

---

### Integration 4: MITRE Caldera Adversary Profile Export
**Source**: `mitre/caldera` (6,876 stars) + `mitre/caldera-ot` (244 stars)
**Roadmap alignment**: Tier 2.3 (Threat Actor Emulation Plans)
**Effort**: Low | **Impact**: High

#### What it adds
Export technique selections from ATTACK-Navi as Caldera-compatible adversary profiles. When an analyst selects a threat actor or a custom technique set, they can export it as a YAML file that Caldera can directly import for adversary emulation.

#### Data format
**Caldera adversary profile** (YAML):
```yaml
id: <uuid>
name: "APT29 - ATTACK-Navi Export"
description: "Adversary profile generated from ATTACK-Navi technique selection"
atomic_ordering:
  - <ability-uuid-for-T1059.001>
  - <ability-uuid-for-T1078>
  - <ability-uuid-for-T1190>
objective: <uuid>
tags: []
```

**Caldera abilities** reference ATT&CK technique IDs via:
- `technique_id`: ATT&CK technique ID (e.g., "T1059.001")
- `technique_name`: Human-readable name
- `tactic`: ATT&CK tactic (e.g., "execution")

#### Implementation plan
1. **New export format** in `app.component.ts` export menu:
   - "Export as Caldera Adversary Profile (.yml)"
   - Generates YAML with technique IDs in `atomic_ordering`
   - Since Caldera maps abilities by technique ID, the profile references technique IDs directly
   - User imports the YAML into their Caldera instance
2. **Technique ordering**: Use kill chain phase ordering (Recon -> Impact)
3. **OT variant**: When ICS domain is active, format for `caldera-ot` compatibility
4. **Atomic Red Team cross-reference**: For each technique, show the matching Caldera ability count (fetched from Caldera's public ability index)

---

### Integration 5: Proof-of-Concept Exploit Enrichment
**Source**: `trickest/cve` (7,674 stars) + `0xMarcio/cve` (1,208 stars)
**Roadmap alignment**: Tier 1.2 (Asset Inventory + CVE Exposure Scoring)
**Effort**: Low | **Impact**: High

#### What it adds
Adds "PoC Available" indicators to CVE data, significantly enhancing exposure risk scoring. A CVE with a public proof-of-concept exploit is far more dangerous than one without.

#### Data format
**trickest/cve**:
- GitHub-hosted, organized by year: `{year}/{CVE-ID}.md`
- Each markdown file lists PoC repositories with GitHub URLs
- No structured API, but the GitHub tree provides a directory listing

**0xMarcio/cve**:
- Similar structure: organized by CVE ID
- Links to PoC exploit code and writeups

#### Implementation plan
1. **Enhance `cve.service.ts`**:
   - Fetch GitHub tree for `trickest/cve` (same pattern as `elastic.service.ts`)
   - Build `Set<string>` of CVE IDs that have PoC exploits
   - New property: `hasPoC(cveId: string): boolean`
   - New observable: `pocCoveredCount$` for total CVEs with PoCs
2. **Sidebar enhancement**: Add "PoC" badge next to CVEs that have public exploits
   - Red badge: "PoC Available" with link to trickest/cve page
   - Tooltip: number of known PoC repositories
3. **Risk scoring enhancement**: Multiply EPSS score by PoC factor
   - CVE with PoC: EPSS * 1.5 (capped at 1.0)
   - This feeds into the exposure heatmap for higher accuracy
4. **Heatmap contribution**: "Weaponized CVE Exposure" mode showing techniques with PoC-backed CVEs

---

### Integration 6: Anthropic Cybersecurity Skills Framework
**Source**: `mukul975/Anthropic-Cybersecurity-Skills` (4,151 stars)
**Roadmap alignment**: Tier 4.3 (AI-Powered Analysis)
**Effort**: Medium | **Impact**: Medium

#### What it adds
754 structured cybersecurity skills mapped to MITRE ATT&CK, NIST CSF 2.0, D3FEND, ATLAS, and AI RMF. Provides AI-ready skill recommendations per technique - what capabilities an analyst or AI agent needs to address each technique.

#### Data format
- Skills defined in YAML/JSON with framework mappings
- Each skill entry includes: skill name, description, framework mappings (ATT&CK technique IDs, NIST CSF functions, D3FEND techniques)
- Index file provides lookup by ATT&CK technique ID

#### Implementation plan
1. **New service**: `cybersecurity-skills.service.ts`
   - Fetch skill index from the GitHub repo
   - Build `Map<string, CyberSkill[]>` keyed by ATT&CK technique ID
   - Expose `loaded$`, `total$`, `covered$`
2. **Sidebar section**: "Required Skills"
   - Per technique: list of cybersecurity skills needed to detect/mitigate
   - Cross-framework view: show NIST CSF + D3FEND + ATLAS connections
   - Skill maturity assessment: analyst can rate team capability per skill
3. **Analytics enhancement**: "Skill Gap Analysis" in the analytics panel
   - Overlay skill requirements on coverage data
   - Identify which skills need training based on coverage gaps
4. **Data health**: Add "Cyber Skills" dot

---

## Medium-Value Integrations (Phase 2)

### Integration 7: Sentinel ATT&CK Detection Rules
**Source**: `edoardogerosa/sentinel-attack` (1,081 stars)
**Effort**: Low | **Impact**: Medium

Enhances the existing M365 Defender integration with Azure Sentinel-specific detection rules and Sysmon configurations. Import their Navigator layer for Sentinel coverage scoring. The project provides KQL queries mapped to ATT&CK techniques.

**Service**: Enhance `m365-defender.service.ts` with Sentinel rule counts fetched from this repo's Navigator layer exports.

### Integration 8: EDR Bypass Risk Scoring
**Source**: `tkmru/awesome-edr-bypass` (1,513 stars)
**Effort**: Medium | **Impact**: Medium

Adds "EDR Evasion Risk" metadata per technique. Techniques that have known EDR bypass methods are higher risk even with EDR deployed. This would surface as a warning in the detection panel: "EDR bypass techniques documented for T1055".

**Service**: New `edr-bypass.service.ts` parsing the awesome-list README to extract technique references and EDR bypass method counts.

### Integration 9: OWASP Threat Dragon Export
**Source**: `OWASP/threat-dragon` (1,376 stars)
**Effort**: Low | **Impact**: Medium

Add "Export as Threat Model" to generate a Threat Dragon-compatible JSON file from ATT&CK technique selections. Maps techniques to STRIDE categories for threat modeling workflows.

### Integration 10: ATT&CK Arsenal Red Team Resources
**Source**: `mitre-attack/attack-arsenal` (535 stars)
**Effort**: Low | **Impact**: Medium

Link red team tools and scripts from attack-arsenal to specific ATT&CK techniques in the sidebar. Provides "Red Team Resources" links alongside the existing Atomic Red Team tests.

---

## Integration Architecture

All new integrations follow the established ATTACK-Navi service pattern:

```
┌──────────────────────────────────────────────────────┐
│                   New Service Pattern                 │
├──────────────────────────────────────────────────────┤
│                                                      │
│  @Injectable({ providedIn: 'root' })                 │
│  export class NewIntegrationService {                │
│                                                      │
│    // Standard observables (data health ribbon)      │
│    loaded$:  BehaviorSubject<boolean>                │
│    total$:   BehaviorSubject<number>                 │
│    covered$: BehaviorSubject<number>                 │
│                                                      │
│    // Technique lookup                               │
│    private byTechniqueId = Map<string, T[]>          │
│                                                      │
│    // HTTP fetch with retry                          │
│    constructor(private http: HttpClient) {            │
│      this.load();   // Auto-load on injection        │
│    }                                                 │
│                                                      │
│    private load(): void {                            │
│      this.http.get<any>(URL).pipe(                   │
│        retryWithBackoff(),                           │
│        catchError(() => of(fallback))                │
│      ).subscribe(data => this.parseAndIndex(data));  │
│    }                                                 │
│                                                      │
│    getForTechnique(id: string): T[] {                │
│      return this.byTechniqueId.get(id) ?? [];        │
│    }                                                 │
│  }                                                   │
│                                                      │
└──────────────────────────────────────────────────────┘
```

### Wiring checklist for each new service:
1. Create service file in `src/app/services/`
2. Inject into `data-health.component.ts` and add to `sources` array
3. Inject into `sidebar.component.ts` for technique-level enrichment
4. Add heatmap mode in `filter.service.ts` (if applicable)
5. Follow the 7-step heatmap pipeline (see `docs/HEATMAPS.md`)

---

## Implementation Priority Matrix

| Priority | Integration | Effort | Impact | Roadmap Tier |
|----------|-------------|--------|--------|--------------|
| **P0** | #1 CVE2CAPEC Kill Chain | Medium | High | 1.2 |
| **P0** | #5 PoC Exploit Enrichment | Low | High | 1.2 |
| **P1** | #2 Sigma + EVTX Detection | Medium | High | 2.2 |
| **P1** | #4 Caldera Export | Low | High | 2.3 |
| **P2** | #3 ThreatHunter Playbooks | Medium | High | 2.3 / 3.4 |
| **P2** | #6 Cybersecurity Skills | Medium | Medium | 4.3 |
| **P3** | #7 Sentinel Detection | Low | Medium | 2.2 |
| **P3** | #8 EDR Bypass Risk | Medium | Medium | - |
| **P3** | #9 Threat Dragon Export | Low | Medium | - |
| **P3** | #10 Arsenal Resources | Low | Medium | - |

---

## Not Recommended for Integration

These starred repos are valuable references but don't have direct integration paths:

| Repo | Reason |
|------|--------|
| `mitre-attack/mitreattack-python` | Python library, not web-consumable |
| `CVEProject/cve-schema` | Schema specification, no data |
| `CVEProject/cvelist-bulk-download` | Utility tool, no web API |
| `CVEProject/cve-website` | Website source code |
| `OWASP/DevGuide` | Reference documentation |
| `OWASP/API-Security` | Reference documentation |
| `ebranca/owasp-pysec` | Python library |
| `stanislav-web/OpenDoor` | CLI scanner tool |
| `JohnHammond/katana` | CTF solver (no ATT&CK mapping) |
| `JohnHammond/recaptcha-phish` | Phishing demo |
| `mitre/mitre.github.io` | MITRE homepage |
| `mitre/atomic` | Caldera plugin (covered by Caldera integration) |

---

## Expected Outcomes

After implementing **P0 + P1** integrations (4 integrations):

| Metric | Current | After Integration |
|--------|---------|-------------------|
| Data health ribbon dots | 18 | 22 (+4) |
| CVE enrichment depth | CVE -> ATT&CK | CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND |
| Detection rule sources | 3 (Sigma, Elastic, Splunk) | 4 (+Community Sigma) |
| Test sample coverage | Atomic Red Team only | +270 EVTX samples |
| Export formats | Navigator, CSV, XLSX, JSON, HTML, STIX | +Caldera YAML |
| CVE risk accuracy | EPSS + KEV | +PoC availability factor |
| Heatmap modes | 25 | 28 (+3 new modes) |
