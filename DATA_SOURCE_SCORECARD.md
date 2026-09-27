# Data Source Scorecard

## Goal

This scorecard captures the current state of the app's cyber data sources and mappings so future work can focus on the highest-value gaps.

Status meanings:

- `wired`
  - the source is visible in current product workflows; this does not prove a live connection or validated detection coverage
- `partial`
  - the source exists in code, but the UI or live data pipeline is incomplete
- `missing`
  - no meaningful integration was found in the current project

**Targeted code review: 2026-09-26.** The MISP, OpenCTI, Zeek, and Suricata rows below
were traced through services, UI callers, and routes. Other source rows are retained from
the earlier scorecard, not newly certified by this review. No private CTI server or network
sensor was connected during this review.

## Summary

The project already has a stronger enrichment foundation than it first appears to have. The biggest gaps are not "add everything from scratch," but:

- make `Sigma` truly live and authoritative
- strengthen `CVE/CWE/CPE` into clearer product and exposure workflows
- validate and complete the existing configurable `MISP` and `OpenCTI` connectors
- validate existing `Zeek` and `Suricata` exports, then add measured telemetry-backed detection context
- refresh static mappings like `D3FEND` with a healthier ingestion path

## Scorecard

| Source | Current Status | Evidence In Repo | Current UI Surfaces | What It Still Needs |
| --- | --- | --- | --- | --- |
| `MITRE ATT&CK` | `wired` | Core data and matrix architecture throughout the app | Matrix, sidebar, analytics, actor/software/campaign workflows, exports | Keep as the product spine |
| `Atomic Red Team` | `wired` | [atomic.service.ts](src/app/services/atomic.service.ts) bundles tests and fetches Red Canary Navigator layer | Sidebar, matrix overlays, purple-team and scenario context | Better readiness workflows and clearer "tested vs testable" UX |
| `CVE` | `wired` | [cve.service.ts](src/app/services/cve.service.ts), [attack-cve.service.ts](src/app/services/attack-cve.service.ts) | Sidebar, analytics, risk, matrix scoring | Stronger environment-aware relevance and fresher ingestion strategy |
| `KEV` | `wired` | Referenced through CVE analytics/risk logic | Analytics, risk-oriented views | Promote KEV more aggressively as a rank/priority signal |
| `D3FEND` | `partial` | [d3fend.service.ts](src/app/services/d3fend.service.ts) is present but based on bundled static mapping | Sidebar, matrix overlays, defensive guidance | Replace or supplement static mapping with a healthier source pipeline |
| `CAPEC` | `partial` | [capec.service.ts](src/app/services/capec.service.ts) and sidebar usage | Sidebar enrichment | More first-class workflows beyond enrichment and drill-down |
| `CWE` | `partial` | Indirectly modeled through CVE mapping logic in [cve.service.ts](src/app/services/cve.service.ts) | Mostly indirect through CVE views | Expose weakness families more clearly in risk and remediation workflows |
| `CPE` | `partial` | Product/platform relevance appears indirect through CVE/NVD logic, not a first-class app model | Limited or indirect | Add asset-aware product impact views and environment relevance |
| `Sigma` | `partial` | [sigma.service.ts](src/app/services/sigma.service.ts) supports mapping and export, but comments indicate no live counts/backend coverage feed | Matrix logic, export, partial detection workflows | Build real ingestion and trustworthy rule coverage surfaces |
| `YARA` | `partial` | [yara.service.ts](src/app/services/yara.service.ts) exists, plus export-oriented UI components | Likely export or detection-related workflows | Clarify whether coverage is real, enrich sidebar and analytics, and connect it to technique detection stories |
| `CAR` | `wired` | [car.service.ts](src/app/services/car.service.ts) and sidebar/matrix usage | Sidebar, matrix/detection context | Keep improving visibility and recommendation quality |
| `Engage` | `wired` | [engage.service.ts](src/app/services/engage.service.ts) and sidebar usage | Sidebar, planning-style context | Better connect Engage recommendations to next-action UX |
| `Controls / NIST / CIS / Cloud controls / VERIS / CRI` | `wired` | Dedicated services and active sidebar usage | Sidebar, compliance and planning flows | Better cross-source synthesis instead of separate buckets |
| `MISP` | `wired` Galaxy reference data; `partial` live-server workflow | [misp.service.ts](src/app/services/misp.service.ts) loads public Galaxy clusters and implements direct/proxy connection tests, event/attribute queries, and event creation | Technique sidebar tags, matrix intelligence scoring, dashboard counts, Intel Feeds reference/template views, Settings connection controls | Wire live event/attribute results into the UI and validate against an authorized server; Galaxy counts are not live event coverage |
| `OpenCTI` | `wired` configurable indicator UI; live compatibility unverified | [opencti.service.ts](src/app/services/opencti.service.ts) implements direct/proxy GraphQL configuration and indicator/actor queries; [sidebar caller](src/app/components/sidebar/sidebar.component.ts) requests indicators | Settings connection controls, technique sidebar indicators, dashboard connection status, Intel Feeds query path | Verify GraphQL schema/filter compatibility and error handling against a supported server; complete actor/relationship workflows and provenance |
| `Zeek` | `wired` script export; telemetry ingestion `missing` | [zeek.service.ts](src/app/services/zeek.service.ts) contains curated script templates and generic TODO fallbacks; [SIEM export](src/app/components/siem-export/siem-export.component.ts) calls its generator | Detection > SIEM (`#/detect/siem`), Zeek export option | Syntax/load checks with Zeek, controlled PCAP replay and negative controls, version/provenance tracking, then sensor-result ingestion; generated files are not observed detections |
| `Suricata` | `wired` rule export; telemetry ingestion `missing` | [suricata.service.ts](src/app/services/suricata.service.ts) contains curated rules and generic network fallbacks; [SIEM export](src/app/components/siem-export/siem-export.component.ts) calls its generator | Detection > SIEM (`#/detect/siem`), Suricata export option | Validate emitted rule syntax and unique SIDs, tune generic fallbacks, test positive/negative traffic, then ingest sensor evidence; export counts are not validated coverage |

## Integration Boundaries

- The static app does not deploy MISP, OpenCTI, Zeek, or Suricata. Connection controls
  and generated artifacts are implemented capabilities, not proof that those services run.
- MISP's `getEventsForTechnique()` / `getAttributesForTechnique()` are service methods
  without current component callers. The Intel MISP view generates an event template;
  it must not be described as a live event browser.
- Direct CTI mode keeps supplied secrets in browser memory. The optional
  [proxy](server/README.md) keeps upstream secrets server-side but does not itself implement
  caller authentication. Keep it behind an authenticated, restricted boundary; CORS alone
  does not authorize clients. No deployment or permission change is implied by this scorecard.
- Zeek's generic fallback contains a TODO rather than a complete analytic. Suricata's
  generic network fallback is broad. Neither should count as technique-specific validated
  detection until tested with representative traffic and negative controls.
- Unit tests and mocked proxy checks establish code behavior, not compatibility with a real
  CTI instance or detection-engine acceptance. Record those results separately.

## Strongest Current Areas

- ATT&CK navigation is the true product backbone
- Atomic Red Team is meaningfully integrated already
- CVE and ATT&CK-CVE logic are substantial, not just conceptual
- Defensive and controls enrichment is already broad in the sidebar

## Weakest Current Areas

- detection coverage is not yet backed by a clearly authoritative open-source ingestion layer
- environment-aware product relevance is still weak
- live CTI connectors exist, but their deployment/schema compatibility and full UI workflows need validation
- network exports lack measured sensor evidence and engine-level validation
- some mapped sources are functional but static rather than refreshable

## Recommended Next Build Order

1. Make `Sigma` real
2. Strengthen `CVE/CWE/CPE` into a more operational exposure workflow
3. Validate and finish existing `MISP` and `OpenCTI` workflows
4. Validate `Zeek` and `Suricata` exports before adding sensor-result ingestion
5. Refresh or deepen `D3FEND`

## Recommended Product Framing

The cleanest model for the app is:

- `ATT&CK` for behavior and navigation
- `CVE/CWE/CPE` for exposure and relevance
- `Sigma/Zeek/Suricata/YARA` for candidate detection content, with validated coverage reported separately
- `Atomic` for validation
- `MISP/OpenCTI` for reference/configurable intel context, live only when connected and verified
- `D3FEND` and controls mappings for defensive action

That keeps the product matrix-first while turning it into a more operational workspace.
