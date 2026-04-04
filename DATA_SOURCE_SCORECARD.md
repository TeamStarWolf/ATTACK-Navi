# Data Source Scorecard

## Goal

This scorecard captures the current state of the app's cyber data sources and mappings so future work can focus on the highest-value gaps.

Status meanings:

- `wired`
  - the source is visible in current product workflows
- `partial`
  - the source exists in code, but the UI or live data pipeline is incomplete
- `missing`
  - no meaningful integration was found in the current project

## Summary

The project already has a stronger enrichment foundation than it first appears to have. The biggest gaps are not "add everything from scratch," but:

- make `Sigma` truly live and authoritative
- strengthen `CVE/CWE/CPE` into clearer product and exposure workflows
- add live CTI via `MISP` or `OpenCTI`
- add open telemetry-backed detection context such as `Zeek` and `Suricata`
- refresh static mappings like `D3FEND` with a healthier ingestion path

## Scorecard

| Source | Current Status | Evidence In Repo | Current UI Surfaces | What It Still Needs |
| --- | --- | --- | --- | --- |
| `MITRE ATT&CK` | `wired` | Core data and matrix architecture throughout the app | Matrix, sidebar, analytics, actor/software/campaign workflows, exports | Keep as the product spine |
| `Atomic Red Team` | `wired` | [atomic.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/atomic.service.ts) bundles tests and fetches Red Canary Navigator layer | Sidebar, matrix overlays, purple-team and scenario context | Better readiness workflows and clearer "tested vs testable" UX |
| `CVE` | `wired` | [cve.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/cve.service.ts), [attack-cve.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/attack-cve.service.ts) | Sidebar, analytics, risk, matrix scoring | Stronger environment-aware relevance and fresher ingestion strategy |
| `KEV` | `wired` | Referenced through CVE analytics/risk logic | Analytics, risk-oriented views | Promote KEV more aggressively as a rank/priority signal |
| `D3FEND` | `partial` | [d3fend.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/d3fend.service.ts) is present but based on bundled static mapping | Sidebar, matrix overlays, defensive guidance | Replace or supplement static mapping with a healthier source pipeline |
| `CAPEC` | `partial` | [capec.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/capec.service.ts) and sidebar usage | Sidebar enrichment | More first-class workflows beyond enrichment and drill-down |
| `CWE` | `partial` | Indirectly modeled through CVE mapping logic in [cve.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/cve.service.ts) | Mostly indirect through CVE views | Expose weakness families more clearly in risk and remediation workflows |
| `CPE` | `partial` | Product/platform relevance appears indirect through CVE/NVD logic, not a first-class app model | Limited or indirect | Add asset-aware product impact views and environment relevance |
| `Sigma` | `partial` | [sigma.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/sigma.service.ts) supports mapping and export, but comments indicate no live counts/backend coverage feed | Matrix logic, export, partial detection workflows | Build real ingestion and trustworthy rule coverage surfaces |
| `YARA` | `partial` | [yara.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/yara.service.ts) exists, plus export-oriented UI components | Likely export or detection-related workflows | Clarify whether coverage is real, enrich sidebar and analytics, and connect it to technique detection stories |
| `CAR` | `wired` | [car.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/car.service.ts) and sidebar/matrix usage | Sidebar, matrix/detection context | Keep improving visibility and recommendation quality |
| `Engage` | `wired` | [engage.service.ts](/C:/Users/dev/Documents/Projects/mitre-mitigation-navigator/src/app/services/engage.service.ts) and sidebar usage | Sidebar, planning-style context | Better connect Engage recommendations to next-action UX |
| `Controls / NIST / CIS / Cloud controls / VERIS / CRI` | `wired` | Dedicated services and active sidebar usage | Sidebar, compliance and planning flows | Better cross-source synthesis instead of separate buckets |
| `MISP` | `missing` | No obvious integration found | None found | Add ATT&CK-tagged event/intel enrichment |
| `OpenCTI` | `missing` | No obvious integration found | None found | Add relationship-rich CTI and provenance |
| `Zeek` | `missing` | No obvious integration found | None found | Add open telemetry-backed coverage and observability guidance |
| `Suricata` | `missing` | No obvious integration found | None found | Add network detection coverage and ATT&CK-linked rule context |

## Strongest Current Areas

- ATT&CK navigation is the true product backbone
- Atomic Red Team is meaningfully integrated already
- CVE and ATT&CK-CVE logic are substantial, not just conceptual
- Defensive and controls enrichment is already broad in the sidebar

## Weakest Current Areas

- detection coverage is not yet backed by a clearly authoritative open-source ingestion layer
- environment-aware product relevance is still weak
- live threat intel integration is absent
- some mapped sources are functional but static rather than refreshable

## Recommended Next Build Order

1. Make `Sigma` real
2. Strengthen `CVE/CWE/CPE` into a more operational exposure workflow
3. Add `MISP` or `OpenCTI`
4. Add `Zeek` and `Suricata`
5. Refresh or deepen `D3FEND`

## Recommended Product Framing

The cleanest model for the app is:

- `ATT&CK` for behavior and navigation
- `CVE/CWE/CPE` for exposure and relevance
- `Sigma/Zeek/Suricata/YARA` for detection coverage
- `Atomic` for validation
- `MISP/OpenCTI` for live intel context
- `D3FEND` and controls mappings for defensive action

That keeps the product matrix-first while turning it into a more operational workspace.
