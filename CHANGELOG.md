# Changelog

All notable changes to ATTACK-Navi are documented here.

## v0.8.0 — Navigation Overhaul & Data Accuracy (2026-08-15)

### The big one: real navigation
- **Angular Router adopted (hash routing)** — every one of the 44 former overlay
  panels is now a routed page with a bookmarkable URL, working back/forward, and
  per-workspace lazy loading. Legacy share links (`#tech=T1059`, filter-key
  hashes, `#import=` collection links) are migrated transparently at startup.
- **9 workspaces** — Matrix, Dashboard, Intel, Detect, Exposure, Coverage,
  Library, Reports, Settings — each with a tab bar carrying its destinations.
  The pre-router "library view mode" became the Library ▸ Workbench tab.
- **Nav rail redesigned** — 44 emoji buttons with 8px labels became 10 workspace
  links with SVG icons and legible labels. Mobile bottom bar now includes Help
  and Settings.
- **Toolbar slimmed** — matrix-scoped controls (searches, filters, heatmap
  picker) moved onto the matrix page; the 14-item export menu became the
  Reports ▸ Export Hub card grid; one global search box opens the command
  palette.
- **Command palette (Ctrl+K)** — searches entities *and* commands: "Go to" any
  of the 44 destinations (old names still match) and actions (exports, theme,
  clear filters, share, help).
- **One keyboard listener** — shortcuts defined once in `models/shortcuts.ts`,
  implemented by `HotkeysService`, rendered by the help overlay (`?`). Modifier
  combos now work while typing in inputs.
- **Sidebar jump index** — the 48 detail sections are reachable through a sticky
  grouped index; sections start collapsed except the core technique profile.
  Hand-curated sections carry a visible "curated" chip.
- **Performance** — initial bundle 2.2 MB → ~1.0 MB raw; service worker now
  caches lazy chunks on demand instead of prefetching everything.

### Data accuracy
- Removed two CAR analytics that do not exist upstream (CAR-2022-06-001,
  CAR-2023-01-001) and the entire hardcoded Atomic test table (21 of 27
  spot-checked names were not in the upstream index) — Atomic details now come
  only from live per-technique YAML and Red Canary's published counts.
- D3FEND bundled seed is provenance-stamped as a curated fallback; the live
  ontology API always wins.

### Infrastructure
- Playwright e2e suite (29 tests) now gates every deploy in CI.
- Initial-bundle budget ratcheted from 3 MB warn to 1.2 MB warn / 2 MB error.

## v0.7.0 — Reliability & Infrastructure (2026-04-17)

### New Features
- **Technique of the Day** — Toolbar button (🎯) highlights a daily rotating technique seeded from the calendar date; click to select and open its sidebar
- **Helm chart documentation** — `docs/HELM.md` covers all chart values, ingress setup, resource sizing, backend proxy configuration, and upgrade commands

### Test Coverage Fixes
- **ExploitdbService spec** — Fixed `triggerLoad()` / `triggerLoadError()` helpers to call `loadOnDemand()` before emitting to ensure the lazy-init HTTP subscription is registered
- **NucleiService spec** — Same lazy-init fix: `loadOnDemand()` added to trigger helpers
- **ElasticService spec** — Updated URL constant from pre-built Navigator layer to GitHub tree endpoint (`/git/trees/main`); updated live-load smoke test to use tree format
- **SplunkContentService spec** — Updated URL constant from pre-built Navigator layer to GitHub tree endpoint (`/git/trees/develop`); updated live-load smoke test to use tree format
- **DataHealthComponent spec** — Added provider mocks for 9 new services; updated dot-count assertions from 15 to 24

### Infrastructure
- **Docker CI** — `.github/workflows/docker.yml` builds the production image and smoke-tests nginx (HTTP 200 on root) on every push touching `Dockerfile`, `src/**`, or `package*.json`
- **Dockerfile fix** — Replaced `npm ci` with `rm -f package-lock.json && npm install` to work around stale peer-dependency lock
- **Deploy workflow** — Removed stale `package-lock.json`; upgraded `upload-pages-artifact` to `@v4`

### Code Quality
- **Nav-rail component** — Extracted 2,311-char inline template and 6,546-char inline styles to separate `.html` / `.scss` files; component file reduced from 13,584 to 4,776 chars

---

## v0.6.0 — Data Enrichment Expansion (2026)

### New Integrations
- **ExploitDB** — Live cross-reference of ExploitDB CVE entries to ATT&CK techniques
- **Nuclei Templates** — GitHub tree scan of nuclei-templates; CVE-tagged templates mapped to ATT&CK
- **EPSS Scores** — EPSS probability scores for CVEs in the technique sidebar
- **CISA KEV** — Known Exploited Vulnerabilities indicator on technique and CVE views
- **NVD Bulk** — Bulk NVD data loader for enriched CVE detail
- **CVE2CAPEC** — Automated CVE-to-CAPEC mapping enrichment
- **PoC Exploits** — PoC-in-GitHub cross-reference per CVE
- **EVTX Samples** — EVTX sample correlation via evtx-attack-samples
- **Sentinel Rules** — Microsoft Sentinel analytics rule count per technique
- **Anthropic Skills** — Anthropic Claude skill templates mapped to techniques
- **ThreatHunter Playbook** — MITRE ThreatHunter-Playbook entries per technique

### Components
- **Data Health ribbon** — Status dots for all 24 data sources with live load indicators and last-refreshed timestamp
- **Coverage analytics** — `covered$` and `total$` observables on every enrichment service for matrix saturation display

---

## v0.5.0 — Detection Coverage (2026)

### New Features
- **Elastic Rules** — GitHub tree scan for Elastic detection-rules `rules/*.toml`; technique IDs extracted from filenames
- **Splunk Content** — GitHub tree scan for Splunk security_content `detections/*.yml`; technique IDs extracted
- **Matrix Zoom** — Viewport-fit zoom button for full-matrix overview
- **Print Stylesheet** — Optimized `@media print` styles for exporting matrix views
- **Technique Count Badges** — ATT&CK tactic headers show technique counts
- **Share Technique** — "Share this technique" URL generation with pre-selected technique in hash state
- **Changelog Panel** — Auto-update notification when newer version is detected

---

## v0.4.0 — Coverage Mapping (2026)

### New Features
- **CAR Analytics** — MITRE Cyber Analytics Repository rule mapping per technique
- **D3FEND** — MITRE D3FEND countermeasure mapping
- **VERIS** — VERIS community database mapping
- **Cloud Controls** — Cloud security control framework mapping
- **CRI Profile** — Cyber Risk Institute profile mapping
- **Copy as Markdown** — Technique detail sidebar copy-to-clipboard as formatted Markdown
- **CSV Import** — Bulk implementation status upload via Navigator-format CSV

---

## v0.3.0 — Compliance & Intelligence (2026)

### New Features
- **NIST 800-53** — ATT&CK-to-NIST control mapping panel
- **CAPEC** — Common Attack Pattern Enumeration and Classification integration
- **MISP Galaxy** — MISP Galaxy cluster mapping
- **ATT&CK CVE** — MITRE ATT&CK CVE mappings cross-referenced to techniques
- **Actor Compare** — Side-by-side threat actor technique comparison panel
- **Kill Chain** — Unified kill chain visualization panel

---

## v0.2.0 — Threat Intelligence & Atomic Testing (2026)

### New Features
- **Sigma Rules** — Sigma rule count per technique from SigmaHQ/sigma
- **Atomic Red Team** — Atomic Red Team test count per technique
- **OpenCTI** — OpenCTI threat intelligence platform proxy integration
- **Scenario Builder** — Attack scenario planning panel
- **Graph View** — Technique relationship graph panel
- **Risk Matrix** — Risk scoring matrix panel
- **Campaign Timeline** — ATT&CK campaign browser with timeline view

---

## v0.1.0 — Initial Release (2026)

### Features

- **Matrix** — Interactive ATT&CK matrix with Enterprise, Mobile, and ICS domain support
- **Heatmaps** — 24+ heatmap modes (coverage, exposure, detection, compliance, risk)
- **Sidebar** — Per-technique detail panel with mitigations, groups, software, CVEs, and detection rules
- **Threat Intelligence** — MISP and OpenCTI integration via optional backend proxy
- **CVE/Exposure** — NVD, KEV, EPSS, ExploitDB, and Nuclei correlation
- **Detection** — Sigma, Elastic, Splunk, Atomic Red Team, and CAR rule mapping
- **Compliance** — NIST 800-53, CIS Controls, D3FEND, and CRI Profile mapping
- **Export** — HTML reports, PDF reports, XLSX, CSV, ATT&CK Navigator layers, and matrix PNG
- **Panels** — Dashboard, analytics, priority, gap view, risk matrix, scenario, roadmap, what-if, and more
- **PWA** — Service worker for offline-capable deployment
- **GitHub Pages** — Automated deployment workflow
