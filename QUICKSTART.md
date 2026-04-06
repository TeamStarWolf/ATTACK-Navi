# ATTACK-Navi Quick Start Guide

## Getting Started

Open the app: **https://teamstarwolf.github.io/ATTACK-Navi/**

The matrix loads automatically with Enterprise ATT&CK data. No login required.

---

## Core Workflow: "How secure am I?"

### Step 1: Run the Assessment Wizard
1. Click **ASSESS** in the nav rail (left sidebar)
2. Pick your domain (Enterprise is most common)
3. Select threat actors relevant to your industry
4. Rate your implementation status for each technique
5. Review your coverage score and top gaps
6. Export the results

### Step 2: Import Your Assets
1. Click **ASSETS** in the nav rail
2. Upload a CSV with columns: `hostname, os, software, tags, criticality`
3. Switch to the Exposure tab to see which techniques affect YOUR environment
4. Enable the "My Exposure" heatmap to see your personalized risk

### Step 3: Run Gap Analysis
1. Click **GAP RPT** in the nav rail
2. Select the threat actors you care about
3. Click Generate — you get a RAG (Red/Amber/Green) report showing:
   - Which actor techniques you've mitigated
   - Which ones you have detection rules for
   - Which ones you're completely blind to
4. Export as PDF for your CISO

---

## Daily Use

### Browse the Matrix
- **Click any technique** to open the sidebar with 30+ enrichment sections
- **Hover** to see a tooltip with key stats
- **Search** by ID (T1059) or name (PowerShell) in the top search bar

### Heatmap Modes (26 available)
Click the **Coverage** dropdown in the toolbar. Key modes:
- **Coverage** — which techniques have mitigations (green = covered)
- **Risk** — combined risk score
- **KEV** — CISA Known Exploited Vulnerabilities
- **EPSS** — exploitation probability
- **My Exposure** — YOUR risk based on imported assets
- **Intelligence** — threat intel signal density
- **Sigma/Elastic/Splunk** — detection rule coverage
- **M365 Defender** — Microsoft hunting query coverage

### Sidebar Sections (when you click a technique)
The sidebar shows everything known about a technique:
- Mitigations and implementation status
- CVE exposure (from 4.5M mappings)
- EPSS exploitation probability
- Sigma, Elastic, Splunk, M365 Defender detection rules
- Atomic Red Team tests (with copy Invoke-AtomicTest commands)
- SIEM queries for 5 platforms (copy to clipboard)
- AD attack paths (BloodHound mappings)
- C2 framework capabilities (Sliver, Cobalt Strike, Metasploit)
- PayloadsAllTheThings references
- Windows logging configuration scripts
- MISP Galaxy clusters, OpenCTI indicators
- NIST 800-53, CRI, cloud controls, VERIS
- D3FEND countermeasures, MITRE Engage activities
- Completeness score (0-100%)

### Technique of the Day
The **Dashboard** panel shows a random technique each day. Good for team learning.

---

## Key Panels

| Nav Item | What It Does |
|----------|-------------|
| **DASHBOARD** | Configurable widgets: coverage, radar chart, gaps, health, KEVs |
| **THREATS** | Select threat groups, see their techniques, run gap analysis |
| **ACTORS** | Deep-dive on a specific threat actor |
| **SCENARIO** | What-if simulation: "What if APT29 targets us?" |
| **INTEL** | Unified threat intelligence: MISP + OpenCTI + ATT&CK |
| **KILL CHAIN** | Technique distribution across attack phases |
| **ANALYTICS** | Radar chart + tactic breakdown |
| **DETECT** | Detection coverage across all rule sources |
| **GAP RPT** | Detection gap analysis with RAG scoring |
| **CVE** | Search CVEs, browse KEV catalog, explore by technique |
| **ASSETS** | Import asset inventory, see personalized exposure |
| **CONTROLS** | NIST 800-53, CIS, cloud control mappings |
| **COMPLY** | SOC 2 / ISO 27001 / PCI DSS compliance mapping |
| **SIGMA** | Generate and export Sigma detection rules |
| **SIEM** | Pre-built queries for Splunk, Elastic, Microsoft, Chronicle, CrowdStrike |
| **YARA** | Generate YARA malware detection rules |
| **IR PLAY** | Incident response playbooks (5-phase) |
| **PURPLE** | Purple team planning and validation |
| **ASSESS** | Guided step-by-step coverage assessment |
| **COLLECT** | STIX 2.1 import/export, custom techniques, sharing |
| **LAYERS** | Save and restore matrix view snapshots |
| **REPORT** | Generate HTML coverage reports |

---

## Sharing & Export

### Share a Technique
Click the **Share** button in the sidebar header. Copies a URL like:
`https://teamstarwolf.github.io/ATTACK-Navi/#tech=T1059.001`

Anyone opening that link sees the technique pre-selected.

### Share Your Collection
In the **COLLECT** panel, click "Share Link" to generate a URL containing your custom techniques and annotations (base64-encoded in the hash).

### Export Formats
Click **Exports** in the toolbar:
- CSV, XLSX (multi-sheet), HTML report, PDF, PNG screenshot
- ATT&CK Navigator JSON layer
- STIX 2.1 bundle
- Sigma rules, SIEM queries, YARA rules

---

## Integrations (Optional)

### Connect MISP Server
1. Click **Settings** in the nav rail
2. Enter your MISP URL, API key, and Org ID
3. Click "Test & Save"
4. The INTEL panel and sidebar now show live MISP data

### Connect OpenCTI
1. Click **Settings**
2. Enter your OpenCTI URL and API token
3. Click "Test & Save"
4. Sidebar shows OpenCTI indicators and threat actors

### Connect TAXII 2.1 Server
1. Click **Settings**
2. Add a TAXII server (URL, credentials)
3. Fetch collections and import STIX bundles

### NVD API Key (Faster CVE Queries)
1. Register at https://nvd.nist.gov/developers/request-an-api-key
2. Enter the key in Settings
3. CVE queries run 3x faster

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Escape` | Close sidebar or panel |
| `/` | Focus search bar |
| `?` | Show keyboard help |

---

## Offline Use

The app is a PWA (Progressive Web App). After your first visit, it works offline — ATT&CK data is cached locally for 24 hours.

To install on your device: look for the "Install" prompt in your browser's address bar.

---

## Self-Hosting

### Docker
```bash
docker-compose up -d
```
Opens on http://localhost:8080 (app) and http://localhost:8787 (proxy).

### Kubernetes
```bash
helm install attack-nav helm/attack-nav/
```

### Manual
```bash
npm install && npx ng build
# Serve dist/mitre-mitigation-navigator/browser/ with any static server
```
