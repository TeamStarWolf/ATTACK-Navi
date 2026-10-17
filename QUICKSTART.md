# ATTACK-Navi quick start

ATTACK-Navi is a browser-based workbench for MITRE ATT&CK. It runs as a static site with
no login and no required backend. This guide covers how to move around, what the colors
mean, and the common workflows.

## Open the app

Hosted build: https://teamstarwolf.github.io/ATTACK-Navi/

The matrix loads with bundled Enterprise ATT&CK 19.2. Nothing is sent anywhere; the data
you enter (assets, assessment answers, annotations) stays in your browser.

## Move around

The left rail holds 10 workspaces: Matrix, Detection, Exposure, Dashboard, Threat Intel,
Coverage, Library, Reports, Status and Settings. Each workspace has its own tabs (47 tabs
in all). Three ways to navigate:

- `Ctrl+K` opens the command palette. Type a destination name and press Enter.
- Every tab has its own URL, so you can bookmark or share it.
- Press `?` for the keyboard shortcut list.

## What the colors mean

Lens labels follow the Known / Covered / Proven vocabulary, so a color never claims more
than the data behind it supports:

- **Known (reference data).** The world knows how to mitigate, detect or test the
  technique. These lenses read "mapped", "available" or "reference depth". They say nothing
  about your environment.
- **Covered (self-attested).** Something is deployed for the technique, recorded by you, but
  not shown to have fired. The assessment and status lenses sit here.
<!-- truth-vocab-allow-next-line proven-only -- names the Proven rung in its own definition; not a claim about this app's data -->
- **Proven.** A named detection fired, or the technique was blocked, on a recorded date.
  The hosted app carries none of it; that rung comes from range evidence, not from anything
  you can enter in the browser.

So the matrix out of the box shows reference depth (what is mappable), not your posture.
Your posture appears only after you record your own implementation status or import assets.

## Workflow: map your coverage and find gaps

### 1. Record your implementation status

1. Open Coverage, Assessment (or `Ctrl+K`, then "assessment").
2. Pick a domain. Enterprise is the common choice.
3. Select the threat groups relevant to your sector.
4. Mark your self-attested implementation status for each technique.
5. Review the summary: techniques with a mapped mitigation, and the ones you marked as
   implemented. The summary is self-attested, not evidenced.
6. Export the result.

### 2. Import your assets

1. Open Coverage, Assets (or `Ctrl+K`, then "assets").
2. Upload a CSV with the columns `hostname, os, software, tags, criticality`.
3. Open Exposure, or turn on the My Exposure lens, to see which techniques affect the
   assets you imported. My Exposure is a reachability view, not a posture rung.

### 3. Run a gap analysis

1. Open Exposure, Gap Analysis (or `Ctrl+K`, then "gap analysis").
2. Select the threat groups you care about.
3. Generate the report. It marks each of the selected groups' techniques by whether you
   have a mapped mitigation and a self-attested detection, so the gaps are the techniques
   with neither.
4. Export as PDF.

## The matrix and the technique sidebar

Click any technique to open the sidebar. Hover for a short tooltip. Search by ID (T1059) or
name (PowerShell) in the top bar.

The sidebar collects what public sources know about a technique: ATT&CK mitigations and
your implementation status; detection content from Sigma, Elastic, Splunk, M365 Defender,
CAR and Atomic Red Team; CVE and KEV links and EPSS scores; copy-ready SIEM queries;
D3FEND countermeasures and MITRE Engage activities; and control mappings for NIST 800-53,
CRI Profile, VERIS, CSA CCM and cloud providers. Each section names its source, and the
detection and control sections are reference data (Known) unless you have recorded your own
status.

## Heatmap modes

The Coverage dropdown in the toolbar switches the matrix coloring. There are 33 modes,
grouped as Coverage and Posture, Threat Landscape, Vulnerabilities, Detections and
Frameworks. Each mode carries a rung, so a Detections lens reads "mapped" or "available"
(reference content exists), not a self-attested or evidenced claim, unless the data is yours. The Threat Landscape
and Vulnerabilities lenses are dimensions (how much adversaries care, what is reachable),
never a posture rung.

## Workspaces and tabs

| Workspace | Tabs |
|---|---|
| Matrix | the single matrix view |
| Detection | Detections, Sigma, SIEM, YARA, Validation, Data Sources, Purple Team |
| Exposure | CVE, Risk, Kill Chain, Graph, Gap Analysis, Priority, SSVC, Dossier, What-If, CTEM |
| Dashboard | Overview, Analytics |
| Threat Intel | Groups, Actors, Compare, Scenarios, Emulation, Campaigns, Software, Feeds |
| Coverage | Assessment, Controls, Custom Mitigations, Compliance, Diff, Timeline, Target, Assets |
| Library | Workbench, Layers, Collections, Comparison, Roadmap, Watchlist, Tags |
| Reports | Report Builder, IR Playbooks, Export Hub |
| Status | source health and data freshness |
| Settings | Preferences, Changelog |

The Library workspace includes 37 named layers drawn from the TeamStarWolf library.

## Share and export

- **Share a technique.** The Share button in the sidebar header copies a URL such as
  `https://teamstarwolf.github.io/ATTACK-Navi/#tech=T1059.001`. Opening it pre-selects the
  technique.
- **Share a collection.** Library, Collections has a share link that encodes your custom
  techniques and annotations in the URL hash.
- **Export.** Reports, Export Hub offers CSV, XLSX, an HTML report, PDF, PNG, an ATT&CK
  Navigator JSON layer (import and export), a STIX 2.1 bundle, Sigma rules, SIEM queries and
  YARA rules.

## Optional integrations

Set these in Settings. They are optional; the app works without them.

- **MISP.** Enter your server URL, API key and organization ID, then Test and Save. The
  Threat Intel panel and sidebar then show your MISP data.
- **OpenCTI.** Enter your URL and API token. The sidebar then shows OpenCTI indicators and
  actors.
- **TAXII 2.1.** Add a server, fetch collections and import STIX bundles.
- **NVD API key.** Register at https://nvd.nist.gov/developers/request-an-api-key and enter
  the key in Settings to raise your NVD rate limit for CVE queries.

Credentials entered in the browser stay in the browser. To keep OpenCTI or MISP credentials
off the client, run the optional proxy under `server/` (see Self-hosting).

## Offline use

The hosted build is a Progressive Web App. After the first visit it works offline, and
ATT&CK data is cached locally. Look for the install prompt in your browser's address bar to
add it to your device.

## Self-hosting

### Docker

```bash
cp server/.env.example server/.env    # optional: credentials and PROXY_AUTH_TOKEN for the proxy
docker compose up -d --build
```

Opens on http://localhost:8080. The optional credentials proxy is reached through the app at
http://localhost:8080/api/ (and from the host on 127.0.0.1:8787). The stack starts without
`server/.env`; the proxy has nothing to forward until you fill it in. To serve on a LAN
address or hostname instead of localhost, set `APP_ORIGIN` (the page origin, for example
`http://navi.lan:8080`) and `APP_HOST` (the bare host name the browser uses, for example
`navi.lan`) in a `.env` file next to `docker-compose.yml`; the proxy refuses other Host
names.

### Kubernetes

```bash
helm install attack-nav helm/attack-nav/
```

### Manual

```bash
npm ci && npx ng build
# Serve dist/mitre-mitigation-navigator/browser/ with any static server
```

## Data, limits and credits

The matrix shows reference data by default: what public sources map, not your posture. The
only environment-specific views are the ones you populate (assessment status, imported
assets, annotations), and those are self-attested, not evidenced. The hosted app has no data
at the evidenced rung.

ATT&CK, ICS and Mobile ATT&CK and the CTID F3 Fraud Framework are bundled; D3FEND, the CTID
mappings, Sigma, Elastic, Splunk, Atomic Red Team, Galeax CVE2CAPEC, CISA KEV, FIRST EPSS,
NVD and others are fetched from their upstream sources at runtime. `THIRD_PARTY_NOTICES.md`
lists every source with its license and terms, and the Status workspace shows which sources
loaded.

© 2026 The MITRE Corporation. The ATT&CK data in this repository is reproduced and
distributed with the permission of The MITRE Corporation. MITRE ATT&CK® is a registered
trademark of The MITRE Corporation. This project is not affiliated with or endorsed by
MITRE. This product uses the NVD API but is not endorsed or certified by the NVD. Data
fetched at runtime from other sources remains subject to those sources' own licenses and
terms.
