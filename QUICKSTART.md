# ATTACK-Navi quick start

ATTACK-Navi is a browser-based workbench for MITRE ATT&CK. It runs as a static site with
no account and no project server. This guide shows the first path to try, how to move
around, what the colors mean, and the common workflows. It describes the app as built from
`main`; control names are quoted as they appear on screen.

## Open the app

Hosted build: https://teamstarwolf.github.io/ATTACK-Navi/

The matrix loads with bundled Enterprise ATT&CK 19.2. There is no login and no telemetry.
The data you create, assessment answers, imported assets, annotations and saved views,
stays in your browser's local storage. Some features do reach the network: the app fetches
reference datasets from their upstream hosts (listed in Data, limits and credits), a CVE
search sends your query to the NVD API, and any MISP, OpenCTI or TAXII server you
configure is contacted directly.

## First five minutes

This path needs no setup and runs on one technique:

1. Open the app. The matrix loads on the Prevalence lens (the lens button reads
   "Frequency"). The first-glance banner above the matrix says it shows adversary
   prevalence, reference data, not your environment; expand "Legend · quick filters" to see
   its THREAT badge.
2. Click a technique, for example T1059.001 (PowerShell). The sidebar opens. Its "Reference
   sources mapped" card is a Known count of how many reference sources map to the technique.
3. Open the sidebar sections that are populated for it: Detected By (the data sources that
   observe it), CAR Detection Analytics, Wazuh stock rules (curated), Atomic Red Team
   Tests, and SIEM Queries.
4. In SIEM Queries, use Copy query to copy one to the clipboard.
5. Use the link button in the sidebar header ("Copy share link") to copy a link; opening
   it reopens the app with T1059.001 selected (the lens is not restored).
6. To color the whole matrix by detection content, open the lens button ("View and explore
   options") and choose "Sigma Rules" (in the Detections group; the button then reads
   "Sigma"). The lens count comes from the SigmaHQ coverage layer; the per-technique Sigma
   rule detail in the sidebar is community content that appears only when `api.github.com`
   is reachable (see Troubleshooting).

## Move around

The left rail lists the workspaces: Matrix, Exposure, Intel, Detect, Coverage, Dashboard,
Reports, Library, Status, then Help and Settings. Most workspaces have their own tabs;
Matrix and Status do not. Three ways to navigate:

- `Ctrl+K` opens the command palette. Type a destination name and press Enter.
- Every tab has its own URL, so you can bookmark or share it.
- Press `?` for the keyboard shortcut list.

## What the colors mean

Lens colors follow the Known / Covered / Proven vocabulary, so a color never claims more
than the data behind it supports:

**Known** is reference data: public sources map a mitigation, detection or test to the
technique, with no claim about your environment.

**Covered (self-attested)** is something you recorded as deployed, not shown to have fired.

<!-- truth-vocab-allow-next-line proven-only -- defines the Proven rung, not a claim about this app -->
**Proven** is a named detection firing or a block on a recorded date. No lens colors the
matrix at this rung. You can log validation runs under Detect > Validation, but those are
self-recorded, not an automated result.

Read the active lens from its legend rather than the color alone. Expand Legend under the
toolbar and it shows, for the current lens, a rung badge (KNOWN, COVERED self-attested,
THREAT or EXPOSURE), the question the lens answers, a Sources line, what a zero cell
means, and a "What is this lens?" button. THREAT and EXPOSURE are dimensions (how much
adversaries care, what is reachable), not posture. The default Prevalence lens carries the
THREAT badge.

## The lens picker

The matrix toolbar has a lens button, "View and explore options", that shows the active
lens short label ("Frequency" by default) and opens a menu to switch the matrix coloring
or change sorting and filtering. There are 33 lenses. With no viewpoint set, the menu
groups are Threat Landscape, Vulnerabilities, Detections, Frameworks and Coverage &
Posture; Frequency is listed under Coverage & Posture but carries the THREAT badge. Each
lens carries a rung, shown as its legend badge, so before reading a color open the legend
and check whether the badge reads KNOWN, COVERED self-attested, THREAT or EXPOSURE.

## Record your own coverage

Two lenses read your self-attested input: Status (the implementation status you set on
mapped mitigations) and Controls (the controls you declare). You can also log validation
runs by hand under Detect > Validation, each with an outcome and evidence links. Everything
else is reference data.

### Assessment (Coverage > Assessment)

1. Open Coverage > Assessment (or `Ctrl+K`, then "assessment").
2. Pick a domain. Enterprise is the common choice.
3. Select the threat groups relevant to your sector.
4. Set your implementation status for each technique.
5. The results show how many techniques you marked Implemented or In Progress, a coverage
   percentage, a threat-weighted gap (0 to 100), a tactic breakdown and the top priority
   gaps. These are self-attested, not validated.
6. Use Export Assessment (CSV) to save them.

### Assets and exposure (Coverage > Assets)

1. Open Coverage > Assets (or `Ctrl+K`, then "assets").
2. In the Inventory tab, upload a CSV whose first line is the header `hostname`
   (required), with optional `os,software,tags,criticality`. `software` and `tags` are
   `;`-separated; `criticality` is one of `critical`, `high`, `medium` or `low`, and
   anything else becomes `medium`. For example:

   ```
   hostname,os,software,tags,criticality
   web01,Ubuntu 22.04,nginx;openssh,prod;dmz,high
   ```

   You can also add assets by hand.
3. Open the Exposure tab to see which techniques reach your assets, and use Enable My
   Exposure Heatmap to color the matrix by it. Matching is keyword-based and heuristic,
   and My Exposure is a reachability view (the EXPOSURE dimension), not a posture rung.

### Gap analysis (Exposure > Gap Analysis)

1. Open Exposure > Gap Analysis (or `Ctrl+K`, then "gap analysis").
2. Select the threat groups you care about, or tick "Analyze all techniques (no actor
   filter)". Generate Report stays disabled until you do one or the other. The scope is
   the parent techniques of the selected groups, or all parent techniques when you analyze
   all.
3. Generate the report. For each technique it checks whether ATT&CK maps a mitigation to
   it and whether public detection content exists for it (Sigma, Elastic, Splunk, M365,
   CAR). Prioritized Gaps are techniques missing a mitigation or detection; Fully Blind
   are the ones with neither. This is reference data, not your posture.
4. Save with CSV, Excel, or Print / Save as PDF.

## The technique sidebar

Click any technique to open the sidebar. Hover for a short tooltip. Search by ID (T1059)
or name (PowerShell) in the top bar. The "Reference sources mapped" card is a Known count.

The sidebar collects what public sources record about a technique, as collapsible sections
that appear when they have content: ATT&CK mitigations and the status you set; Detected By
(data sources); detection content in CAR Detection Analytics, Wazuh stock rules (curated),
Atomic Red Team Tests, SIEM Queries, and Sigma Rules, Microsoft 365 Defender and Sentinel
Rules when those are present; CVE and KEV links and EPSS scores; D3FEND countermeasures
and MITRE Engage activities; and control mappings for NIST 800-53, CRI Profile, VERIS, CSA
CCM and cloud providers. Elastic and Splunk appear as rule counts rather than as their own
sections.

For offensive work the sidebar also has CAPEC, ExploitDB, Nuclei, PoC Exploits, Payloads,
C2, BloodHound, Offensive tools, EVTX samples and ThreatHunter Playbook sections, again
shown when populated. Some of this is curated in this repository (the Wazuh mappings,
offensive tools, C2, BloodHound, the YARA, Zeek and Suricata templates and the IR
playbooks); the rest is upstream reference data. Each section names its source, and nothing
here reflects your own posture unless you have recorded a status.

## Workspaces and tabs

| Workspace (rail label) | Tabs |
|---|---|
| Matrix | none; the matrix view |
| Exposure | CVE, Risk, Kill Chain, Graph, Gap Analysis, Priority, SSVC, Dossier, What-If, CTEM |
| Intel (Threat Intel) | Groups, Actors, Compare, Scenarios, Emulation, Campaigns, Software, Feeds |
| Detect (Detection) | Detections, Sigma, SIEM, YARA, Validation, Data Sources, Purple Team |
| Coverage | Assessment, Controls, Custom Mitigations, Compliance, Diff, Timeline, Target, Assets |
| Dashboard | Overview, Analytics |
| Reports | Report Builder, IR Playbooks, Export Hub |
| Library | Workbench, Layers, Collections, Comparison, Roadmap, Watchlist, Tags |
| Status | none; source health and data freshness |
| Settings | Preferences, Changelog |

The Library workspace includes 37 named layers drawn from the TeamStarWolf library.

## Share and export

- **Share a technique.** The link button in the sidebar header ("Copy share link") copies
  a link that reopens the app with the technique selected; the active lens is not
  restored. A second button copies the technique as Markdown.
- **Share a collection.** Library > Collections has a share link, and the STIX 2.1 bundle
  import and export, for your custom techniques and annotations.
- **Export Hub (Reports > Export Hub).** Six sections: Coverage Data (Coverage CSV, Tactic
  Summary, Implementation Plan, Excel Workbook), Reports (Full Report, HTML Report, PDF
  Report, Print Matrix, Matrix PNG), ATT&CK Navigator (Export, Open in, Import), Workspace
  State (Export State, Import State), Saved Layers, and Full Workspace Backup (Export
  Workspace, Import Workspace).
- **Detection exports.** Sigma rule templates, SIEM queries and YARA rules are generated
  from their own Detect tabs (Sigma, SIEM, YARA). The Sigma output is a labelled template
  at informational level, a starting point you complete.

## Optional integrations

Set these at Settings > Preferences > Integrations with Test & Save. They are optional;
the app works without them. Each integration has a Direct browser mode and a Secure
backend proxy mode. Direct mode keeps the secret in memory for the session and needs the
server to allow cross-origin requests (CORS). Proxy mode sends requests through the proxy
under `server/`: set the per-integration proxy URL field to the proxy origin
(`http://localhost:8080` under the compose stack, or `http://localhost:8787` per README;
the service appends its own `/api/...` path). Set the token in Settings > Preferences >
Integrations > "Proxy access token" to the `PROXY_AUTH_TOKEN` the proxy expects.

- **MISP.** Enter your server URL, API key and organization ID, then Test & Save. The
  connection test and the public MISP Galaxy clusters work; querying your own MISP events
  and attributes is not wired into the UI, and the MISP Events tab builds templates
  locally.
- **OpenCTI.** Enter your URL and API token. The sidebar then shows OpenCTI indicators and
  actors.
- **TAXII 2.1.** Add a server, fetch collections and import STIX bundles.
- **NVD API key.** The key is sent only by the per-technique CWE lookups, not by keyword
  or CVE ID searches, and it raises your NVD rate limit. README.md ("Configuration") has
  the exact limits.

## Offline use

The hosted build is a Progressive Web App. After the first visit its shell works offline.
The service worker caches runtime data only for the listed upstream hosts, for 6 to 24
hours, and never caches `api.github.com`, so offline or after the cache expires those
sources show the MISSING DATA banner. The ICS and Mobile ATT&CK bundles are cached lazily,
on first use. The install prompt appears in Chromium browsers; desktop Firefox does not
offer one.

## Troubleshooting: the MISSING DATA banner

Several datasets load from `api.github.com` without authentication, which GitHub limits to
60 requests per hour per IP. After a few loads, or behind a shared corporate IP, that
limit is reached and sources fail, including Elastic, Splunk, community Sigma, PoC
exploits, M365 hunting queries, Sentinel rules, Nuclei, PayloadsAllTheThings, EVTX
samples, Cyb3r-Monk hunts and the CTID KEV mapping. Their counts then read zero, which
means "not loaded", not "no content", and Gap Analysis counts fewer techniques as
detected. A MISSING DATA banner above the matrix names the failed sources and carries one
"Data health and Retry" link to the Status page, where the per-source Retry buttons live.
Wait for the hourly reset, then Retry there.

## Self-hosting

### Docker

```bash
cp server/.env.example server/.env    # optional: credentials and PROXY_AUTH_TOKEN for the proxy
docker compose up -d --build
```

Opens on http://localhost:8080. The optional credentials proxy is reached through the app
at http://localhost:8080/api/ (and from the host on 127.0.0.1:8787). The stack starts
without `server/.env`; the proxy has nothing to forward until you fill it in. To serve on
a LAN address or hostname instead of localhost, set `APP_ORIGIN` (the page origin, for
example `http://navi.lan:8080`) and `APP_HOST` (the bare host the browser uses, for
example `navi.lan`) in a `.env` file next to `docker-compose.yml`; the proxy refuses other
Host names. If you use an integration in Direct browser mode, add its origin to
`CSP_EXTRA_CONNECT_SRC`, or the self-hosted Content-Security-Policy blocks the request.

### Kubernetes

No workflow in this repository publishes a container image, so build and push one first,
then point the chart at it:

```bash
helm install attack-nav helm/attack-nav/ \
  --set image.repository=YOUR_REGISTRY/attack-nav --set image.tag=YOUR_TAG
```

See docs/HELM.md ("Build and push the image") for the full steps.

### Manual

```bash
npm ci && npx ng build
# Serve dist/mitre-mitigation-navigator/browser/ with any static server
```

## Data, limits and credits

The matrix shows reference data by default: what public sources map, not your posture. The
only environment-specific views are the ones you populate (assessment status, imported
assets, annotations) and the validation runs you log under Detect > Validation, which are
self-recorded. No lens colors the matrix at the evidenced rung.

Enterprise, ICS and Mobile ATT&CK and the CTID F3 Fraud Framework are bundled. The app
also bundles fallbacks it uses when a live source is unavailable (a CISA KEV snapshot, a
D3FEND seed, a CVE-to-technique map, a CWE catalog and SSVC decision tables); the "Bundled
data assets" section of docs/FACTS.md lists them. D3FEND, the CTID mappings, Sigma,
Elastic, Splunk, Atomic Red Team, Galeax CVE2CAPEC, CISA KEV, FIRST EPSS, NVD and others
are fetched from their upstream sources at runtime. THIRD_PARTY_NOTICES.md lists every
source with its license and terms, and the Status workspace shows which sources loaded.

© 2026 The MITRE Corporation. The ATT&CK data in this repository is reproduced and
distributed with the permission of The MITRE Corporation. MITRE ATT&CK® is a registered
trademark of The MITRE Corporation. This project is not affiliated with or endorsed by
MITRE. This product uses the NVD API but is not endorsed or certified by the NVD. Data
fetched at runtime from other sources remains subject to those sources' own licenses and
terms.
