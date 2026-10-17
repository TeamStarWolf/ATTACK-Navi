# Configuration Guide

This document covers the configuration options for ATTACK-Navi: external integrations, display preferences, data management, and deployment.

---

## Table of Contents

1. [MISP Server Setup](#1-misp-server-setup)
2. [OpenCTI Setup](#2-opencti-setup)
3. [NVD API Key](#3-nvd-api-key)
4. [Theme Settings](#4-theme-settings)
5. [Domain Selection](#5-domain-selection)
6. [Scoring Weights (retired)](#6-scoring-weights-retired)
7. [Display Options](#7-display-options)
8. [Organization Settings](#8-organization-settings)
9. [Data Persistence](#9-data-persistence)
10. [URL State](#10-url-state)
11. [Deployment](#11-deployment)

---

## 1. MISP Server Setup

MISP (Malware Information Sharing Platform). The app shows public MISP Galaxy ATT&CK data with no configuration at all: it loads the MISP Galaxy attack-pattern clusters from the public `MISP/misp-galaxy` file on GitHub (`misp.service.ts`), which drive the sidebar's MISP Galaxy Cluster section and the Intelligence heatmap lens. Configuring a MISP server here adds only a connection test. The event and attribute queries in `misp.service.ts` are not wired to the UI, so no live MISP events or sightings are shown and the MISP Events tab builds event templates locally.

The server connection has two modes, set by the mode selector in the integration card: **Direct browser mode**, where the browser calls MISP directly, and **Secure backend proxy**, where the optional `server/` proxy holds the credentials (see [Optional credentials proxy](../README.md#optional-credentials-proxy)). Direct mode keeps the API key in memory for the session only.

### Configuration Fields

In **Direct browser mode** the card shows:

| Field | Required | Description |
|-------|----------|-------------|
| Server URL | Yes | The base URL of your MISP instance |
| API Key | Yes | Your MISP automation/API key |
| Org ID | No | Your MISP organization ID; stored for future event queries, not used by the UI yet |

In **Secure backend proxy** mode the card shows only a proxy URL field (placeholder `https://your-proxy-host.example`); the MISP URL, API key and Org ID live in the proxy's `server/.env`, not in the browser (see [Optional credentials proxy](../README.md#optional-credentials-proxy)).

### URL Format

Enter the full base URL with protocol:

```
https://misp.example.org
https://misp.internal.company.com:8443
```

Do not include trailing slashes or path segments like `/events`.

### API Key Generation

1. Log in to your MISP web interface.
2. Navigate to **Administration > List Users** or click your username.
3. Click **Auth Keys** in the left sidebar.
4. Click **Add authentication key**.
5. Set the allowed IPs if your organization requires IP restrictions.
6. Copy the generated key immediately -- it is shown only once.
7. The key is a 40-character key string.

### CORS in Direct browser mode

MISP servers usually do not send CORS headers, and in Direct browser mode the app calls MISP from the browser, so MISP has to allow cross-origin requests from the app's origin. Two safe ways to do that:

**Option A: turn on CORS in MISP, pinned to the app's origin**

In MISP, set `Security.allow_cors` to `true` and `Security.cors_origins` to the app's exact origin (never `*`) so MISP answers the browser's preflight itself. The direct-mode request carries `Authorization` and `Content-Type: application/json`, so the browser sends a `CORS` preflight; a bare `add_header` block does not satisfy it (MISP answers an unauthenticated `OPTIONS` with a non-2xx status and the app reports "Connection failed"). If you add the headers at a reverse proxy instead, that proxy must also answer `OPTIONS` with `204` and the same headers:

```nginx
# On the MISP host or a proxy in front of it; use the app's exact origin, never "*".
add_header Access-Control-Allow-Origin "https://your-attack-navi-origin.example" always;
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
add_header Access-Control-Allow-Headers "Authorization, Content-Type, Accept" always;
if ($request_method = OPTIONS) { return 204; }
```

**Option B: use the bundled proxy instead**

Switch the integration to **Secure backend proxy** and run the `server/` proxy. It keeps the MISP credentials on the server, pins the allowed origin with `ALLOWED_ORIGINS`, checks the `Host` header against `ALLOWED_HOSTS`, and fails closed on a non-loopback host with no token. This keeps MISP off the browser entirely. Do not place a hand-rolled reverse proxy that sends `Access-Control-Allow-Origin: *` and forwards `Authorization` in front of an internal MISP; that opens it to every origin.

### Testing the Connection

In **Direct browser mode**:

1. Open **Settings > Preferences** (gear icon at the bottom of the nav rail) and the **Integrations** tab.
2. Leave the mode on **Direct browser mode**.
3. Enter the MISP URL and API key, and optionally the Org ID.
4. Click **Test & Save**.
5. On success a green "Connected to MISP" status appears.
6. On failure the status reads "Connection failed" with the message the browser returned. A browser cannot tell a CORS block from a network error, so a blocked cross-origin request and an unreachable host look the same here.

In **Secure backend proxy** mode:

1. In the same card, set the mode to **Secure backend proxy**.
2. In the proxy URL field (placeholder `https://your-proxy-host.example`), enter `http://localhost:8787` for the standalone proxy, or `http://localhost:8080` under Docker Compose (the app origin, no `/api/` suffix; the app appends the path).
3. If the proxy sets `PROXY_AUTH_TOKEN`, paste the same value into the **Proxy access token** field and click its **Save** button; wait for "Proxy token saved for this session". Do this before Test & Save, because Test & Save does not persist that field and a proxy with `PROXY_AUTH_TOKEN` set answers 403 (shown as "Connection failed") without it. The app sends the token as the `X-Proxy-Key` header and keeps it in sessionStorage only.
4. For the standalone proxy on `http://localhost:8787`, set `ALLOWED_ORIGINS` in `server/.env` to the exact origin the app is served from (for the Pages build, `https://teamstarwolf.github.io`); the proxy defaults to `http://localhost:4200` and rejects other origins with 403. Under Docker Compose the app and proxy are same-origin, so this is already handled.
5. Click **Test & Save**. The MISP URL and key come from the proxy's `server/.env`, not this card.

To remove a saved MISP connection, use **Disconnect** on the card.

### What Data Is Used

The public MISP Galaxy ATT&CK clusters (loaded with no configuration, as above) are what is wired in. They appear in two places:

- the sidebar's **MISP Galaxy Cluster** section for a selected technique, with the galaxy tag you can copy;
- the **Intelligence** heatmap lens, whose per-technique score is the number of ATT&CK groups that use the technique, plus one when MISP Galaxy has a cluster for it.

The event and attribute REST queries (`events/restSearch`, `attributes/restSearch`) are implemented in `misp.service.ts`, but nothing in the UI calls them, so live event counts and sightings are not shown. See the README's [Known limitations](../README.md#known-limitations).

---

## 2. OpenCTI Setup

OpenCTI integration adds indicators from your OpenCTI instance to techniques: `getIndicatorsForTechnique` runs per selected technique (`sidebar.component.ts`, `threat-intelligence-panel.component.ts`) and the results show in the sidebar and in Intel > Feeds. It does not add threat-actor data; a `getThreatActorsForTechnique` method exists in `opencti.service.ts` but nothing in the UI calls it.

Like MISP, it has two modes in the integration card: **Direct browser mode**, where the browser calls OpenCTI, and **Secure backend proxy**, where the `server/` proxy holds the token (see [Optional credentials proxy](../README.md#optional-credentials-proxy)). Direct mode keeps the token in memory for the session only; proxy mode keeps it on the backend.

### Configuration Fields

In **Direct browser mode** the card shows:

| Field | Required | Description |
|-------|----------|-------------|
| URL | Yes | The base URL of your OpenCTI instance |
| API Token | Yes | Your OpenCTI API bearer token |

In **Secure backend proxy** mode the card shows only a proxy URL field (placeholder `https://your-proxy-host.example`); the OpenCTI URL and token live in the proxy's `server/.env`, not in the browser.

### URL Format

```
https://opencti.example.org
```

### Token Generation

1. Log in to your OpenCTI instance.
2. Open the profile menu (your avatar, top-right) and choose **Profile**.
3. Copy the API token shown under **API access** on your profile page.
4. Tokens are typically UUIDs (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890`).

### Required Permissions

The app queries only **Indicators**, so a token with read access to indicators is enough; a read-only analyst role suffices and no write permission is needed. (**Threat Actors** read access matters only if the unused threat-actor query is wired up later, or if you run the proxy, whose read allowlist covers that field.)

The proxy's read allowlist is `about`, `indicators` and `threatActors` by default; `OPENCTI_ALLOWED_QUERY_FIELDS` extends it, and mutations are refused unless `OPENCTI_ALLOW_IMPORT=true`, which admits only the app's `ImportStix` operation (`server/src/index.js`).

### GraphQL Queries

In Direct browser mode the app calls OpenCTI's GraphQL endpoint at `{url}/graphql`, so allow POST requests to that path through your firewall and any proxy. This has the same cross-origin requirement as MISP: OpenCTI (or a proxy in front of it) must allow the app's exact origin and answer the `OPTIONS` preflight, or use Secure backend proxy mode to keep OpenCTI off the browser entirely. In Secure backend proxy mode the browser calls the `server/` proxy, which forwards to OpenCTI.

### Testing the Connection

In **Direct browser mode**:

1. Open **Settings > Preferences** and the **Integrations** tab.
2. Leave the mode on **Direct browser mode** and enter the OpenCTI URL and API token.
3. Click **Test & Save**. The app sends a test GraphQL query to verify authentication.
4. On success a green "Connected to OpenCTI" status appears; on failure the error is shown (authentication, network, or a CORS block, which a browser reports the same as a network error).

In **Secure backend proxy** mode set the mode to **Secure backend proxy** and enter the proxy URL in that field (placeholder `https://your-proxy-host.example`): `http://localhost:8787` standalone, or `http://localhost:8080` under Docker Compose, no `/api/` suffix. If the proxy sets `PROXY_AUTH_TOKEN`, paste it into the **Proxy access token** field and click its **Save** button (wait for "Proxy token saved for this session") before Test & Save, since Test & Save does not persist that field and the proxy otherwise answers 403. For the standalone proxy, set `ALLOWED_ORIGINS` in `server/.env` to the app's serving origin (the default is `http://localhost:4200`); under Compose the app and proxy are same-origin. Then click **Test & Save**. The OpenCTI URL and token come from the proxy's `server/.env`.

### Clearing the Connection

Click the **Clear** button to remove the stored OpenCTI configuration. It removes `opencti_config` from localStorage (which holds the URL, mode and proxy URL) and clears the token from memory. The token is never written to localStorage.

---

## 3. NVD API Key

An NVD (National Vulnerability Database) API key raises the NVD rate limit from 5 requests per 30 seconds (unauthenticated) to 50. The app sends the key only on its per-technique CWE lookups, described under [What the key affects](#what-the-key-affects).

### Where to Get a Key

1. Visit [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).
2. Enter your organization email address.
3. Accept the terms of use.
4. The API key is sent to your email immediately.
5. The key is a UUID-format string.

### What the key affects

Without a key, NVD allows 5 requests per 30 seconds; with a key, 50. The key is sent only by the per-technique CWE lookups, which query at most five CWEs in turn, waiting 100 ms between requests with a key and 300 ms without. Keyword and CVE ID searches do not send it. So a key reduces the wait on the CWE lookups for CVE-heavy techniques and changes nothing else.

### Configuration

1. Open **Settings** > **Integrations** tab.
2. Paste the NVD API key into the input field.
3. Click **Save**.
4. A green "API key saved" confirmation appears.

The key is kept in sessionStorage (under `mitre-nav-settings-v1-key`), not localStorage, so it is cleared when the tab's session ends rather than persisting with the rest of the settings. (It is not written to localStorage; note that Chromium may retain sessionStorage across a restart for session restore.) The other settings live in localStorage under `mitre-nav-settings-v1`.

---

## 4. Theme Settings

### Dark and Light Mode

ATTACK-Navi follows the operating system's light or dark setting (`prefers-color-scheme`) until you pick a theme, and keeps following it if the OS setting changes. The theme button in the toolbar (or "Toggle theme" in the command palette) is an explicit choice: it is stored in localStorage under `mitre-nav-theme` (`light` or `dark`) with the marker `mitre-nav-theme-explicit`, and it always wins over the OS. Following the OS writes nothing to storage. A `light` value stored by an older version without the marker was the old automatic default, so the OS decides instead; a stored `dark` is kept as a choice.

### Heatmap Color Themes

**Settings > Preferences > Display > Heatmap Color Theme** sets the palette for matrix cells. There are five: Default, Vivid, Blue/Orange, Monochrome and High Contrast, each a five-step ramp from low to high.

This palette colors only the **Mitigations mapped** (coverage) lens: `getCoverageColors` is read just by that lens's cell and legend rendering (`matrix.component.ts` `case 'coverage'`, `technique-cell.component.ts`, `legend.component.ts`). Every other lens has its own fixed ramp in `heatmap-modes.ts`, and the default lens is the one labelled **Frequency** (its first-visit banner describes it as adversary prevalence), so changing the theme shows nothing until you switch to the Mitigations mapped lens.

A separate **Colorblind-safe heatmaps** toggle on the same tab replaces every lens's ramp with Viridis (sequential) and Okabe-Ito (status), regardless of the theme chosen.

One caveat: the swatch you click and the ramp the matrix applies are defined in two places and currently disagree. "High Contrast" shows a red-to-green swatch (`#cc0000` to `#003300`, `settings-panel.component.ts`) but applies the Viridis ramp (`#440154` to `#fde725`, `settings.service.ts` and `safe-palette.ts`), the opposite palette; "Blue/Orange" shows `#1d4ed8` to `#92400e` but applies `#1d4ed8, #2563eb, #0ea5e9, #f59e0b, #d97706`; and Default's second step is `#e65100` in the swatch versus `#b45309` applied. A follow-up code change will render the swatches from the same definition the matrix uses, and this note will go when it lands.

---

## 5. Domain Selection

ATTACK-Navi supports four ATT&CK domains:

| Domain | Description | STIX Source |
|--------|-------------|-------------|
| Enterprise | Enterprise IT techniques (default) | `enterprise-attack.json` |
| ICS | Industrial Control Systems | `ics-attack.json` |
| Mobile | Mobile platform techniques | `mobile-attack.json` |
| F3 | CTID Fight Fraud Framework | `f3-attack.json` |

### How Switching Works

1. Use the domain selector in the toolbar.
2. Selecting a new domain clears the current matrix data.
3. The app loads that domain's pinned STIX bundle, shipped with the build (see Data Source below).
4. The bundle is parsed into tactics, techniques, mitigations, groups, software, campaigns, and relationships.
5. All panels and the sidebar reset to reflect the new domain's data.

### Data Source: pinned ATT&CK

ATT&CK is pinned to the release bundled with the build. Each domain loads its bundle from `src/assets/data/` (`enterprise-attack.json`, `ics-attack.json`, `mobile-attack.json`, `f3-attack.json`); the pinned version is the one the bundle's own `x-mitre-collection` object declares, recorded in the source registry and shown on the data-health view (`#/status`). The version on screen never changes by itself during a session.

There are two data modes, chosen in Settings > Preferences > Data > **ATT&CK Data** and saved with the other settings (`mitre-nav-settings-v1`, field `attackDataMode`):

| Mode | Value | What happens |
|------|-------|--------------|
| Pinned bundle (default) | `bundled` | Only the pinned bundle is loaded. MITRE is contacted only when you click **Check for ATT&CK update**. A fresh profile starts here. |
| Pinned bundle, check MITRE for an update when data loads | `live` | The pinned bundle still loads; after each load the app also checks MITRE and, if a newer release exists, offers it. Nothing is applied without a click. |

**Check for ATT&CK update** (the refresh-arrow button next to the domain selector) fetches the domain's current STIX from MITRE's `attack-stix-data` master branch (F3: CTID's `fight-fraud-framework` main branch):

```
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}-attack/{domain}-attack.json
```

and compares its release number with the pinned one. A status panel (a polite live region, so screen readers announce it) then says one of: no newer release; release N is available, with **Use N for this session** and **Keep** buttons; or the check failed, with **Try again**. A release you choose applies to this session only: it is held in memory, survives a domain round trip, and is gone after a reload or in a new tab, which start on the pinned bundle again. `Back to <pinned>` returns to the pinned release at any time. The live copy's own status (loaded, failed, cached) appears on the data-health view, where its **Load now** / **Retry** runs the same check. Adopting a new ATT&CK release for everyone is a reviewed data change to the bundles, not a runtime switch.

### Caching

A live STIX copy fetched by an update check is cached in IndexedDB (database: `mitre-navigator-cache`, object store: `stix-bundles`) with a 24-hour TTL. Only the automatic check of the `live` mode may answer from that cache; **Check for ATT&CK update** always asks MITRE. The cache is never put on screen by itself. You can clear it in Settings > Preferences > Data.

---

## 6. Scoring Weights (retired)

The Scoring Weights tab and its setting were removed. They weighted reference sources into a 0-100 score in the technique drawer, coloured red to green, although every input was reference data that says nothing about what is deployed. The drawer now shows a plain count of the reference sources that map the technique (CAR, Atomic, D3FEND, Mitigations, NIST, CRI, CAPEC). A `scoringWeights` value saved by an older version is dropped when settings load.

**Reset All to Defaults**, which sat on the old tab, is now on the Display tab.

---

## 7. Display Options

Configure matrix rendering in Settings > Preferences > Display:

### Matrix Cell Size

| Size | Description |
|------|-------------|
| Compact | Smaller cells, more techniques visible at once |
| Normal | Default size |
| Large | Bigger cells, easier to read labels |

The cell-size choice is saved with your preferences, but matrix rendering does not use it yet; the Settings panel notes this next to the control.

### Matrix Display Toggles

| Option | Default | Description |
|--------|---------|-------------|
| Colorblind-safe heatmaps | Off | Replace every lens's ramp with the Viridis and Okabe-Ito palettes (see [Theme Settings](#4-theme-settings)) |
| Show technique IDs | On | Display ATT&CK IDs (e.g., T1059) on matrix cells |
| Expand sections by default | On | Collapsible groups (Detect, Data Sources, Assessment) start expanded |
| Show mitigation count badge | On | Number of mitigations as a badge on each cell |
| Show subtechnique count badge | On | Subtechnique count on parent technique cells |

### Cell Display

A separate group toggles the badges and markers drawn on each cell, all on by default:

| Toggle | Shows |
|--------|-------|
| Show exposure (groups) badge | Count of threat-actor groups using the technique |
| Show software badge | Count of software or malware using it |
| Show campaign badge | Count of campaigns using it |
| Show heatmap metric badge | The mode-specific count, shown only in its own heatmap (D3FEND, Atomic, CRI) |
| Show analyst note marker | A marker when the technique has analyst notes |
| Show annotation dot | A colored dot when the technique is annotated |
| Show watchlist marker | A marker when the technique is on the watchlist |

These preferences are persisted in localStorage and take effect immediately. The cell-size choice above is persisted too, but matrix rendering does not use it yet.

---

## 8. Organization Settings

Configure organization information in Settings > Preferences > Organization:

| Field | Description |
|-------|-------------|
| Organization Name | Appears in the header of generated HTML reports |
| Organization Logo | Placeholder; the field reads "Coming soon" and logo upload is not implemented |

A live preview of the report header is shown when an organization name is entered.

---

## 9. Data Persistence

Your application state (assessment answers, imported assets, annotations, tags, saved views, and so on) is stored client-side in localStorage and IndexedDB and is not sent anywhere. The app does make outbound requests to fetch public data from the hosts listed under Deployment, and to your configured MISP and OpenCTI endpoints. Some of those carry terms you type: a CVE keyword or CVE ID search sends your query to the NVD API, and a per-technique CWE lookup sends CWE IDs. Your saved application state is never part of those requests.

### localStorage Keys

| Key | Service | Description |
|-----|---------|-------------|
| `mitre-nav-settings-v1` | SettingsService | Display options, org name, ATT&CK data mode (`attackDataMode`, default `bundled`); the NVD API key and proxy token live in sessionStorage |
| `mitre-nav-impl-v1` | ImplementationService | Mitigation implementation status (Map of ID to status) |
| `mitre-nav-docs-mit-v1` | DocumentationService | Mitigation documentation notes |
| `mitre-nav-docs-tech-v1` | DocumentationService | Technique documentation notes |
| `mitre-nav-annotations-v1` | AnnotationService | Per-technique annotations and notes |
| `mitre-nav-tags-v1` | TaggingService | Custom tags applied to techniques |
| `mitre-nav-custom-mitigations-v1` | CustomMitigationService | Organization-specific custom mitigations |
| `mitre-nav-views-v1` | SavedViewsService | Saved filter/view configurations |
| `mitre-nav-watchlist-v1` | WatchlistService | Watched technique IDs with notes |
| `mitre-nav-controls-v1` | ControlsService | Custom control entries |
| `mitre-nav-layers-v1` | LayersService | Saved Navigator layer snapshots |
| `mitre-nav-timeline-v1` | TimelineService | Coverage timeline snapshots |
| `mitre-nav-theme` | ThemeService | Light/dark theme the user picked (absent while the theme follows the OS) |
| `mitre-nav-theme-explicit` | ThemeService | `1` when `mitre-nav-theme` holds an explicit choice |
| `misp_config` | MispService | MISP server URL, org ID, mode and proxy URL; the API key is kept in memory only |
| `opencti_config` | OpenCtiService | OpenCTI URL, mode and proxy URL; the API token is kept in memory only |

### IndexedDB

| Database | Object Store | Description |
|----------|-------------|-------------|
| `mitre-navigator-cache` | `stix-bundles` | Live ATT&CK STIX copies fetched by an update check (24h TTL); never shown without a click |

### Data Management

In Settings > Preferences > Data:
- **ATT&CK Data** -- The data mode: pinned bundle (default), or pinned bundle with an update check when data loads (see Domain Selection > Data Source)
- **Refresh Data** -- Clears the cached live copy and this session's chosen release for the domain on screen, and reloads the pinned bundle
- **Clear Cache** -- Removes the cached live STIX copies without re-fetching
- **Clear All Snapshots** -- Deletes all timeline snapshots from localStorage
- **Export Implementation CSV** -- Downloads the current implementation status as a CSV file

### Storage Limits

localStorage is typically limited to 5-10 MB depending on the browser. If the quota is exceeded, write operations fail silently. The app uses a try-catch pattern around all localStorage writes to handle this gracefully.

### Clearing All Data

To reset the application to factory state:
1. Open browser DevTools (F12)
2. Go to Application > Storage
3. Click "Clear site data" to remove all localStorage and IndexedDB entries
4. Reload the page

---

## 10. URL State

The app encodes the current filter configuration in the URL hash fragment. This enables sharing specific views by copying the URL.

### How It Works

1. When any filter changes (search query, heatmap mode, threat group selection, and so on), the app re-serializes the state into the URL after a 300 ms debounce.
2. The state lives in router query params inside the hash, for example `#/matrix?heat=sigma&grp=G0007`. Older flat-hash links such as `#heat=sigma&grp=G0007` still work; the app rewrites them on load.
3. Only non-default values are written, to keep URLs short. The default heatmap mode (`frequency`) and the default search scope (`name`) are omitted.
4. On load, the app reads the query params once and restores the state.

The Share button copies the current URL. It does not include the selected technique, but an incoming link with a `tech=` parameter, such as `#/matrix?tech=T1059`, selects that technique.

### Supported Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `mit` | CSV | Mitigation ATT&CK IDs | `mit=M1036,M1038` |
| `tq` | String | Technique search query | `tq=credential` |
| `pf` | String | Platform filter (single) | `pf=Windows` |
| `plat` | CSV | Multi-platform filter | `plat=Windows,Linux` |
| `dim` | Flag | Dim unmapped techniques | `dim=1` |
| `sfm` | Flag | Search filter mode | `sfm=1` |
| `ds` | String | Data source filter | `ds=Process` |
| `heat` | Enum | Heatmap mode | `heat=sigma` |
| `impl` | String | Implementation status filter | `impl=in-progress` |
| `scope` | Enum | Search scope (name/full) | `scope=full` |
| `tsearch` | String | Technique search | `tsearch=powershell` |
| `grp` | CSV | Threat group ATT&CK IDs | `grp=G0007,G0016` |
| `sw` | CSV | Software ATT&CK IDs | `sw=S0154` |
| `camp` | CSV | Campaign ATT&CK IDs | `camp=C0001` |

### Example Shareable URLs

Show the Sigma heatmap with the APT28 group filter:
```
https://teamstarwolf.github.io/ATTACK-Navi/#/matrix?heat=sigma&grp=G0007
```

Show the CVE heatmap with a Windows platform filter and a credential search:
```
https://teamstarwolf.github.io/ATTACK-Navi/#/matrix?heat=cve&pf=Windows&tq=credential
```

Show two mitigations with unmapped techniques dimmed:
```
https://teamstarwolf.github.io/ATTACK-Navi/#/matrix?mit=M1036,M1038&dim=1
```

### Limitations

- The URL hash stores filter state only, not panel open/close state
- Implementation status, annotations, and other per-technique data are not encoded in the URL
- Very long filter combinations may exceed URL length limits in some browsers

---

## 11. Deployment

### GitHub Pages (Included Workflow)

The repository includes a GitHub Actions workflow at `.github/workflows/deploy.yml` that deploys to GitHub Pages on every push to `main`, on a daily schedule, and on manual dispatch.

**Workflow summary:**
1. Checks out the repository
2. Sets up Node.js 24 with npm cache
3. Runs `npm ci` to install dependencies
4. Runs the unit suite (`npx ng test --no-watch --browsers=ChromeHeadless`); a failing suite blocks the deploy
5. Builds with `npx ng build --base-href /ATTACK-Navi/`
6. Uploads the `dist/mitre-mitigation-navigator/browser` directory as a Pages artifact
7. Deploys to the `github-pages` environment

**To enable in a fork:**
1. Go to your repository's Settings > Pages.
2. Under "Source", select **GitHub Actions**.
3. Set `--base-href` in `deploy.yml` to `/<your-repository-name>/`, matching the repository name exactly. GitHub Pages paths are case-sensitive: a repository named `ATTACK-Navi` is served at `/ATTACK-Navi/`, and a build made for a different path 404s on every asset.
4. Push to `main` to trigger the first deployment.
5. The site will be available at `https://<owner>.github.io/<your-repository-name>/`.

### Custom Domain

To use a custom domain with GitHub Pages:
1. In your repository Settings > Pages, enter the custom domain.
2. Add a CNAME record in your DNS pointing to `<username>.github.io`.
3. Update the `--base-href` in the deploy workflow to `/` (or your subdirectory).
4. Add a `CNAME` file to the `src` directory containing your domain name.
5. Update `angular.json` to include the CNAME file in the build assets.

### Self-Hosted with Nginx

For self-hosted deployments, build the project and serve the output directory with any static file server.

**Build:**
```bash
npm ci
npx ng build --base-href /
```

The build output is in `dist/mitre-mitigation-navigator/browser/`.

**Nginx configuration:** use the two files the Docker image ships rather than a copy that drifts:

- [`nginx.conf`](../nginx.conf) -- the site config (SPA fallback, same-origin `/api/` route to the credentials proxy, asset caching, gzip).
- [`nginx-security-headers.conf`](../nginx-security-headers.conf) -- the security headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) as one snippet.

Two things in them are deliberate and worth keeping when you adapt them:

1. The security headers are *included* in the `server` block **and again in every `location` that declares an `add_header` of its own** (the asset-cache location, the `/api/` route). nginx inherits `add_header` only into blocks that add nothing themselves, so a lone `add_header Cache-Control` inside the asset location silently strips the CSP and `nosniff` from every JS/CSS/font response.
2. `script-src` is `'self'` -- no `'unsafe-inline'`. The app needs none, and the Docker workflow fails if it is added.

The files are envsubst templates: replace `${PROXY_UPSTREAM}`, `${NGINX_RESOLVER}` and `${CSP_EXTRA_CONNECT_SRC}` by hand (or drop the `/api/` location) when you use them outside the image. Put the snippet where the `include` directive points, e.g. `/etc/nginx/conf.d/security-headers.inc`.

**CSP `connect-src` origins the app fetches at runtime** (the full list; `scripts/check-csp-connect-src.mjs` verifies it against `src/app/services` and the Docker smoke test verifies the served header):

| Origin | Used for |
|--------|----------|
| `'self'` | bundled snapshots and the `/api/` proxy route |
| `https://raw.githubusercontent.com` | ATT&CK STIX bundles, MITRE Engage, CAPEC, Sigma, Atomic Red Team, KEV mirror and other GitHub-hosted data |
| `https://api.github.com` | GitHub API listings (Elastic, Splunk, changelog) |
| `https://gitlab.com` | Exploit-DB index |
| `https://api.first.org` | EPSS scores |
| `https://services.nvd.nist.gov` | NVD CVE lookups |
| `https://www.cisa.gov` | CISA KEV catalog |
| `https://d3fend.mitre.org` | D3FEND technique mappings |
| `https://cveawg.mitre.org` | CVE Services record (CISA SSVC decisions) |
| your MISP, OpenCTI and TAXII origins | direct mode only; in proxy mode the browser talks to `/api/` on the app origin |

Note that the GitHub Pages deployment serves no CSP at all (Pages sets no headers), so the policy above applies to the nginx/Docker/Helm deployments only.

### Docker

The repository's [`Dockerfile`](../Dockerfile) is the containerized deployment: a `node:24-alpine` build stage runs `npm ci` and `ng build --configuration production --base-href /`, and an `nginxinc/nginx-unprivileged:alpine` stage (nginx on port 8080 as the unprivileged user 101) serves `dist/mitre-mitigation-navigator/browser` with the two nginx files above installed as templates under `/etc/nginx/templates/`. The image accepts three environment variables, all with defaults:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PROXY_UPSTREAM` | `http://proxy:8787` | where `/api/` is forwarded (the compose `proxy` service) |
| `NGINX_RESOLVER` | `127.0.0.11` | DNS used to resolve it per request (Docker's embedded DNS; set your cluster DNS on Kubernetes) |
| `CSP_EXTRA_CONNECT_SRC` | empty | extra `connect-src` origins, space separated (direct-mode OpenCTI/MISP/TAXII, or a proxy on another origin) |

[`docker-compose.yml`](../docker-compose.yml) runs the app on port 8080 together with the credentials proxy (`server/`), sets the proxy's `ALLOWED_ORIGINS` to the page origin (`APP_ORIGIN`) and `ALLOWED_HOSTS` to `APP_HOST` (empty by default; nginx forwards the browser's `Host`, and loopback names are always allowed), and reads credentials and `PROXY_AUTH_TOKEN` from the optional `server/.env`. See the README's Docker section for the quick start.

### Build Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| `--base-href` | Deployment path | `/<repository-name>/` for GitHub Pages (`/ATTACK-Navi/` here, case-sensitive), `/` for root |
| Build output | `dist/mitre-mitigation-navigator/browser` | Static files ready to serve |
| Node.js | `^22.22.3 \|\| ^24.15.0 \|\| >=26.0.0` | Required by Angular 22 (`engines` in `package.json`); CI and the Dockerfile use Node 24. Node 20 is end-of-life |
| npm | 10+ | Comes with Node.js 22 and 24 |

### Environment Requirements

ATTACK-Navi is a fully client-side application. The deployment server only needs to:
1. Serve static files (HTML, JS, CSS, JSON assets)
2. Return `index.html` for all non-file routes (SPA fallback)
3. Let the user's browser (not the server) reach the runtime data hosts in the CSP `connect-src` table above: `raw.githubusercontent.com`, `api.github.com`, `gitlab.com`, `api.first.org`, `services.nvd.nist.gov`, `www.cisa.gov`, `d3fend.mitre.org` and `cveawg.mitre.org`, plus any MISP, OpenCTI or TAXII origin you configure

No server-side runtime, database, or backend API is required.
