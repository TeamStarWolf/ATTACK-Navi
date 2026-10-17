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

MISP (Malware Information Sharing Platform) integration adds MISP's ATT&CK galaxy cluster data to techniques. It has two modes, set by the mode selector in the integration card: **Direct browser mode**, where the browser calls MISP, and **Secure backend proxy**, where the optional `server/` proxy holds the credentials (see [Optional credentials proxy](../README.md#optional-credentials-proxy)). Direct mode keeps the API key in memory for the session only. The connection test and the public MISP Galaxy data work today; the event and attribute queries in `misp.service.ts` are not wired to the UI, so the MISP Events tab builds event templates locally.

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| Server URL | Yes | The base URL of your MISP instance |
| API Key | Yes | Your MISP automation/API key |
| Org ID | No | Your MISP organization ID (filters events to your org) |

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
7. The key should look like a 40-character hexadecimal string.

### CORS Considerations

MISP servers typically do not serve CORS headers by default. The Navigator makes requests from the browser, so the MISP server must allow cross-origin requests from the Navigator's domain.

**Option A: Configure MISP CORS headers**

Add CORS headers to your MISP Apache or Nginx configuration:

```nginx
# Nginx example for MISP
add_header Access-Control-Allow-Origin "https://your-navigator-domain.com" always;
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
add_header Access-Control-Allow-Headers "Authorization, Content-Type, Accept" always;
```

**Option B: Use a reverse proxy**

Place a reverse proxy between the Navigator and MISP that adds CORS headers:

```nginx
location /misp-proxy/ {
    proxy_pass https://misp.internal.company.com/;
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
    if ($request_method = OPTIONS) {
        return 204;
    }
}
```

### Testing the Connection

1. Open **Settings** (gear icon at the bottom of the nav rail).
2. Click the **Integrations** tab.
3. Enter the MISP URL and API key.
4. Optionally enter the Org ID.
5. Click **Test & Save**.
6. A green "Connected to MISP" status appears on success.
7. On failure, the error message describes the issue (network error, authentication failure, CORS block).

### What Data Is Used

The public MISP Galaxy ATT&CK clusters are the part that is wired in. In Intel > Feeds, a technique's score is the number of ATT&CK groups that use it, plus one when MISP Galaxy has a cluster for it. The event and attribute REST queries (`events/restSearch`, `attributes/restSearch`) are implemented in `misp.service.ts`, but nothing in the UI calls them yet, so live event counts and sightings are not shown. See the README's [Known limitations](../README.md#known-limitations).

---

## 2. OpenCTI Setup

OpenCTI integration enriches techniques with indicators and threat-actor data from your OpenCTI instance. Like MISP, it has two modes set in the integration card: **Direct browser mode**, where the browser calls OpenCTI, and **Secure backend proxy**, where the `server/` proxy holds the token. Direct mode keeps the token in memory for the session only; proxy mode keeps it on the backend.

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| URL | Yes | The base URL of your OpenCTI instance |
| API Token | Yes | Your OpenCTI API bearer token |

### URL Format

```
https://opencti.example.org
```

### Token Generation

1. Log in to your OpenCTI instance.
2. Click your profile icon in the top-right corner.
3. Navigate to **Settings** or **API access**.
4. Copy the API token displayed on the settings page.
5. Tokens are typically UUIDs (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890`).

### Required Permissions

The API token needs read access to **Indicators** and **Threat Actors**; the app looks these up per technique over GraphQL. A read-only analyst role is enough, and no write permission is needed. If you use the proxy, it forwards only read queries on the `about`, `indicators` and `threatActors` fields.

### GraphQL Queries

The Navigator uses OpenCTI's GraphQL API endpoint at `{url}/graphql`. Ensure your firewall and proxy rules allow POST requests to this path.

### Testing the Connection

1. Open **Settings** > **Integrations** tab.
2. Enter the OpenCTI URL and API token.
3. Click **Test & Save**.
4. The Navigator sends a test GraphQL query to verify authentication.
5. A green "Connected to OpenCTI" status appears on success.
6. On failure, the specific error is displayed (authentication, network, CORS).

### Clearing the Connection

Click the **Clear** button to remove the stored OpenCTI configuration. It removes `opencti_config` from localStorage (which holds the URL, mode and proxy URL) and clears the token from memory. The token is never written to localStorage.

---

## 3. NVD API Key

An NVD (National Vulnerability Database) API key increases the rate limit for CVE lookups from 5 requests per 30 seconds (unauthenticated) to 50 requests per 30 seconds.

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

The key is kept in sessionStorage (under `mitre-nav-settings-v1-key`), not localStorage, so it is gone when the tab closes and is never written to disk. The rest of the settings do live in localStorage under `mitre-nav-settings-v1`.

---

## 4. Theme Settings

### Dark and Light Mode

ATTACK-Navi follows the operating system's light or dark setting (`prefers-color-scheme`) until you pick a theme, and keeps following it if the OS setting changes. The theme button in the toolbar (or "Toggle theme" in the command palette) is an explicit choice: it is stored in localStorage under `mitre-nav-theme` (`light` or `dark`) with the marker `mitre-nav-theme-explicit`, and it always wins over the OS. Following the OS writes nothing to storage. A `light` value stored by an older version without the marker was the old automatic default, so the OS decides instead; a stored `dark` is kept as a choice.

### Heatmap Color Themes

Settings > Display > Heatmap Color Theme sets the palette used to color matrix cells. Each theme is a five-step ramp from low to high; click a swatch to apply it.

| Theme | Notes |
|-------|-------|
| Default | The standard ramp |
| Vivid | A brighter version of the default ramp |
| Blue/Orange | Cool to warm, to avoid a red/green ramp |
| Monochrome | Grayscale |
| High Contrast | A colorblind-safe (Viridis) ramp with monotonic luminance |

A separate **Colorblind-safe heatmaps** toggle on the same tab forces the Viridis ramp regardless of the theme chosen. The applied hex values are in `COLOR_THEMES` in `src/app/services/settings.service.ts`; the swatch preview in the picker is maintained separately, so treat the swatch as an approximation of the ramp the matrix uses.

---

## 5. Domain Selection

The Navigator supports four ATT&CK domains:

| Domain | Description | STIX Source |
|--------|-------------|-------------|
| Enterprise | Enterprise IT techniques (default) | `enterprise-attack.json` |
| ICS | Industrial Control Systems | `ics-attack.json` |
| Mobile | Mobile platform techniques | `mobile-attack.json` |
| F3 | CTID Fight Fraud Framework | `f3-attack.json` |

### How Switching Works

1. Use the domain selector in the toolbar.
2. Selecting a new domain clears the current matrix data.
3. The Navigator loads that domain's pinned STIX bundle, shipped with the build (see Data Source below).
4. The bundle is parsed into tactics, techniques, mitigations, groups, software, campaigns, and relationships.
5. All panels and the sidebar reset to reflect the new domain's data.

### Data Source: pinned ATT&CK (decision D2)

ATT&CK is pinned to the release bundled with the build. Each domain loads its bundle from `src/assets/data/` (`enterprise-attack.json`, `ics-attack.json`, `mobile-attack.json`, `f3-attack.json`); the pinned version is the one the bundle's own `x-mitre-collection` object declares, recorded in the source registry and shown on the data-health view (`#/status`). The version on screen never changes by itself during a session.

There are two data modes, chosen in Settings > Data > **ATT&CK Data** and saved with the other settings (`mitre-nav-settings-v1`, field `attackDataMode`):

| Mode | Value | What happens |
|------|-------|--------------|
| Pinned bundle (default) | `bundled` | Only the pinned bundle is loaded. MITRE is contacted only when you click **Check for ATT&CK update**. A fresh profile starts here. |
| Pinned bundle, check MITRE for an update when data loads | `live` | The pinned bundle still loads; after each load the app also checks MITRE and, if a newer release exists, offers it. Nothing is applied without a click. |

**Check for ATT&CK update** (the refresh-arrow button next to the domain selector) fetches the domain's current STIX from MITRE's `attack-stix-data` master branch (F3: CTID's `fight-fraud-framework` main branch):

```
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}-attack/{domain}-attack.json
```

and compares its release number with the pinned one. A status panel (a polite live region, so screen readers announce it) then says one of: no newer release; release N is available, with **Use N for this session** and **Keep** buttons; or the check failed, with **Try again**. A release you choose applies to this session only: it is held in memory, survives a domain round trip, and is gone after a reload or in a new tab, which start on the pinned bundle again. **Back to <pinned>** returns to the pinned release at any time. The live copy's own status (loaded, failed, cached) appears on the data-health view, where its **Load now** / **Retry** runs the same check. Adopting a new ATT&CK release for everyone is a reviewed data change to the bundles, not a runtime switch.

### Caching

A live STIX copy fetched by an update check is cached in IndexedDB (database: `mitre-navigator-cache`, object store: `stix-bundles`) with a 24-hour TTL. Only the automatic check of the `live` mode may answer from that cache; **Check for ATT&CK update** always asks MITRE. The cache is never put on screen by itself. You can clear it in Settings > Data.

---

## 6. Scoring Weights (retired)

The Scoring Weights tab and its setting were removed in plan epic E1.5. They weighted reference sources into a 0-100 score in the technique drawer, coloured red to green, although every input was reference data that says nothing about what is deployed. The drawer now shows a plain count of the reference sources that map the technique (CAR, Atomic, D3FEND, Mitigations, NIST, CRI, CAPEC) under the Known rung. A `scoringWeights` value saved by an older version is dropped when settings load.

**Reset All to Defaults**, which sat on the old tab, is now on the Display tab.

---

## 7. Display Options

Configure matrix rendering in Settings > Display:

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
| Show technique IDs | On | Display ATT&CK IDs (e.g., T1059) on matrix cells |
| Show mitigation count | On | Show the number of mitigations as a badge on cells |
| Show subtechnique count | On | Show subtechnique count on parent technique cells |

The display toggles are persisted in localStorage and take effect immediately. The cell-size choice is persisted too, but matrix rendering does not use it yet (see the note above).

---

## 8. Organization Settings

Configure organization information in Settings > Organization:

| Field | Description |
|-------|-------------|
| Organization Name | Appears in the header of generated HTML reports |
| Organization Logo | Placeholder; the field reads "Coming soon" and logo upload is not implemented |

A live preview of the report header is shown when an organization name is entered.

---

## 9. Data Persistence

All application state is stored client-side using localStorage and IndexedDB. No data is sent to any server (except for configured integrations like MISP and OpenCTI).

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

In Settings > Data:
- **ATT&CK Data** -- The data mode: pinned bundle (default), or pinned bundle with an update check when data loads (see Domain Selection > Data Source)
- **Refresh Data** -- Clears the cached live copy and this session's chosen release for the domain on screen, and reloads the pinned bundle
- **Clear Cache** -- Removes the cached live STIX copies without re-fetching
- **Clear All Snapshots** -- Deletes all timeline snapshots from localStorage
- **Export Implementation CSV** -- Downloads the current implementation status as a CSV file

### Storage Limits

localStorage is typically limited to 5-10 MB depending on the browser. If the quota is exceeded, write operations fail silently. The Navigator uses a try-catch pattern around all localStorage writes to handle this gracefully.

### Clearing All Data

To reset the application to factory state:
1. Open browser DevTools (F12)
2. Go to Application > Storage
3. Click "Clear site data" to remove all localStorage and IndexedDB entries
4. Reload the page

---

## 10. URL State

The Navigator encodes the current filter configuration in the URL hash fragment. This enables sharing specific views by copying the URL.

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

The Navigator is a fully client-side application. The deployment server only needs to:
1. Serve static files (HTML, JS, CSS, JSON assets)
2. Return `index.html` for all non-file routes (SPA fallback)
3. Allow outbound HTTPS connections to GitHub and NVD APIs (from the user's browser, not the server)

No server-side runtime, database, or backend API is required.
