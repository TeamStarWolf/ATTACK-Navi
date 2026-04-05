# Configuration Guide

This document covers all configuration options for the MITRE ATT&CK Navi, including external integrations, display preferences, data management, and deployment.

---

## Table of Contents

1. [MISP Server Setup](#1-misp-server-setup)
2. [OpenCTI Setup](#2-opencti-setup)
3. [NVD API Key](#3-nvd-api-key)
4. [Theme Settings](#4-theme-settings)
5. [Domain Selection](#5-domain-selection)
6. [Scoring Weights](#6-scoring-weights)
7. [Display Options](#7-display-options)
8. [Organization Settings](#8-organization-settings)
9. [Data Persistence](#9-data-persistence)
10. [URL State](#10-url-state)
11. [Deployment](#11-deployment)

---

## 1. MISP Server Setup

MISP (Malware Information Sharing Platform) integration enables live threat event queries and ATT&CK galaxy cluster enrichment for techniques.

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

Once connected, the Navigator:
- Fetches MISP galaxy clusters mapped to ATT&CK techniques
- Displays MISP tags in the technique sidebar
- Shows event counts and sighting data
- Populates the Intelligence panel with MISP-sourced indicators

---

## 2. OpenCTI Setup

OpenCTI integration enriches techniques with structured threat intelligence, including indicators, confidence levels, and threat actor attribution.

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| URL | Yes | The base URL of your OpenCTI instance |
| API Token | Yes | Your OpenCTI API bearer token |

### URL Format

```
https://opencti.example.org
https://demo.opencti.io
```

### Token Generation

1. Log in to your OpenCTI instance.
2. Click your profile icon in the top-right corner.
3. Navigate to **Settings** or **API access**.
4. Copy the API token displayed on the settings page.
5. Tokens are typically UUIDs (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890`).

### Required Permissions

The API token must have at least read access to:
- **Indicators** -- For technique enrichment with IOCs
- **Threat Actors** -- For actor attribution data
- **Attack Patterns** -- For ATT&CK technique mappings
- **Reports** -- For intelligence context

A read-only analyst role is sufficient. No write permissions are needed.

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

Click the **Clear** button to remove the stored OpenCTI configuration. This deletes the URL and token from localStorage.

---

## 3. NVD API Key

An NVD (National Vulnerability Database) API key increases the rate limit for CVE lookups from 5 requests per 30 seconds (unauthenticated) to 50 requests per 30 seconds.

### Where to Get a Key

1. Visit [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).
2. Enter your organization email address.
3. Accept the terms of use.
4. The API key is sent to your email immediately.
5. The key is a UUID-format string.

### How It Improves Performance

Without an API key, the Navigator throttles NVD requests to 5 per 30 seconds. When browsing multiple techniques with CVE data, this can cause noticeable delays. With the API key, the 10x rate increase makes CVE lookups significantly faster.

### Configuration

1. Open **Settings** > **Integrations** tab.
2. Paste the NVD API key into the input field.
3. Click **Save**.
4. A green "API key saved" confirmation appears.

The key is stored in localStorage under the `mitre-nav-settings-v1` key as part of the application settings object.

---

## 4. Theme Settings

### Dark and Light Mode

The Navigator defaults to dark mode. Toggle light mode using the theme button in the application toolbar. The preference is stored in localStorage under the key `mitre-nav-theme` with a value of `light` or `dark`.

### Heatmap Color Themes

The heatmap color palette used for matrix cells is configurable in Settings > Display:

| Theme | Description | Colors |
|-------|-------------|--------|
| Default | Red to green gradient | `#d32f2f` to `#1b5e20` |
| Vivid | Bright red to green | `#dc2626` to `#15803d` |
| Blue/Orange | Cool to warm | `#1d4ed8` to `#92400e` |
| Monochrome | Grayscale | `#111827` to `#e5e7eb` |
| High Contrast | Accessible palette | `#cc0000` to `#003300` |

Select a theme by clicking its color swatch in Settings > Display > Heatmap Color Theme. The High Contrast theme is designed for accessibility and meets WCAG color contrast requirements.

---

## 5. Domain Selection

The Navigator supports three ATT&CK domains:

| Domain | Description | STIX Source |
|--------|-------------|-------------|
| Enterprise | Enterprise IT techniques (default) | `enterprise-attack.json` |
| ICS | Industrial Control Systems | `ics-attack.json` |
| Mobile | Mobile platform techniques | `mobile-attack.json` |

### How Switching Works

1. Use the domain selector in the toolbar.
2. Selecting a new domain clears the current matrix data.
3. The Navigator fetches the corresponding STIX bundle from GitHub (or from IndexedDB cache if available).
4. The bundle is parsed into tactics, techniques, mitigations, groups, software, campaigns, and relationships.
5. All panels and the sidebar reset to reflect the new domain's data.

### Data Source

Each domain's STIX bundle is fetched live from the MITRE `attack-stix-data` repository on GitHub:

```
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}-attack/{domain}-attack.json
```

For Enterprise, a bundled fallback is included in the build at `assets/enterprise-attack.json`.

### Caching

STIX bundles are cached in IndexedDB (database: `mitre-navigator-cache`, object store: `stix-bundles`) with a 24-hour TTL. After 24 hours, the Navigator fetches a fresh bundle. You can manually clear or refresh the cache in Settings > Data.

---

## 6. Scoring Weights

Coverage scores displayed in the technique sidebar and used by the coverage heatmap are computed from five weighted dimensions:

| Dimension | Default Weight | Max | Description |
|-----------|---------------|-----|-------------|
| Mitigations | 40 | 60 | ATT&CK mitigations mapped to the technique |
| CAR Analytics | 20 | 40 | MITRE Cyber Analytics Repository detections |
| Atomic Red Team | 15 | 30 | Atomic Red Team test coverage |
| D3FEND | 15 | 30 | MITRE D3FEND countermeasures |
| NIST Controls | 10 | 20 | NIST 800-53 Rev5 control mappings |

### Adjusting Weights

1. Open **Settings** > **Scoring Weights** tab.
2. Use the sliders to adjust each dimension's weight.
3. The total should sum to 100. A warning appears if it does not.
4. Click **Auto-normalize to 100** to proportionally adjust all weights to sum to 100.
5. Changes are auto-saved and immediately affect all coverage scores.

### Sample Preview

The settings panel includes a live preview showing how the current weights would score a sample technique (3 mitigations, has CAR analytics, has Atomic tests, no D3FEND, has NIST controls).

### Resetting

Click **Reset All to Defaults** to restore the default weight distribution.

---

## 7. Display Options

Configure matrix rendering in Settings > Display:

### Matrix Cell Size

| Size | Description |
|------|-------------|
| Compact | Smaller cells, more techniques visible at once |
| Normal | Default size (recommended) |
| Large | Bigger cells, easier to read labels |

### Matrix Display Toggles

| Option | Default | Description |
|--------|---------|-------------|
| Show technique IDs | On | Display ATT&CK IDs (e.g., T1059) on matrix cells |
| Show mitigation count | On | Show the number of mitigations as a badge on cells |
| Show subtechnique count | On | Show subtechnique count on parent technique cells |

All display preferences are persisted in localStorage and take effect immediately.

---

## 8. Organization Settings

Configure organization information in Settings > Organization:

| Field | Description |
|-------|-------------|
| Organization Name | Appears in the header of generated HTML reports |
| Organization Logo | Coming soon (placeholder in current version) |

A live preview of the report header is shown when an organization name is entered.

---

## 9. Data Persistence

All application state is stored client-side using localStorage and IndexedDB. No data is sent to any server (except for configured integrations like MISP and OpenCTI).

### localStorage Keys

| Key | Service | Description |
|-----|---------|-------------|
| `mitre-nav-settings-v1` | SettingsService | Scoring weights, display options, org name, NVD API key |
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
| `mitre-nav-theme` | AppComponent | Light/dark mode preference |
| `misp_config` | MispService | MISP server URL, API key, org ID |
| `opencti_config` | OpenCtiService | OpenCTI URL and API token |

### IndexedDB

| Database | Object Store | Description |
|----------|-------------|-------------|
| `mitre-navigator-cache` | `stix-bundles` | Cached ATT&CK STIX bundles (24h TTL) |

### Data Management

In Settings > Data:
- **Refresh Data** -- Clears the IndexedDB cache and fetches a fresh STIX bundle from GitHub
- **Clear Cache** -- Removes the cached STIX bundle without re-fetching
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

1. When any filter changes (search query, heatmap mode, threat group selection, etc.), the Navigator updates the URL hash after a 300ms debounce.
2. The hash uses URL search parameter format: `#key1=value1&key2=value2`
3. Only non-default values are included to keep URLs compact.
4. On page load, the Navigator reads the hash and restores the encoded state.

### Supported Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `mit` | CSV | Mitigation ATT&CK IDs | `mit=M1036,M1038` |
| `tq` | String | Technique search query | `tq=credential` |
| `pf` | String | Platform filter (single) | `pf=Windows` |
| `plat` | CSV | Multi-platform filter | `plat=Windows,Linux` |
| `dim` | Flag | Dim uncovered techniques | `dim=1` |
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

Show Sigma heatmap with APT28 filter:
```
https://example.com/ATTACK-Navi/#heat=sigma&grp=G0007
```

Show CVE heatmap with Windows platform filter and credential search:
```
https://example.com/ATTACK-Navi/#heat=cve&pf=Windows&tq=credential
```

Show coverage heatmap with two mitigations highlighted:
```
https://example.com/ATTACK-Navi/#mit=M1036,M1038&dim=1
```

### Limitations

- The URL hash stores filter state only, not panel open/close state
- Implementation status, annotations, and other per-technique data are not encoded in the URL
- Very long filter combinations may exceed URL length limits in some browsers

---

## 11. Deployment

### GitHub Pages (Included Workflow)

The repository includes a GitHub Actions workflow at `.github/workflows/deploy.yml` that automatically deploys to GitHub Pages on every push to `main`.

**Workflow summary:**
1. Checks out the repository
2. Sets up Node.js 20 with npm cache
3. Runs `npm ci` to install dependencies
4. Builds with `npx ng build --base-href /ATTACK-Navi/`
5. Uploads the `dist/mitre-mitigation-navigator/browser` directory as a Pages artifact
6. Deploys to the `github-pages` environment

**To enable:**
1. Go to your repository's Settings > Pages.
2. Under "Source", select **GitHub Actions**.
3. Push to `main` to trigger the first deployment.
4. The site will be available at `https://<username>.github.io/ATTACK-Navi/`.

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

**Nginx configuration example:**

```nginx
server {
    listen 80;
    server_name attack-nav.example.com;

    root /var/www/attack-nav;
    index index.html;

    # SPA fallback: serve index.html for all routes
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets aggressively
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://raw.githubusercontent.com https://services.nvd.nist.gov https://api.first.org;" always;

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;
}
```

**Key CSP connect-src domains:**
- `https://raw.githubusercontent.com` -- ATT&CK STIX bundle fetches
- `https://services.nvd.nist.gov` -- NVD CVE lookups
- `https://api.first.org` -- EPSS score lookups
- Your MISP and OpenCTI instance URLs (if configured)

### Docker

A basic Dockerfile for a containerized deployment:

```dockerfile
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npx ng build --base-href /

FROM nginx:alpine
COPY --from=build /app/dist/mitre-mitigation-navigator/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

### Build Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| `--base-href` | Deployment path | `/ATTACK-Navi/` for GitHub Pages, `/` for root |
| Build output | `dist/mitre-mitigation-navigator/browser` | Static files ready to serve |
| Node.js | 20+ | Required by Angular 19 |
| npm | 9+ | Comes with Node.js 20 |

### Environment Requirements

The Navigator is a fully client-side application. The deployment server only needs to:
1. Serve static files (HTML, JS, CSS, JSON assets)
2. Return `index.html` for all non-file routes (SPA fallback)
3. Allow outbound HTTPS connections to GitHub and NVD APIs (from the user's browser, not the server)

No server-side runtime, database, or backend API is required.
