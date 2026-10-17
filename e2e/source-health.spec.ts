// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// E1.3 acceptance: "forcing each source offline in e2e shows 'failed'".
//
// For every live source in the inventory, the test blocks that source's own URL
// (Playwright route-blocking, on top of the hermetic workspace) and counts the
// blocked requests, so the failure is the one this test caused. It then checks:
//   1. the data-health view (#/status) shows that source as 'failed'. A source that
//      loads only when a view asks for it (NVD, EPSS per CVE, Atomic per technique,
//      the tree listings) is started with its "Load now" button;
//   2. the shared view banner on one route that reads the source names it
//      ("<name> (failed)"). The route comes from src/app/services/route-sources.ts:
//      the first route other than the matrix that lists the source, else the matrix.
// The navigation to that route stays inside the app (hash change), because a reload
// would start a new session with a fresh source registry.
import { Page, Route } from '@playwright/test';
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';
import { SOURCE_DEFINITIONS } from '../src/app/services/source-inventory';
import { ROUTE_SOURCES, sourcesForRoute } from '../src/app/services/route-sources';

type Domain = 'enterprise' | 'ics' | 'mobile' | 'f3';

interface OfflineCase {
  /** Which requests belong to the source. */
  match: (url: string) => boolean;
  /** Switch the matrix to this domain first (live ATT&CK bundles load per domain). */
  domain?: Domain;
  /** Serve the CTID ATT&CK-to-CVE CSV: these services wait on it before making their own request. */
  needsCtid?: boolean;
}

const has = (...parts: string[]) => (url: string) => parts.every(p => url.includes(p));

/** One case per live source: the request that source makes. */
const OFFLINE: Record<string, OfflineCase> = {
  'attack-live-enterprise': { match: has('attack-stix-data/master/enterprise-attack/') },
  'attack-live-ics': { match: has('attack-stix-data/master/ics-attack/'), domain: 'ics' },
  'attack-live-mobile': { match: has('attack-stix-data/master/mobile-attack/'), domain: 'mobile' },
  'attack-live-f3': { match: has('fight-fraud-framework/main/public/f3-stix.json'), domain: 'f3' },
  'attack-releases': { match: has('api.github.com/repos/mitre-attack/attack-stix-data/releases') },
  'cve2capec-runtime': { match: has('Galeax/CVE2CAPEC') },
  'ctid-attack-to-cve': { match: has('attack_to_cve/') },
  'cisa-kev': { match: has('known_exploited_vulnerabilities.json') },
  'epss': { match: has('api.first.org/data/v1/epss') },
  'nvd': { match: has('services.nvd.nist.gov/rest/json/cves/2.0') },
  'cve-services': { match: has('cveawg.mitre.org/api/cve') },
  'ctid-nist-800-53': { match: has('mappings-explorer', '/mappings/nist_800_53/') },
  'ctid-cri-profile': { match: has('mappings-explorer', '/mappings/cri_profile/') },
  'ctid-csa-ccm': { match: has('mappings-explorer', '/mappings/csa_ccm/') },
  'ctid-veris': { match: has('mappings-explorer', '/mappings/veris/') },
  'ctid-aws': { match: has('mappings-explorer', '/mappings/aws/') },
  'ctid-azure': { match: has('mappings-explorer', '/mappings/azure/') },
  'ctid-gcp': { match: has('mappings-explorer', '/mappings/gcp/') },
  'ctid-m365': { match: has('mappings-explorer', '/mappings/m365/') },
  'ctid-kev': { match: url => url.includes('mappings-explorer') && url.includes('/kev') },
  'sigmahq-coverage': { match: has('/SigmaHQ/sigma/') },
  'car-layer': { match: has('mitre-attack/car/') },
  'atomic-layer': { match: has('art-navigator-layer.json') },
  'atomic-tests': { match: url => /atomic-red-team\/master\/atomics\/T\d{4}/.test(url) },
  'capec': { match: has('mitre/cti/master/capec/') },
  'misp-galaxy': { match: has('MISP/misp-galaxy/') },
  'engage': { match: has('mitre/engage/') },
  'elastic-tree': { match: has('repos/elastic/detection-rules/') },
  'splunk-tree': { match: has('repos/splunk/security_content/') },
  'sentinel-attack-tree': { match: has('repos/edoardogerosa/sentinel-attack/') },
  'm365-hunting-queries': { match: has('Microsoft-365-Defender-Hunting-Queries') },
  'trickest-poc-tree': { match: has('repos/trickest/cve/'), needsCtid: true },
  'nuclei-tree': { match: has('repos/projectdiscovery/nuclei-templates/'), needsCtid: true },
  'mdecrevoisier-sigma-tree': { match: has('repos/mdecrevoisier/SIGMA-detection-rules/') },
  'cyb3r-monk-hunting-tree': { match: has('repos/Cyb3r-Monk/Threat-Hunting-and-Detection/') },
  'evtx-samples-tree': { match: has('repos/mdecrevoisier/EVTX-to-MITRE-Attack/') },
  'payloads-tree': { match: has('repos/swisskyrepo/PayloadsAllTheThings/') },
  'exploitdb': { match: has('exploit-database/exploitdb'), needsCtid: true },
  'ipsum': { match: has('stamparm/ipsum/') },
  'threathunter-playbook': { match: has('OTRF/ThreatHunter-Playbook/') },
  'anthropic-skills-layer': { match: has('mukul975/Anthropic-Cybersecurity-Skills/') },
  'd3fend-ontology': { match: has('d3fend.mitre.org/api/technique/all.json') },
  'd3fend-technique-api': { match: has('d3fend.mitre.org/api/offensive-technique/attack/') },
};

/** Live sources with no request to block, and why. */
const NOT_FETCHED: Record<string, string> = {
  'cis-controls': 'withdrawn upstream: the app makes no request (archived-upstream, never loaded)',
};

const CTID_CSV_URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv';
const CTID_CSV = 'CVE ID,Primary Impact,Secondary Impact,Exploitation Technique,Uncategorized,Phase\nCVE-2021-44228,T1190,,T1059,,\n';

const DOMAIN_BUTTON: Record<Domain, string> = {
  enterprise: 'Enterprise ATT&CK',
  ics: 'ICS ATT&CK',
  mobile: 'Mobile ATT&CK',
  f3: 'F3 Fraud Framework (CTID)',
};

/** One route that reads the source: the first non-matrix route that lists it, else the matrix. */
function dependentRoute(id: string, domain: Domain): string {
  const routes = Object.keys(ROUTE_SOURCES).filter(r => sourcesForRoute(r, domain).includes(id));
  return routes.find(r => r !== '/matrix') ?? routes[0];
}

/** Block the source's requests (registered after the hermetic routes, so it wins) and count them. */
async function takeOffline(page: Page, c: OfflineCase): Promise<() => number> {
  let blocked = 0;
  if (c.needsCtid) {
    await page.route(CTID_CSV_URL, route => route.fulfill({ status: 200, contentType: 'text/plain', body: CTID_CSV }));
  }
  await page.route(url => c.match(url.href), (route: Route) => {
    blocked++;
    return route.abort('internetdisconnected');
  });
  return () => blocked;
}

const LIVE = SOURCE_DEFINITIONS.filter(d => d.kind === 'live');

test.describe('E1.3: each live source forced offline shows failed, and its view banner names it', () => {
  test('every live source has an offline case', () => {
    const missing = LIVE.map(d => d.id).filter(id => !(id in OFFLINE) && !(id in NOT_FETCHED));
    expect(missing).toEqual([]);
    expect(Object.keys(OFFLINE).filter(id => !LIVE.some(d => d.id === id))).toEqual([]);
    for (const id of Object.keys(OFFLINE)) {
      expect(dependentRoute(id, OFFLINE[id].domain ?? 'enterprise'), `${id} has a dependent route`).toBeTruthy();
    }
  });

  for (const def of LIVE.filter(d => d.id in OFFLINE)) {
    const c = OFFLINE[def.id];
    const domain = c.domain ?? 'enterprise';
    const route = dependentRoute(def.id, domain);

    test(`${def.id} offline: data health shows failed; ${route} names it`, async ({ page }) => {
      test.slow(); // a few loaders back off and retry (1 s, 2 s, 4 s) before they give up
      const blockedCount = await takeOffline(page, c);

      await page.goto(`${BASE}/#/status`);
      const row = page.locator(`app-source-health tr[data-source-id="${def.id}"]`);
      await expect(row).toBeAttached({ timeout: ROUTE_TIMEOUT });

      if (c.domain) {
        // Switching the matrix to the domain is what loads its live bundle.
        await page.locator(`.domain-btn[title="${DOMAIN_BUTTON[c.domain]}"]`).click();
        await expect(page.locator(`.domain-btn[title="${DOMAIN_BUTTON[c.domain]}"]`)).toHaveClass(/active/);
      }

      // Let a source that loads on its own start; one that loads only on demand stays
      // 'pending' and is started from its row.
      await expect(row).not.toHaveAttribute('data-status', 'loading', { timeout: ROUTE_TIMEOUT });
      if (!c.domain && (await row.getAttribute('data-status')) === 'pending') {
        await row.getByRole('button', { name: `Load now: ${def.name}` }).click();
      }

      await expect(row).toHaveAttribute('data-status', 'failed', { timeout: ROUTE_TIMEOUT });
      await expect(row.locator('.sh-status')).toHaveText('failed');
      await expect(row.locator('.sh-detail')).not.toBeEmpty();
      expect(blockedCount(), 'the source sent its request and the block caught it').toBeGreaterThan(0);
      // A failed source offers Retry.
      await expect(row.getByRole('button', { name: `Retry: ${def.name}` })).toBeVisible();

      // In-app navigation keeps this session's registry.
      await page.evaluate(path => { window.location.hash = `#${path}`; }, route);
      const banner = page.locator('app-source-banner [data-testid="source-banner"]');
      await expect(banner).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(banner.locator(`[data-source-id="${def.id}"]`)).toContainText(`${def.name} (failed)`);
      await expect(banner).toContainText(`${def.name} (failed)`);
    });
  }
});
