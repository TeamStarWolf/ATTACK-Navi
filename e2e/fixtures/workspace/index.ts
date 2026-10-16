// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The shared e2e fixture workspace (plan epic E0.3).
//
// Every journey, redirect and accessibility spec opens the app through this
// one module so they all see the same hermetic network and the same starting
// state. It is deliberately small today; it is the seed of the "sample org"
// the redesign introduces later, and sample-org.json next to it already holds
// the data the eight acceptance journeys will load (assets, the range-import
// contract, the CTI report, the share link).
//
// Hermetic routing: when the hermetic() helper from the e2e hardening PR
// (#126) is on main, this module should import it instead of keeping its own
// copy. Until then it carries a minimal version with the same rules: block
// every request that is not the app itself and serve each ATT&CK domain from
// its own bundled snapshot.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test as base, expect, Page } from '@playwright/test';

export { expect };

export const BASE = 'http://localhost:4200';

// A deep link's first hit has to download that lazy route's chunk and boot
// the app; on the constrained CI runner that is far slower than locally.
export const ROUTE_TIMEOUT = process.env['CI'] ? 60000 : 15000;

const STIX = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master';

/**
 * Each ATT&CK bundle the app revalidates, routed to the matching bundled
 * snapshot. Routed per domain on purpose: one wildcard route would answer the
 * ICS and Mobile fetches with Enterprise data.
 */
export const ATTACK_FIXTURES: ReadonlyArray<readonly [url: string, file: string]> = [
  [`${STIX}/enterprise-attack/enterprise-attack.json`, 'src/assets/data/enterprise-attack.json'],
  [`${STIX}/ics-attack/ics-attack.json`, 'src/assets/data/ics-attack.json'],
  [`${STIX}/mobile-attack/mobile-attack.json`, 'src/assets/data/mobile-attack.json'],
  [
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-stix.json',
    'src/assets/data/f3-attack.json',
  ],
];

const isAppOrigin = (url: URL): boolean =>
  (url.hostname === 'localhost' || url.hostname === '127.0.0.1') && url.port === '4200';

/**
 * Make the page hermetic: abort everything that is not the app, then serve the
 * ATT&CK bundles from the repo. Every enrichment loader already treats a
 * failed fetch as "no data", so a run never depends on GitHub, CISA, NVD,
 * FIRST or MITRE being reachable.
 *
 * Playwright evaluates routes in reverse registration order, so the catch-all
 * is registered first and the fixture routes after it win.
 */
export async function hermetic(page: Page): Promise<void> {
  await page.route(url => !isAppOrigin(url), route => route.abort('blockedbyclient'));
  for (const [url, file] of ATTACK_FIXTURES) {
    await page.route(url, route => route.fulfill({ path: file, contentType: 'application/json' }));
  }
}

/** Starting state for a page opened through the workspace. */
export interface WorkspaceOptions {
  /**
   * Skip the first-visit onboarding overlay (it would intercept every click).
   * Journey 4 ("fresh profile") turns this off.
   */
  skipOnboarding: boolean;
}

export const DEFAULT_WORKSPACE: WorkspaceOptions = { skipOnboarding: true };

/** Prepare a page: hermetic network plus the requested starting state. */
export async function openWorkspace(page: Page, options: Partial<WorkspaceOptions> = {}): Promise<void> {
  const opts = { ...DEFAULT_WORKSPACE, ...options };
  await hermetic(page);
  if (opts.skipOnboarding) {
    await page.addInitScript(() => localStorage.setItem('onboarding-completed', 'true'));
  }
}

/** The sample-org data set the journeys will load (see sample-org.json). */
export interface SampleOrg {
  schema: string;
  name: string;
  synthetic: true;
  note: string;
  assets: Array<{ id: string; name: string; vendor: string; product: string; version: string; cves: string[] }>;
  vmJourney: { cve: string; affectedAssetIds: string[] };
  rangeContract: {
    mission: string;
    rows: Array<{ mission_id: string; technique_id: string; result: string; detection: string; run_at: string }>;
  };
  ctiReport: { title: string; text: string; expected: Array<{ technique_id: string; sentence: string }> };
  share: { hash: string };
  honesty: { forbiddenStrings: string[] };
}

/** Read the sample org from disk (the spec files run with the repo root as cwd). */
export function loadSampleOrg(): SampleOrg {
  return JSON.parse(readFileSync(join(__dirname, 'sample-org.json'), 'utf8')) as SampleOrg;
}

/**
 * `test` with the workspace applied automatically: every test that imports it
 * starts hermetic with onboarding skipped. Override per file or describe with
 * `test.use({ workspace: { skipOnboarding: false } })`.
 */
export const test = base.extend<{ workspace: WorkspaceOptions; workspaceReady: void }>({
  workspace: [DEFAULT_WORKSPACE, { option: true }],
  workspaceReady: [
    async ({ page, workspace }, use) => {
      await openWorkspace(page, workspace);
      await use();
    },
    { auto: true },
  ],
});
