// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Mobile boot memory: a phone can open the matrix.
//
// The owner's iPhone showed "Can't open this page" on every visit. The cause was a
// boot-time download the default matrix does not need: the CVE2CAPEC year files
// (about 56 MiB of gzip, about 1.7 GB of JSONL once inflated) parsed on the main
// thread, which drove the browser's content process to 1.2-1.4 GB and kept about
// 200 MB of JS heap. They, the trickest PoC index and the CTID ATT&CK-to-CVE
// mapping now load on demand. This spec opens #/matrix as an iPhone 13 (Playwright's
// device descriptor, run in Chromium for the CDP memory metrics) with the service
// worker blocked, and checks:
//   - no request to the Galeax CVE2CAPEC files or the trickest tree before a drawer opens;
//   - all 872 technique cells render;
//   - CDP Performance.getMetrics JSHeapUsedSize, sampled every 250 ms from navigation
//     to networkidle + 3 s, stays under 150 MB, and under 80 MB after
//     HeapProfiler.collectGarbage (performance.memory is not used: it is unreliable);
//   - no long task over 1,000 ms;
//   - picking the CVE Kill Chain lens through the View menu starts the CVE2CAPEC
//     request and the lens renders (the year files are answered with a one-line fixture).
// Written for the production build (dev builds mislead network and memory numbers);
// it also runs against the development bundle the e2e workflow serves.
// Run it alone with: npx playwright test e2e/mobile-boot-memory.spec.ts
import { gzipSync } from 'node:zlib';
import { devices } from '@playwright/test';
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';

const IPHONE_13 = devices['iPhone 13'];
// The descriptor names WebKit as its default browser; the CDP metrics need Chromium.
const { defaultBrowserType: _webkit, ...iphone13 } = IPHONE_13 ?? { defaultBrowserType: undefined };

const MB = 1024 * 1024;
const HEAP_PEAK_LIMIT = 150 * MB;
const HEAP_AFTER_GC_LIMIT = 80 * MB;
const LONG_TASK_LIMIT_MS = 1000;
const MATRIX_CELLS = 872;

const isGaleax = (url: string): boolean => url.startsWith('https://raw.githubusercontent.com/Galeax/CVE2CAPEC/');
const isTrickest = (url: string): boolean => url.startsWith('https://api.github.com/repos/trickest/cve/');

/** One CVE2CAPEC JSONL line, gzipped as upstream ships it: two techniques get one chain each. */
const CHAIN_FIXTURE = gzipSync(
  JSON.stringify({ 'CVE-2024-3400': { CWE: ['77'], CAPEC: ['88'], TECHNIQUES: ['1190', '1059'], DEFEND: ['D3-NTA'] } }) + '\n',
);
/** The kill-chain ramp's top stop ('#9c5cc5'): what a technique holding the most chains is painted. */
const KILL_CHAIN_TOP = 'rgb(156, 92, 197)';

test.describe('mobile boot memory: an iPhone 13 can open the matrix', () => {
  test.skip(!IPHONE_13, "Playwright's bundled iPhone 13 device descriptor is missing");
  test.use({ ...iphone13, serviceWorkers: 'block' });

  test('the matrix boots without the on-demand CVE sources, inside the heap budget, and the kill-chain lens loads its chains when picked', async ({ page, context, browserName }) => {
    test.skip(browserName !== 'chromium', 'CDP memory metrics are Chromium-only');
    test.slow();

    const requests: string[] = [];
    page.on('request', r => requests.push(r.url()));
    await page.route('**/ngsw-worker.js', r => r.abort());
    // Registered after the hermetic catch-all, so it wins: the year files get the fixture.
    await page.route(url => isGaleax(url.href), r => r.fulfill({ status: 200, contentType: 'application/gzip', body: CHAIN_FIXTURE }));
    await page.addInitScript(() => {
      const w = window as unknown as { __longTasks: number[] };
      w.__longTasks = [];
      try {
        new PerformanceObserver(list => {
          for (const e of list.getEntries()) w.__longTasks.push(e.duration);
        }).observe({ type: 'longtask', buffered: true });
      } catch { /* no longtask support: the list stays empty */ }
    });

    const cdp = await context.newCDPSession(page);
    await cdp.send('Performance.enable');
    await cdp.send('HeapProfiler.enable');
    const heapUsed = async (): Promise<number> => {
      const { metrics } = await cdp.send('Performance.getMetrics');
      return metrics.find(m => m.name === 'JSHeapUsedSize')?.value ?? 0;
    };
    let heapPeak = 0;
    let samples = 0;
    let sampling = true;
    const sampler = (async () => {
      while (sampling) {
        try { heapPeak = Math.max(heapPeak, await heapUsed()); samples++; } catch { /* page navigating */ }
        await new Promise(r => setTimeout(r, 250));
      }
    })();

    await page.goto(`${BASE}/#/matrix`, { waitUntil: 'networkidle', timeout: ROUTE_TIMEOUT * 4 });
    await page.waitForTimeout(3000);
    sampling = false;
    await sampler;

    // No drawer has opened, so neither on-demand download may have started.
    await expect(page.locator('.sidebar.open')).toHaveCount(0);
    expect(requests.filter(isGaleax), 'no CVE2CAPEC request at boot').toEqual([]);
    expect(requests.filter(isTrickest), 'no trickest tree request at boot').toEqual([]);

    await expect(page.locator('[data-tech-id]')).toHaveCount(MATRIX_CELLS, { timeout: ROUTE_TIMEOUT });

    expect(samples, 'the heap was sampled').toBeGreaterThan(4);
    expect(heapPeak, `JS heap peak ${(heapPeak / MB).toFixed(1)} MB`).toBeLessThan(HEAP_PEAK_LIMIT);
    await cdp.send('HeapProfiler.collectGarbage');
    const afterGc = await heapUsed();
    expect(afterGc, `JS heap after GC ${(afterGc / MB).toFixed(1)} MB`).toBeLessThan(HEAP_AFTER_GC_LIMIT);

    const longTasks = await page.evaluate(() => (window as unknown as { __longTasks: number[] }).__longTasks);
    expect(Math.max(0, ...longTasks), `longest task of ${longTasks.length}`).toBeLessThan(LONG_TASK_LIMIT_MS);

    // Pick the CVE Kill Chain lens through the View menu: the chains are requested now.
    await page.locator('.heatmap-btn').click();
    await page.locator('.views-menu .lens-item[data-lens="kill-chain"] .heatmap-mode-btn').click();
    await expect(page).toHaveURL(/[?&]heat=kill-chain(&|$)/, { timeout: ROUTE_TIMEOUT });
    await expect.poll(() => requests.filter(isGaleax).length, { message: 'the CVE2CAPEC year files are requested', timeout: ROUTE_TIMEOUT }).toBeGreaterThan(0);

    // The lens renders: its legend (in the context strip, closed by default), then the
    // chained techniques in the ramp's top colour.
    await page.locator('.context-strip-toggle').click();
    await expect(page.locator('app-legend .legend-label')).toHaveText('CVE Kill Chain');
    await expect(page.locator('app-legend .legend-loading')).toHaveCount(0, { timeout: ROUTE_TIMEOUT });
    await expect.poll(
      () => page.locator('[data-tech-id]').evaluateAll((cells, top) =>
        cells.filter(c => [c, ...Array.from(c.querySelectorAll('*'))].some(e => getComputedStyle(e).backgroundColor === top)).length, KILL_CHAIN_TOP),
      { message: 'the chained techniques are painted', timeout: ROUTE_TIMEOUT },
    ).toBeGreaterThan(0);
  });
});
