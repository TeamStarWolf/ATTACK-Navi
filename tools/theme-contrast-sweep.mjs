// Every-tab review: for each route x theme, detect leftover navy surfaces and
// run an axe color-contrast scan. Navy detector: samples computed backgrounds
// of visible elements; flags dark blue-dominant colors (b > r+20 && b > g+15,
// luminance < 90) that aren't heatmap/data cells.
import { chromium } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';

const routes = [
  '#/matrix',
  '#/dashboard/overview', '#/dashboard/analytics',
  '#/intel/groups', '#/intel/actors', '#/intel/compare', '#/intel/scenarios', '#/intel/emulation', '#/intel/campaigns', '#/intel/software', '#/intel/feeds',
  '#/detect/detections', '#/detect/sigma', '#/detect/siem', '#/detect/yara', '#/detect/validation', '#/detect/data-sources', '#/detect/purple-team',
  '#/exposure/cve', '#/exposure/risk', '#/exposure/kill-chain', '#/exposure/graph', '#/exposure/gap-analysis', '#/exposure/priority', '#/exposure/what-if', '#/exposure/ctem',
  '#/coverage/assessment', '#/coverage/controls', '#/coverage/custom-mitigations', '#/coverage/compliance', '#/coverage/diff', '#/coverage/timeline', '#/coverage/target', '#/coverage/assets',
  '#/library/workbench', '#/library/layers', '#/library/collections', '#/library/comparison', '#/library/roadmap', '#/library/watchlist', '#/library/tags',
  '#/reports/report', '#/reports/playbooks', '#/reports/exports',
  '#/settings/preferences', '#/settings/changelog',
];

const browser = await chromium.launch();
const findings = [];

for (const theme of ['dark', 'light']) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.route('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/**', route =>
    route.fulfill({ path: 'src/assets/data/enterprise-attack.json', contentType: 'application/json' }),
  );
  await page.addInitScript((th) => {
    localStorage.setItem('onboarding-completed', 'true');
    localStorage.setItem('mitre-nav-theme', th);
  }, theme);

  for (const route of routes) {
    try {
      await page.goto(`http://localhost:4200/${route}`);
      await page.waitForTimeout(2200);

      const navy = await page.evaluate(() => {
        const bad = new Map();
        const els = document.querySelectorAll('*');
        for (const el of els) {
          if (el.closest('.cell') || el.closest('app-technique-cell')) continue; // heatmap data colors
          const r = el.getBoundingClientRect();
          if (r.width < 40 || r.height < 16 || r.bottom < 0 || r.top > innerHeight) continue;
          const bg = getComputedStyle(el).backgroundColor;
          const m = bg.match(/rgba?\((\d+), (\d+), (\d+)/);
          if (!m) continue;
          const [, rr, gg, bb] = m.map(Number);
          const lum = 0.299 * rr + 0.587 * gg + 0.114 * bb;
          // navy: blue-dominant dark. The zinc palette keeps channels within
          // a few points of each other, so even mild blue dominance is off-palette.
          if (lum < 90 && bb > rr + 8 && bb > gg + 5 && bb > 25) {
            const key = `${bg} <${el.tagName.toLowerCase()}.${(el.className?.toString?.() ?? '').split(' ')[0]}>`;
            bad.set(key, (bad.get(key) ?? 0) + 1);
          }
        }
        return [...bad.entries()].slice(0, 4);
      });

      const axe = await new AxeBuilder({ page }).withRules(['color-contrast']).analyze();
      if (navy.length || axe.violations.length) {
        const contrast = axe.violations.flatMap(v => v.nodes.slice(0, 3).map(n => {
          const d = n.any?.[0]?.data;
          return `${n.target[0].toString().replace(/\[_ngcontent[^\]]*\]/g, '').slice(0, 55)} ${d?.fgColor}/${d?.bgColor}=${d?.contrastRatio}`;
        }));
        findings.push({ route, theme, navy, contrastCount: axe.violations.reduce((a, v) => a + v.nodes.length, 0), contrast: contrast.slice(0, 3) });
      }
    } catch (e) {
      findings.push({ route, theme, error: String(e).slice(0, 100) });
    }
  }
  await context.close();
}

console.log(JSON.stringify(findings, null, 1));
console.log(`\nTOTAL findings: ${findings.length} of ${routes.length * 2} page-theme combos`);
await browser.close();
