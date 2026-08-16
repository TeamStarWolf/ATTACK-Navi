import { chromium } from '@playwright/test';
const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
await page.route('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/**', r =>
  r.fulfill({ path: 'src/assets/data/enterprise-attack.json', contentType: 'application/json' }));
await page.addInitScript(() => {
  localStorage.setItem('onboarding-completed', 'true');
  localStorage.setItem('mitre-nav-theme', 'dark');
});
await page.goto('http://localhost:4200/#/exposure/priority');
await page.waitForTimeout(2500);
const out = await page.evaluate(() => {
  const res = [];
  const seen = new Set();
  let el = document.querySelector('.row-header');
  while (el) {
    const bg = getComputedStyle(el).backgroundColor;
    const key = `${el.tagName}.${(el.className?.toString?.() ?? '').split(' ')[0]}`;
    if (!seen.has(key)) { seen.add(key); res.push(`${key}: ${bg}`); }
    el = el.parentElement;
  }
  return res;
});
console.log(out.join('\n'));
await browser.close();
