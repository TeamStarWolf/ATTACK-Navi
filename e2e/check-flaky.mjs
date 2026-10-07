#!/usr/bin/env node
// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Fails when the Playwright JSON report contains a test that only passed on a
// retry. playwright.config.ts allows one retry on CI so a slow runner does not
// fail the run, but a retried pass is a flaky test, and a flaky test must be
// visible in the workflow rather than reported as green.
//
//   node e2e/check-flaky.mjs [playwright-report/results.json]
import { readFileSync } from 'node:fs';

const reportPath = process.argv[2] ?? 'playwright-report/results.json';

let report;
try {
  report = JSON.parse(readFileSync(reportPath, 'utf8'));
} catch (err) {
  console.error(`check-flaky: cannot read ${reportPath}: ${err.message}`);
  process.exit(2);
}

/** Collect every (title, status) pair from Playwright's nested suite tree. */
export function collect(suites, prefix = []) {
  const out = [];
  for (const suite of suites ?? []) {
    const here = suite.title ? [...prefix, suite.title] : prefix;
    for (const spec of suite.specs ?? []) {
      for (const t of spec.tests ?? []) {
        out.push({ title: [...here, spec.title].join(' › '), status: t.status, project: t.projectName });
      }
    }
    out.push(...collect(suite.suites, here));
  }
  return out;
}

const tests = collect(report.suites);
const flaky = tests.filter(t => t.status === 'flaky');
const summary = tests.reduce((acc, t) => ({ ...acc, [t.status]: (acc[t.status] ?? 0) + 1 }), {});
console.log(`check-flaky: ${tests.length} tests — ${JSON.stringify(summary)}`);

if (flaky.length) {
  console.error('check-flaky: these tests passed only on retry (flaky):');
  for (const t of flaky) console.error(`  - ${t.title}`);
  process.exit(1);
}
