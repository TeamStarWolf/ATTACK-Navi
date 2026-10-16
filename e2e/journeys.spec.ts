// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The eight acceptance journeys of the redesign plan (Appendix C), as pending
// tests (plan epic E0.3).
//
// Each journey is a test.fixme: it is listed (and counted as skipped) in every
// run so the CI report always shows the eight journeys and the phase each one
// is due to turn green in. The body is the journey script, step by step, as
// comments. The phase that builds a journey's last piece replaces its comments
// with assertions and changes test.fixme to test; nothing else in this file
// needs to move.
//
// The journeys load their data from the shared fixture workspace
// (e2e/fixtures/workspace). The "shared fixture workspace" block at the end is
// live today: it guards that fixture so a journey never turns on against data
// that has drifted from what its script promises.
import { readFileSync } from 'node:fs';
import { test, expect, loadSampleOrg } from './fixtures/workspace';

/** Annotation shown next to each pending journey in the report. */
const greenBy = (phase: string) => ({ tag: '@journey', annotation: { type: 'green by', description: phase } });

test.describe('acceptance journeys (plan Appendix C)', () => {
  test.fixme('journey 1, VM: KEV to packet', greenBy('P5'), async () => {
    // 1. Load the fixture workspace (sample-org.json: fw-edge-01 runs PAN-OS 11.1.0).
    // 2. On Home, paste CVE-2024-3400 and open the CVE page (#/cve/CVE-2024-3400).
    // 3. Assert a dated KEV badge (date from the catalog's dateAdded).
    // 4. Assert an SSVC decision with every input shown.
    // 5. Assert the affected assets (fw-edge-01).
    // 6. Assert the techniques from the bundled chain, each edge with its confidence.
    // 7. Assert at least one Blunt control.
    // 8. Assert a packet with every field.
    // 9. Force the KEV fetch to fail; assert the decision reads 'provisional: exploitation unknown'.
    // 10. Record a close date; assert MTTM appears in the VM brief.
  });

  test.fixme('journey 2, Detection: gap to rule', greenBy('P7'), async () => {
    // 1. Select two actors.
    // 2. Open Detect > Gaps and take the first row.
    // 3. Open its SigmaHQ rules; assert the links resolve.
    // 4. Export SPL; assert the output contains no TODO.
  });

  test.fixme('journey 3, Purple: range import', greenBy('P2 (fixture), P6 (vendored)'), async () => {
    // 1. Import the synthetic 8-row fixture contract (sample-org.json rangeContract,
    //    6 distinct techniques).
    // 2. Assert 6 Proven-in-range cells, each with the lab badge.
    // 3. Open #/mission/CORNERIA-ROOT-01; assert it renders.
    // 4. Open the T1558.003 drawer; assert it lists 'validated, wazuh:100821'.
  });

  test.fixme('journey 4, Honesty: empty user', greenBy('P1'), async () => {
    // 1. Fresh profile: test.use({ workspace: { skipOnboarding: false } }), no stored state.
    // 2. Assert the default lens is neither Posture nor Reference depth.
    // 3. DOM scan: assert no 'covered', 'defended', 'LOW RISK' (sample-org.json
    //    honesty.forbiddenStrings) or grade strings anywhere on the page.
  });

  test.fixme('journey 5, Share', greenBy('P2 / P4'), async () => {
    // 1. In a new browser context, open #/matrix?lens=posture&tech=T1059.001&dom=enterprise&v=20.0
    //    (sample-org.json share.hash).
    // 2. Assert the same lens, the T1059.001 drawer open and data version 20.0.
    // 3. Assert every old route redirects (redirects.spec.ts PLANNED_REDIRECTS all on)
    //    and that ?view= survives each redirect.
  });

  test.fixme('journey 6, Accessibility', greenBy('P8'), async () => {
    // 1. Run axe on every route (a11y.spec.ts); assert 0 serious and 0 critical
    //    (today the spec is report-only against docs/A11Y_BASELINE.json).
    // 2. Assert the matrix has exactly one tab stop.
    // 3. Assert the arrow keys move between cells.
    // 4. Press Enter; assert the drawer opens with focus inside it.
  });

  test.fixme('journey 7, Learner: study and progress', greenBy('P6'), async () => {
    // 1. Choose the Learner role.
    // 2. Open T1059.001; assert the drawer opens on the Learn tab.
    // 3. Print-preview the full page.
    // 4. Mark it studied in one click.
    // 5. Export the progress layer; assert it contains T1059.001.
  });

  test.fixme('journey 8, CTI: report to layer', greenBy('P7'), async () => {
    // 1. Start a timer; record every request that leaves the browser.
    // 2. Paste the fixture report text (sample-org.json ctiReport.text).
    // 3. Assert the expected technique ids are proposed, each with its sentence
    //    (ctiReport.expected).
    // 4. Accept them and save a layer with citations.
    // 5. Assert no network request left the browser.
    // 6. Assert elapsed time <= 2 minutes.
  });
});

test.describe('shared fixture workspace', () => {
  const org = loadSampleOrg();

  // Every technique the journeys rely on must exist, unrevoked and not
  // deprecated, in the bundled Enterprise snapshot the e2e run serves.
  test('every sample-org technique id is live in the bundled Enterprise ATT&CK', () => {
    const bundle = JSON.parse(readFileSync('src/assets/data/enterprise-attack.json', 'utf8')) as {
      objects: Array<{
        type: string;
        revoked?: boolean;
        x_mitre_deprecated?: boolean;
        external_references?: Array<{ source_name: string; external_id?: string }>;
      }>;
    };
    const live = new Set<string>();
    for (const o of bundle.objects) {
      if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
      const id = o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
      if (id) live.add(id);
    }
    const used = new Set([
      ...org.rangeContract.rows.map(r => r.technique_id),
      ...org.ctiReport.expected.map(e => e.technique_id),
      'T1059.001', // journeys 5 and 7
    ]);
    expect([...used].filter(id => !live.has(id))).toEqual([]);
  });

  test('the range contract is the 8-row, 6-technique contract journey 3 promises', () => {
    const rows = org.rangeContract.rows;
    expect(rows).toHaveLength(8);
    expect(new Set(rows.map(r => r.technique_id)).size).toBe(6);
    expect(rows.every(r => r.mission_id === 'CORNERIA-ROOT-01')).toBe(true);
    expect(rows).toContainEqual(
      expect.objectContaining({ technique_id: 'T1558.003', result: 'validated', detection: 'wazuh:100821' }),
    );
  });

  test('the CTI report holds every expected sentence verbatim', () => {
    for (const { sentence } of org.ctiReport.expected) {
      expect(org.ctiReport.text).toContain(sentence);
    }
  });

  test('journey 1 and journey 5 inputs are present', () => {
    expect(org.synthetic).toBe(true);
    const asset = org.assets.find(a => a.id === org.vmJourney.affectedAssetIds[0]);
    expect(asset?.cves).toContain(org.vmJourney.cve);
    expect(org.vmJourney.cve).toBe('CVE-2024-3400');
    expect(org.share.hash).toBe('/matrix?lens=posture&tech=T1059.001&dom=enterprise&v=20.0');
  });
});
