// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 40: the range telemetry cause is worded per technique and per rule,
// never per row. The round-8 breaker's multi-row and same-run shapes (g35) are stored
// as "Import range results" and "Import JSON" store them (testing/rpf8-shapes.ts), then
// every surface is read the way the app reads it: runInputsFor and derivePosture, the
// Posture, Covered and Status why lines, the cell's aria-label and tooltip, the card's
// Covered rows and Record-a-run tooltip, the Validation pill's tally and the Proven block.
import type { Technique } from '../technique';
import { heatmapModeDef, type LensContext } from '../heatmap-modes';
import type { CoveredMark, PostureInputs, PostureState } from './posture.types';
import { DEFAULT_POSTURE_RULES, derivePosture } from './derive-posture';
import { latestRun, storedRunKey } from './latest-run';
import { firedRuleTally } from './fired-rules';
import { notCreditedWords, partialMarkWords, recordRunTooltip, telemetryPartialWords } from './partial-cause';
import { postureCellLabel } from './posture-ramp';
import { lensExplain, provenNoneLine } from '../lens-explain';
import { runInputsFor } from '../../services/posture-adapters';
import type { ImplView } from '../../services/posture-adapters';
import type { ValidationRunV2 } from '../../services/validation.service';
import { rpf8Runs } from '../../testing/rpf8-shapes';

const NOW = new Date(2026, 9, 23, 12);
const WINDOWS = DEFAULT_POSTURE_RULES.decayDays;
const NOT_PROOF = 'but the range reports telemetry-only coverage, so it is not proof';

/** The technique's state as PostureService derives it from its stored runs. */
function derive(runs: readonly ValidationRunV2[], covered: readonly CoveredMark[] = []): PostureState {
  const inputs = runInputsFor(runs);
  const input: PostureInputs = {
    knownSignals: 2, threatWeight: 1, exposureWeight: 0,
    covered: [...covered, ...inputs.flatMap(i => i.covered)],
    proof: inputs.flatMap(i => i.proof), verdicts: inputs.flatMap(i => i.verdicts), runs: inputs.map(i => i.summary),
  };
  return derivePosture(`attack/enterprise/${runs[0]?.techniqueId ?? 'T0000'}@19.2`, input, DEFAULT_POSTURE_RULES, NOW);
}

function ctx(state: PostureState, impl: ImplView = { status: null, partialVia: null }): LensContext {
  return {
    posture: () => state, implView: () => impl, theme: 'dark', colorblindSafe: false,
    known: () => ({ mitigations: true, detectionContent: false, controls: false, d3fend: false, atomic: false }),
    knownCounts: () => ({ mitigations: 1, detectionContent: 0, controls: 0, d3fend: 0, atomic: 0 }),
  } as unknown as LensContext;
}

const TECH = { id: 'attack-pattern--x', attackId: 'T0000' } as Technique;

/** Every surface of the drawer and the technique page that words the telemetry cause, for one state. */
function surfaces(state: PostureState, impl?: ImplView): Record<string, string> {
  const c = ctx(state, impl);
  const out: Record<string, string> = {};
  for (const lens of ['posture', 'covered', 'status', 'proven'] as const) {
    const def = heatmapModeDef(lens)!;
    const cell = def.project!(c, TECH);
    out[`why ${lens}`] = lensExplain(def, cell, { state, decayDays: WINDOWS });
    out[`cell ${lens}`] = lens === 'posture'
      ? postureCellLabel(state, WINDOWS)
      : postureCellLabel(state, WINDOWS, { value: lens, words: cell.label }, { bucket: cell.bucket ?? 'none', subStates: cell.subStates ?? [] });
  }
  state.covered.forEach((m, i) => {
    out[`covered row ${i}`] = partialMarkWords(m) ?? '';
    if (m.partialCause === 'telemetry') out[`record-a-run ${i}`] = recordRunTooltip(m);
  });
  return out;
}

/** How many rules the pill (the latest run) and the Proven block count as fired. */
function counted(runs: readonly ValidationRunV2[], state: PostureState): { pill: number; proven: number } {
  const latest = latestRun(runs, storedRunKey)!.run;
  const proofLine = provenNoneLine(state);
  const none = /(\d+) rules? fired/.exec(proofLine);
  const proven = state.proof.length > 0 ? (state.proof[0].runRulesFired ?? 1) : none ? Number(none[1]) : 0;
  return { pill: firedRuleTally(latest).fired, proven };
}

describe('RP-F decision 40: the telemetry cause per technique and per rule', () => {
  const shapes = rpf8Runs();
  const of = (id: string) => {
    const runs = shapes.get(id)!;
    const state = derive(runs);
    return { runs, state, words: telemetryPartialWords(state.covered) };
  };

  // The invariant: "no detection alerted" never appears while the pill or the Proven
  // block counts a fired rule for the technique.
  for (const [id, runs] of rpf8Runs()) {
    it(`${id}: no surface says "no detection alerted" beside a fired rule the pill or the Proven block counts`, () => {
      const state = derive(runs);
      const { pill, proven } = counted(runs, state);
      const all = surfaces(state);
      if (pill > 0 || proven > 0) {
        for (const [where, text] of Object.entries(all)) expect(`${where}: ${text}`).not.toContain('no detection alerted');
      } else {
        expect(pill + proven).toBe(0);
      }
      for (const text of Object.values(all)) expect(text).not.toMatch(/\bundefined\b|\bNaN\b|\bnull\b/);
    });
  }

  it('T1105 (wazuh:206 logged on 10/20, alerted on 10/21): one clause, alerted, dated 10/21', () => {
    const { state, words } = of('T1105');
    expect(state.covered.filter(m => m.partialCause === 'telemetry').length).toBe(1);
    expect(words).toBe(`range telemetry observed via wazuh:206: partial; the rule alerted in this run, ${NOT_PROOF} (range run on 10/21/26)`);
    expect(surfaces(state)['why posture']).toContain(words);
    expect(surfaces(state)['cell covered']).toContain(words);
  });

  it('T1113 (wazuh:201 alerted, wazuh:202 logged): two clauses, one quiet and one alerted, beside a pill counting 1', () => {
    const { runs, state, words } = of('T1113');
    expect(words).toBe(
      'range telemetry observed via wazuh:202: partial, this rule did not alert (range run on 10/21/26); '
      + `range telemetry observed via wazuh:201: partial; the rule alerted in this run, ${NOT_PROOF} (range run on 10/21/26)`);
    expect(firedRuleTally(latestRun(runs, storedRunKey)!.run).words).toBe('1 of 1 expected rules fired');
    expect(state.covered.map(m => partialMarkWords(m))).toEqual([
      `range telemetry observed via wazuh:201: partial; the rule alerted in this run, ${NOT_PROOF} (range run on 10/21/26)`,
      'range telemetry observed via wazuh:202: partial, this rule did not alert (range run on 10/21/26)',
    ]);
  });

  it('T1057 (Proven by wazuh:204): the Covered row for wazuh:203 reads quiet while the Proven block names wazuh:204', () => {
    const { state } = of('T1057');
    expect(state.bucket).toBe('proven');
    expect(state.proof.map(p => p.detectionRef)).toEqual(['wazuh:204']);
    expect(state.covered.map(m => [m.via, partialMarkWords(m)])).toEqual([
      ['wazuh:203', 'range telemetry observed via wazuh:203: partial, this rule did not alert (range run on 10/21/26)'],
    ]);
  });

  it('T1560 (one Import JSON run: wazuh:303 telemetry logged, wazuh:304 alerted): wazuh:303 reads quiet beside "1 of 2"', () => {
    const { runs, words } = of('T1560');
    expect(firedRuleTally(runs[0]).words).toBe('1 of 2 expected rules fired');
    expect(words).toBe('range telemetry observed via wazuh:303: partial, this rule did not alert (range run on 10/21/26)');
  });

  it('T1213 (Proven by wazuh:308 in the run that logged wazuh:309): wazuh:309 reads quiet', () => {
    const { state, words } = of('T1213');
    expect(state.bucket).toBe('proven');
    expect(words).toBe('range telemetry observed via wazuh:309: partial, this rule did not alert (range run on 10/21/26)');
  });

  it("T1221 (a telemetry row with no rule in a run that fired wazuh:301): the row resolves against its run's fired set", () => {
    const { words } = of('T1221');
    expect(words).toBe(`range telemetry observed via wazuh:301: partial; the rule alerted in this run, ${NOT_PROOF} (range run on 10/21/26)`);
  });

  it("T1030 (row 'WAZUH:306', fired 'wazuh:306'): rule ids match case-insensitively", () => {
    const { words } = of('T1030');
    expect(words).toBe(`range telemetry observed via WAZUH:306: partial; the rule alerted in this run, ${NOT_PROOF} (range run on 10/21/26)`);
  });

  it('a rule that fired only in an older run is named alerted with that run\'s date; a newer quiet row of it supersedes the older one', () => {
    const runs = shapes.get('T1105')!.map(r => r.runDate === '2026-10-20'
      ? { ...r, outcomes: r.outcomes.map(o => ({ ...o, outcome: 'alerted' as const })), detectionsFired: ['wazuh:206'] }
      : { ...r, outcomes: r.outcomes.map(o => ({ ...o, outcome: 'logged' as const })), detectionsFired: [] });
    const words = telemetryPartialWords(derive(runs).covered);
    expect(words).toBe(`range telemetry observed via wazuh:206: partial; the rule alerted in a run on 10/20/26, ${NOT_PROOF} (range run on 10/21/26)`);
  });

  // RP-F decision 44: a range run whose attack did not execute credits nothing and shows
  // no fired count. Round 8 (T1027.013: an errored Import JSON range run with wazuh:307
  // in detectionsFired and an alerted telemetry row) read "the rule alerted in this run".
  it('T1027.013 (range run errored): no mark, no fired count, no alerted clause; the Covered words say it was not credited', () => {
    const { runs, state } = of('T1027.013');
    expect(runs[0].status).toBe('untested');
    expect(state.covered).toEqual([]);
    expect(state.runsWithoutProof.map(r => [r.status, r.rulesFired, r.notExecuted])).toEqual([['untested', 0, 'errored']]);
    expect(notCreditedWords(state.runsWithoutProof[0])).toBe('range run on 10/21/26 did not execute (errored): not credited');
    expect(firedRuleTally(runs[0]).words).toBe('attack did not execute');
    expect(provenNoneLine(state)).toBe('No recorded detection for this technique');
    for (const text of Object.values(surfaces(state))) {
      expect(text).not.toContain('alerted in this run');
      expect(text).not.toMatch(/[1-9]\d* rules? fired/);
    }
    expect(surfaces(state)['why posture']).toContain('1 range run recorded, latest untested on 10/21/26');
  });

  it('a non-executed run supersedes no rule: an older executed telemetry row of the rule keeps its mark', () => {
    const [errored] = shapes.get('T1027.013')!;
    const older = { ...errored, id: 'older', runDate: '2026-10-20', attackResult: 'executed' as const, status: 'partial' as const };
    const state = derive([older, errored]);
    expect(state.covered.map(m => [m.via, m.at, m.telemetryOutcome])).toEqual([['wazuh:307', '2026-10-20', 'alerted']]);
  });

  it('the Status lens why line carries the telemetry clause its aria-label and tooltip carry (T1106: M1038 plus wazuh:14)', () => {
    const runs = shapes.get('T1082')!.map(r => ({ ...r, techniqueId: 'T1106', outcomes: r.outcomes.map(o => ({ ...o, detectionRef: 'wazuh:14' })), detectionsExpected: ['wazuh:14'], detectionsFired: ['wazuh:14'] }));
    const breadth: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'partial', via: 'M1038', source: 'manual', partialCause: 'breadth' };
    const state = derive(runs, [breadth]);
    const all = surfaces(state, { status: 'implemented', partialVia: 'M1038' });
    const clause = `range telemetry observed via wazuh:14: partial; the rule alerted in this run, ${NOT_PROOF} (range run on 10/21/26)`;
    expect(all['cell status']).toBe(`Status: implemented, partial via M1038, ${clause}`);
    expect(all['why status']).toBe(`Status: implemented, partial via M1038, ${clause}`);
  });
});
