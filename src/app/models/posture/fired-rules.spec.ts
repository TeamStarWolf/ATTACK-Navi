// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 30b: one fired-rule count. firedRules is the distinct, trimmed,
// non-empty union of detectionsFired and the rules of alerted or blocked outcomes;
// the run summary (posture-adapters) and the card's Proven line (lens-explain) count
// through it, as the Validation pill does (validation-status-pill.component.spec.ts).
import { firedRuleCount, firedRules, firedRuleTally } from './fired-rules';
import { firedRules as reExported } from '../../services/validation.service';
import { DEFAULT_POSTURE_RULES, derivePosture } from './derive-posture';
import { postureExplain } from '../lens-explain';
import { runInputs } from '../../services/posture-adapters';
import type { ValidationOutcome, ValidationRunV2 } from '../../services/validation.service';

function run(over: Partial<ValidationRunV2> = {}): ValidationRunV2 {
  return {
    id: 'r1', techniqueId: 'T1113', techniqueName: 'Screen Capture', runDate: '2026-10-20T10:00:00.000Z', operator: '',
    telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '',
    attackResult: 'executed', detectionsExpected: [], detectionsFired: [],
    responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '', status: 'passed',
    domain: 'enterprise', attackVersion: '19.2', source: 'manual',
    createdAt: '2026-10-20T10:00:00.000Z', updatedAt: '2026-10-20T10:00:00.000Z',
    techniqueRef: 'attack/enterprise/T1113@19.2', proofScope: 'own-run', outcomes: [], statusFromSource: false,
    ...over,
  };
}

const outcome = (detectionRef: string | null, o: ValidationOutcome['outcome']): ValidationOutcome => ({ detectionRef, outcome: o });

/** The card's Posture line for these runs, derived as PostureService derives it. */
function cardLine(runs: readonly ValidationRunV2[]): string {
  const inputs = runs.map(runInputs);
  const state = derivePosture('attack/enterprise/T1113@19.2', {
    knownSignals: 2, threatWeight: 1, exposureWeight: 0,
    covered: inputs.flatMap(i => i.covered),
    proof: inputs.flatMap(i => i.proof),
    verdicts: inputs.flatMap(i => i.verdicts),
    runs: inputs.map(i => i.summary),
  }, DEFAULT_POSTURE_RULES, new Date('2026-10-21T00:00:00.000Z'));
  return postureExplain(state);
}

describe('firedRules (RP-F decision 30b)', () => {
  it('a rule named only by a blocked or alerted outcome is a fired rule', () => {
    expect(firedRules({ detectionsFired: [], outcomes: [outcome('edr:x', 'blocked')] })).toEqual(['edr:x']);
    expect(firedRules({ detectionsFired: [], outcomes: [outcome('siem:y', 'alerted')] })).toEqual(['siem:y']);
  });

  it('duplicates and blanks collapse; logged, none and rule-less outcomes fire nothing', () => {
    expect(firedRules({
      detectionsFired: ['siem:a', ' siem:a ', '', '   '],
      outcomes: [outcome(' siem:a', 'alerted'), outcome('', 'blocked'), outcome(null, 'blocked'),
        outcome('siem:logged', 'logged'), outcome('siem:none', 'none')],
    })).toEqual(['siem:a']);
    expect(firedRuleCount({ detectionsFired: [] })).toBe(0);
    expect(firedRuleCount({ detectionsFired: [' ', ''], outcomes: [] })).toBe(0);
  });

  it('a run with both lists and overlap counts each rule once, detectionsFired first', () => {
    expect(firedRules({
      detectionsFired: ['siem:a', 'siem:b'],
      outcomes: [outcome('siem:b', 'alerted'), outcome('edr:c', 'blocked'), outcome('siem:a', 'blocked')],
    })).toEqual(['siem:a', 'siem:b', 'edr:c']);
  });

  it('a v1-shaped run (no outcomes) counts its detectionsFired', () => {
    expect(firedRuleCount({ detectionsFired: ['siem:a', 'siem:a', 'siem:b'] })).toBe(2);
  });

  // RP-F decision 33: the helper supplies both numbers, and the words for them when
  // more rules fired than were expected (never 'N of M' then).
  describe('firedRuleTally (RP-F decision 33)', () => {
    it("fired within expected: both numbers, no words (each surface keeps its fraction)", () => {
      expect(firedRuleTally({ detectionsExpected: ['siem:a', 'siem:b'], detectionsFired: ['siem:a'] }))
        .toEqual({ fired: 1, expected: 2, exceeds: false, words: null });
      expect(firedRuleTally({ detectionsExpected: ['siem:a'], detectionsFired: ['siem:a'] }))
        .toEqual({ fired: 1, expected: 1, exceeds: false, words: null });
      expect(firedRuleTally({ detectionsExpected: [], detectionsFired: [] }))
        .toEqual({ fired: 0, expected: 0, exceeds: false, words: null });
    });

    it("fired exceeds expected (rules known only from outcomes): 'N fired, M expected'", () => {
      expect(firedRuleTally({ detectionsExpected: [], detectionsFired: [], outcomes: [outcome('edr:x', 'blocked')] }))
        .toEqual({ fired: 1, expected: 0, exceeds: true, words: '1 fired, 0 expected' });
      expect(firedRuleTally({ detectionsExpected: ['siem:a'], detectionsFired: ['siem:a', 'siem:b'] }).words).toBe('2 fired, 1 expected');
    });

    it('expected counts distinct, trimmed, non-empty rules, as fired does', () => {
      expect(firedRuleTally({ detectionsExpected: ['siem:a', ' siem:a ', '', '  '], detectionsFired: ['siem:a'] }))
        .toEqual({ fired: 1, expected: 1, exceeds: false, words: null });
    });
  });

  it('ValidationService re-exports the same helper', () => {
    expect(reExported).toBe(firedRules);
  });

  describe('the run summary and the card count through it', () => {
    it('T1113, a passed run whose only rule is a blocked outcome: the summary says 1 and the card "1 rule fired"', () => {
      const r = run({ outcomes: [outcome('edr:x', 'blocked')] });
      expect(runInputs(r).summary.rulesFired).toBe(1);
      expect(cardLine([r])).toBe('Proven (your run) on 10/20/26 by manual; 1 rule fired');
    });

    it('both lists with overlap: the summary and the card count each rule once', () => {
      const r = run({ detectionsFired: ['siem:a', 'edr:x', ''], outcomes: [outcome('edr:x', 'blocked'), outcome(' siem:a ', 'alerted')] });
      expect(runInputs(r).summary.rulesFired).toBe(2);
      expect(cardLine([r])).toBe('Proven (your run) on 10/20/26 by manual; 2 rules fired');
    });

    it('the card counts the rules of the run it dates, not every standing record of every run', () => {
      // Two passed runs of different rules; the pill shows the newer run (1 of its rules fired).
      const older = run({ id: 'r0', runDate: '2026-10-18T10:00:00.000Z', detectionsFired: ['siem:old'] });
      const newer = run({ id: 'r1', detectionsFired: ['siem:new'] });
      expect(firedRuleCount(newer)).toBe(1);
      expect(cardLine([older, newer])).toBe('Proven (your run) on 10/20/26 by manual; 1 rule fired');
    });
  });
});
