// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 30b: one fired-rule count. firedRules is the distinct, trimmed,
// non-empty union of detectionsFired and the rules of alerted or blocked outcomes;
// the run summary (posture-adapters) and the card's Proven line (lens-explain) count
// through it, as the Validation pill does (validation-status-pill.component.spec.ts).
import { attackDidNotExecute, attackResultWords, firedRuleCount, firedRules, firedRuleTally } from './fired-rules';
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

  // RP-F decision 38: the fraction counts EXPECTED rules that fired (k of M), names the
  // unexpected ones (n) beside it, and reads 'N fired, none expected' when nothing was
  // expected. Round 7: expected [a, b] with fired [a, c] read '2 of 2' (decision 33
  // counted every fired rule against the expected ones).
  // RP-F decision 44: a run whose attack did not execute (failed-prereq, errored) fired
  // nothing, whatever its lists say; the tally names no fraction.
  describe('a run whose attack did not execute (RP-F decision 44)', () => {
    for (const attackResult of ['failed-prereq', 'errored']) {
      it(`${attackResult}: no fired rule, no fraction, 'attack did not execute'`, () => {
        const run = { attackResult, detectionsExpected: ['a', 'b'], detectionsFired: ['a', 'b'], outcomes: [{ detectionRef: 'a', outcome: 'alerted' }] };
        expect(firedRules(run)).toEqual([]);
        expect(firedRuleTally(run)).toEqual({ executed: false, fired: 0, expected: 2, matched: 0, unexpected: 0, words: 'attack did not execute' });
        expect(attackDidNotExecute(attackResult)).toBeTrue();
      });
    }

    it('executed and blocked attacks fire as before; the words of each non-executed result', () => {
      for (const attackResult of ['executed', 'blocked', undefined]) {
        expect(firedRules({ attackResult, detectionsFired: ['a'] })).toEqual(['a']);
        expect(attackDidNotExecute(attackResult)).toBeFalse();
      }
      expect(attackResultWords('failed-prereq')).toBe('failed prerequisite');
      expect(attackResultWords('errored')).toBe('errored');
      expect(attackResultWords('executed')).toBe('executed');
    });
  });

  describe('firedRuleTally (RP-F decision 38)', () => {
    it("expected [a, b], fired [a, c]: '1 of 2 expected rules fired, plus 1 unexpected'", () => {
      expect(firedRuleTally({ detectionsExpected: ['a', 'b'], detectionsFired: ['a', 'c'] }))
        .toEqual({ executed: true, fired: 2, expected: 2, matched: 1, unexpected: 1, words: '1 of 2 expected rules fired, plus 1 unexpected' });
    });

    it("expected [a], fired [a, c]: '1 of 1 expected rules fired, plus 1 unexpected'", () => {
      expect(firedRuleTally({ detectionsExpected: ['a'], detectionsFired: ['a', 'c'] }))
        .toEqual({ executed: true, fired: 2, expected: 1, matched: 1, unexpected: 1, words: '1 of 1 expected rules fired, plus 1 unexpected' });
    });

    it("expected none, fired [x]: '1 fired, none expected'; a rule known only from an outcome counts", () => {
      expect(firedRuleTally({ detectionsExpected: [], detectionsFired: ['x'] }))
        .toEqual({ executed: true, fired: 1, expected: 0, matched: 0, unexpected: 1, words: '1 fired, none expected' });
      expect(firedRuleTally({ detectionsExpected: [], detectionsFired: [], outcomes: [outcome('edr:x', 'blocked')] }).words).toBe('1 fired, none expected');
      expect(firedRuleTally({ detectionsExpected: [], detectionsFired: [] }).words).toBe('0 fired, none expected');
    });

    it("an exact match reads 'M of M expected rules fired'; a missing expected rule is never counted as fired", () => {
      expect(firedRuleTally({ detectionsExpected: ['a', 'b'], detectionsFired: ['b', 'a'] }).words).toBe('2 of 2 expected rules fired');
      expect(firedRuleTally({ detectionsExpected: ['a', 'b'], detectionsFired: ['a'] }).words).toBe('1 of 2 expected rules fired');
      expect(firedRuleTally({ detectionsExpected: ['a'], detectionsFired: [] }).words).toBe('0 of 1 expected rules fired');
      // Expected [a, b], fired a and c: never '2 of 2'.
      expect(firedRuleTally({ detectionsExpected: ['a', 'b'], detectionsFired: ['a'], outcomes: [outcome('c', 'alerted')] }).words)
        .not.toContain('2 of 2');
    });

    it('blanks and duplicates collapse on both lists', () => {
      expect(firedRuleTally({ detectionsExpected: ['siem:a', ' siem:a ', '', '  ', 'siem:b'], detectionsFired: ['siem:a', ' siem:a', ''], outcomes: [outcome('siem:a', 'alerted'), outcome(' ', 'blocked')] }))
        .toEqual({ executed: true, fired: 1, expected: 2, matched: 1, unexpected: 0, words: '1 of 2 expected rules fired' });
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
