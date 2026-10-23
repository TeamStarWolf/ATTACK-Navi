// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// THE count of a run's fired detection rules (RP-F decision 30b), and, beside the
// rules it expected, how that count is said (firedRuleTally, RP-F decision 33). Every surface
// that says how many rules a run fired counts through firedRules: the Validation
// pill ("N of M detection rules fired"), the Detection Validation workbench (its
// tiles and runs table), the run summary the evidence card reads (posture-adapters
// runInputs, RunSummary.rulesFired) and the card's Proven line (lens-explain
// proofExplain). Round 5 found a passed run whose only rule was in its outcomes
// (detectionsFired empty): the card said "1 rule fired" (it counted proof records,
// which include outcome rules) beside a pill reading "0 of 0" (it counted
// detectionsFired alone).

/** One outcome as firedRules reads it: a run's ValidationOutcome, or a ProofRecord. */
export interface FiredRuleOutcome {
  readonly detectionRef: string | null;
  readonly outcome: string;
}

/** What firedRules reads of a run. `outcomes` is absent on a v1-shaped run. */
export interface FiredRulesInput {
  readonly detectionsFired: readonly string[];
  readonly outcomes?: readonly FiredRuleOutcome[];
}

/**
 * The rules a run fired: the distinct, trimmed, non-empty union of its
 * detectionsFired and the detectionRef of every outcome that alerted or blocked,
 * in first-seen order (detectionsFired first). A 'logged' or 'none' outcome fired
 * nothing; a blank or duplicate id is one rule or none:
 *   detectionsFired [] and outcomes [{ detectionRef: 'edr:x', outcome: 'blocked' }] -> ['edr:x']
 *   detectionsFired ['siem:a', ' siem:a ', ''] and outcomes [{ 'siem:a', 'alerted' }] -> ['siem:a']
 */
export function firedRules(run: FiredRulesInput): string[] {
  const rules = new Set<string>();
  for (const d of run.detectionsFired) {
    const ref = typeof d === 'string' ? d.trim() : '';
    if (ref !== '') rules.add(ref);
  }
  for (const o of run.outcomes ?? []) {
    if (o.outcome !== 'alerted' && o.outcome !== 'blocked') continue;
    const ref = typeof o.detectionRef === 'string' ? o.detectionRef.trim() : '';
    if (ref !== '') rules.add(ref);
  }
  return [...rules];
}

/** How many rules a run fired: firedRules(run).length. */
export function firedRuleCount(run: FiredRulesInput): number {
  return firedRules(run).length;
}

/** What firedRuleTally reads of a run: firedRules' input plus the rules it expected. */
export interface FiredTallyInput extends FiredRulesInput {
  readonly detectionsExpected: readonly string[];
}

/**
 * A run's fired and expected rule counts, and how the pill and the workbench say them
 * (RP-F decision 33). `fired` is firedRuleCount; `expected` counts the distinct,
 * trimmed, non-empty detectionsExpected. When fired exceeds expected (rules known
 * only from outcomes, or fired rules nobody listed as expected), a fraction would read
 * as more than all: `exceeds` is true and `words` is 'N fired, M expected', which
 * every surface prints instead of 'N of M' or 'N/M'. Round 6 read a tile 'fired 2/1'
 * beside a pill 'UNTESTED 2 of 1'. Otherwise `words` is null and each surface keeps
 * its fraction.
 */
export interface FiredRuleTally {
  readonly fired: number;
  readonly expected: number;
  readonly exceeds: boolean;
  readonly words: string | null;
}

/** The fired and expected counts of a run, and the words for them when fired exceeds expected (RP-F decision 33). */
export function firedRuleTally(run: FiredTallyInput): FiredRuleTally {
  const fired = firedRuleCount(run);
  const expected = new Set(
    run.detectionsExpected.map(d => (typeof d === 'string' ? d.trim() : '')).filter(d => d !== ''),
  ).size;
  const exceeds = fired > expected;
  return { fired, expected, exceeds, words: exceeds ? `${fired} fired, ${expected} expected` : null };
}
