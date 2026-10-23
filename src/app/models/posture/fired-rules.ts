// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// THE count of a run's fired detection rules (RP-F decision 30b), and, beside the
// rules it expected, how that count is said (firedRuleTally, RP-F decision 38). Every surface
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
 * A run's fired rules beside the rules it expected, and how the pill, the workbench
 * tile and Run History say them (RP-F decision 38). The fraction counts EXPECTED
 * rules that fired, so it can never read as all expected rules firing when one did
 * not:
 * - `fired`: every rule the run fired (firedRuleCount);
 * - `expected` (M): the distinct, trimmed, non-empty detectionsExpected;
 * - `matched` (k): the fired rules that were expected, |fired ∩ expected|;
 * - `unexpected` (n): the fired rules nobody listed as expected;
 * - `words`: 'k of M expected rules fired', plus ', plus n unexpected' when n > 0, or
 *   'N fired, none expected' when M = 0.
 * Expected [a, b] and fired [a, c] read '1 of 2 expected rules fired, plus 1
 * unexpected'. Decision 33's '2 fired, 1 expected' (round 6) and the plain 'N of M'
 * before it counted every fired rule against the expected ones, so expected [a, b]
 * with fired [a, c] read '2 of 2' (round 7).
 */
export interface FiredRuleTally {
  readonly fired: number;
  readonly expected: number;
  readonly matched: number;
  readonly unexpected: number;
  readonly words: string;
}

/** The distinct, trimmed, non-empty rules of a list, in first-seen order. */
function distinctRules(list: readonly string[]): string[] {
  return [...new Set(list.map(d => (typeof d === 'string' ? d.trim() : '')).filter(d => d !== ''))];
}

/** A run's fired rules beside its expected ones, and the words for them (RP-F decision 38). */
export function firedRuleTally(run: FiredTallyInput): FiredRuleTally {
  const fired = firedRules(run);
  const expected = new Set(distinctRules(run.detectionsExpected));
  const matched = fired.filter(r => expected.has(r)).length;
  const unexpected = fired.length - matched;
  const words = expected.size === 0
    ? `${fired.length} fired, none expected`
    : `${matched} of ${expected.size} expected rules fired${unexpected > 0 ? `, plus ${unexpected} unexpected` : ''}`;
  return { fired: fired.length, expected: expected.size, matched, unexpected, words };
}
