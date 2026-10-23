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

/** What firedRules reads of a run. `outcomes` is absent on a v1-shaped run; `attackResult` on a hand-built one. */
export interface FiredRulesInput {
  readonly detectionsFired: readonly string[];
  readonly outcomes?: readonly FiredRuleOutcome[];
  readonly attackResult?: string;
}

/**
 * The attack results that mean the attack did not execute (RP-F decisions 32 and 44):
 * Record Run's "Failed prerequisite" and "Errored", with their words. THE one table:
 * ValidationService's ATTACK_DID_NOT_EXECUTE is derived from it (attackDidNotExecute),
 * and the evidence card's runs line and the Covered block's not-credited line take
 * their words from it (notExecutedNote, attackResultWords). PR #241 round 1 found a
 * second table in ValidationService that only a spec kept in agreement.
 */
const NOT_EXECUTED: Readonly<Record<string, string>> = { 'failed-prereq': 'failed prerequisite', errored: 'errored' };

/** True when `attackResult` says the attack did not execute (failed-prereq, errored). */
export function attackDidNotExecute(attackResult: string | undefined): boolean {
  return attackResult !== undefined && Object.prototype.hasOwnProperty.call(NOT_EXECUTED, attackResult);
}

/** The words of a non-executed attack result: 'failed prerequisite', 'errored'; the result itself otherwise. */
export function attackResultWords(attackResult: string): string {
  return attackDidNotExecute(attackResult) ? NOT_EXECUTED[attackResult] : attackResult;
}

/** What the pill, the workbench tile and Run History say of a run whose attack did not execute (RP-F decision 44). */
export const NOT_EXECUTED_WORDS = 'attack did not execute';

/**
 * The note a run line carries for a run whose attack did not execute (RP-F decision 44):
 * 'attack did not execute: errored', 'attack did not execute: failed prerequisite'; null
 * for a run that executed (or names no result). The evidence card's runs line reads it.
 */
export function notExecutedNote(attackResult: string | undefined): string | null {
  return attackResult !== undefined && attackDidNotExecute(attackResult) ? `${NOT_EXECUTED_WORDS}: ${attackResultWords(attackResult)}` : null;
}

/**
 * A rule id as every rule comparison reads it (RP-F decision 40): trimmed and
 * case-insensitive, so 'WAZUH:306' and ' wazuh:306' are the rule 'wazuh:306'. The
 * fired set (firedRules), the expected-rules fraction (firedRuleTally), the proof
 * records and the range marks (posture-adapters), the proof supersession
 * (derive-posture sameRule) and the pill's range-run rules all compare through it.
 * PR #241 round 1: the pill read '1 of 1 expected rules fired, plus 1 unexpected' and
 * the Proven block '2 rules fired' for 'wazuh:306' fired and 'WAZUH:306' alerted.
 */
export function ruleKey(rule: string): string {
  return rule.trim().toLowerCase();
}

/**
 * The rules a run fired: the distinct, trimmed, non-empty union of its
 * detectionsFired and the detectionRef of every outcome that alerted or blocked,
 * in first-seen order (detectionsFired first), ids compared by ruleKey (trimmed,
 * case-insensitive; the first spelling seen is kept). A 'logged' or 'none' outcome fired
 * nothing; a blank or duplicate id is one rule or none:
 *   detectionsFired [] and outcomes [{ detectionRef: 'edr:x', outcome: 'blocked' }] -> ['edr:x']
 *   detectionsFired ['siem:a', ' siem:a ', ''] and outcomes [{ 'siem:a', 'alerted' }] -> ['siem:a']
 *   detectionsFired ['wazuh:306'] and outcomes [{ 'WAZUH:306', 'alerted' }] -> ['wazuh:306']
 * A run whose attack did not execute (attackResult failed-prereq or errored) fired
 * nothing (RP-F decision 44): its ticked or imported rules never count as fired, so no
 * surface shows a fired count or an alerted clause for it. Round 7 read "UNTESTED 2 of 2
 * expected rules fired" on a "Failed prerequisite" run with its rules ticked; round 8
 * read "the rule alerted in this run" on T1027.013, whose range run errored.
 */
export function firedRules(run: FiredRulesInput): string[] {
  if (attackDidNotExecute(run.attackResult)) return [];
  const rules = new Map<string, string>();
  const add = (d: unknown): void => {
    const ref = typeof d === 'string' ? d.trim() : '';
    if (ref !== '' && !rules.has(ruleKey(ref))) rules.set(ruleKey(ref), ref);
  };
  for (const d of run.detectionsFired) add(d);
  for (const o of run.outcomes ?? []) {
    if (o.outcome === 'alerted' || o.outcome === 'blocked') add(o.detectionRef);
  }
  return [...rules.values()];
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
 * - `expected` (M): the distinct non-empty detectionsExpected, by ruleKey;
 * - `matched` (k): the fired rules that were expected, |fired ∩ expected| by ruleKey;
 * - `unexpected` (n): the fired rules nobody listed as expected;
 * - `words`: 'k of M expected rules fired', plus ', plus n unexpected' when n > 0, or
 *   'N fired, none expected' when M = 0.
 * Expected [a, b] and fired [a, c] read '1 of 2 expected rules fired, plus 1
 * unexpected'. Decision 33's '2 fired, 1 expected' (round 6) and the plain 'N of M'
 * before it counted every fired rule against the expected ones, so expected [a, b]
 * with fired [a, c] read '2 of 2' (round 7).
 */
export interface FiredRuleTally {
  /** False when the attack did not execute (RP-F decision 44): then nothing fired and `words` names no fraction. */
  readonly executed: boolean;
  readonly fired: number;
  readonly expected: number;
  readonly matched: number;
  readonly unexpected: number;
  readonly words: string;
}

/** The distinct non-empty rules of a list by ruleKey (trimmed, case-insensitive). */
function distinctRuleKeys(list: readonly string[]): Set<string> {
  return new Set(list.map(d => (typeof d === 'string' ? ruleKey(d) : '')).filter(d => d !== ''));
}

/** A run's fired rules beside its expected ones, and the words for them (RP-F decision 38). */
export function firedRuleTally(run: FiredTallyInput): FiredRuleTally {
  const fired = firedRules(run);
  const expected = distinctRuleKeys(run.detectionsExpected);
  // RP-F decision 44: an attack that did not execute fired nothing; no fraction is said.
  if (attackDidNotExecute(run.attackResult)) {
    return { executed: false, fired: 0, expected: expected.size, matched: 0, unexpected: 0, words: NOT_EXECUTED_WORDS };
  }
  const matched = fired.filter(r => expected.has(ruleKey(r))).length;
  const unexpected = fired.length - matched;
  const words = expected.size === 0
    ? `${fired.length} fired, none expected`
    : `${matched} of ${expected.size} expected rules fired${unexpected > 0 ? `, plus ${unexpected} unexpected` : ''}`;
  return { executed: true, fired: fired.length, expected: expected.size, matched, unexpected, words };
}
