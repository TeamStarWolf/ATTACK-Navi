// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// What the Proven block, the Proven lens's why line and the Proven lens's cell
// (aria-label and tooltip) say when no proof stands (RP-F decision 28): "No
// recorded detection for this technique", unless a run of yours lists a fired
// rule, which the Validation pill shows ("UNTESTED 1 of 0 detection rules
// fired", "range-run rules: siem:curated"). Then the run is named with its day
// and status instead, on every one of those surfaces, so the cell never says
// "no recorded detection" while its card and pill say a rule fired (round 4,
// S12 T1018, S13 T1082, S27 T1059.001).
//
// Whether a status proves is read from PROVING_STATUSES (derive-posture), the
// one allow-list (RP-F decision 23); nothing here compares a status literal.
// Every rung word stays out: these lines name a status and a day, never a rung.
import type { PostureState, RunSummary } from './posture.types';
import { PROVING_STATUSES, provesStatus } from './derive-posture';
import { runTime, validationDay } from '../local-date';

/** The Proven lens's 0 stop, and the Proven block's line when no run of yours fired a rule. */
export const NO_RECORDED_DETECTION = 'No recorded detection for this technique';

/**
 * The newest run of yours that lists a fired rule yet yields no proof, or null.
 * runsWithoutProof is newest first (the one latest-run comparator) and holds every
 * run without a qualifying proof record: one whose status is not on
 * PROVING_STATUSES, and one whose status proves but whose proof a later run
 * outranked or whose date cannot be read.
 */
export function firedRunWithoutProof(state: Pick<PostureState, 'runsWithoutProof'>): RunSummary | null {
  return state.runsWithoutProof.find(r => (r.rulesFired ?? 0) > 0) ?? null;
}

/** 'passed' (or 'passed or partial'): the statuses on PROVING_STATUSES, as the lines name them. */
export function provingStatusWords(): string {
  return [...PROVING_STATUSES].join(' or ');
}

/**
 * Why `run`, which fired a rule, is not proof:
 * - its status is not on PROVING_STATUSES: 'a run is proof only when its status is passed';
 * - its date cannot be read: 'a run is proof only with a readable date';
 * - otherwise a later run outranked its proof: 'a later run outranks it'.
 */
function reason(run: RunSummary): string {
  if (!provesStatus(run.status)) return `a run is proof only when its status is ${provingStatusWords()}`;
  if (runTime(run.date) === null) return 'a run is proof only with a readable date';
  return 'a later run outranks it';
}

/**
 * Whose run it was, by its source (RP-F decision 35): 'your run' only for a run you
 * recorded (source 'manual'), 'the range run' for a run imported from a range contract
 * ('lylat-range:<mission>'), else 'the imported run'. Round 7 called a range row
 * 'your run' on T1082.
 */
export function runSourceWords(source: string): string {
  if (source === 'manual') return 'your run';
  return source.startsWith('lylat-range:') ? 'the range run' : 'the imported run';
}

/** 'N rule(s) fired in your run on <day> (status <status>)', or 'in the range run' for a range row. */
function firedRunWords(run: RunSummary): string {
  const n = run.rulesFired as number;
  return `${n} rule${n === 1 ? '' : 's'} fired in ${runSourceWords(run.source)} on ${validationDay(run.date)} (status ${run.status})`;
}

/** 'run' or 'runs' after a count. */
function runsWord(n: number): string {
  return n === 1 ? 'run' : 'runs';
}

/** A run that fired no rule, as the Proven block names it: 'no rule fired in the range run on <day> (status <status>)'. */
function quietRunWords(run: RunSummary): string {
  return `no rule fired in ${runSourceWords(run.source)} on ${validationDay(run.date)} (status ${run.status})`;
}

/** One other run of the same day: its status, and its fired count when it fired a rule: 'partial (1 rule fired)'. */
function sameDayRunWords(run: RunSummary): string {
  const n = run.rulesFired ?? 0;
  return n > 0 ? `${run.status} (${n} rule${n === 1 ? '' : 's'} fired)` : run.status;
}

/**
 * What the Proven block says when no proof stands (RP-F decisions 28 and 41), in parts:
 * - `head`: the LATEST run without proof by the one latest-run comparator (RP-F decision
 *   24: on the same instant the run that proves less first, then by id), the run the
 *   Validation pill shows: 'N rule(s) fired in the range run on <day> (status <status>)',
 *   or 'no rule fired in ...' when it fired none;
 * - `sameDay`: the other runs of that day, by count and status: 'and 1 more run the same
 *   day: partial (1 rule fired)';
 * - `earlier`: the newest earlier run that fired a rule, when the latest fired none and
 *   no run of its day did: 'earlier, 1 rule fired in your run on <day> (status untested)';
 * - `reason`: why the run that fired is not proof.
 * Null when no run without proof fired a rule: the block then says NO_RECORDED_DETECTION.
 * Round 8 (T1005) named a partial run that fired wazuh:207 while the pill named the
 * untested run of the same day: two runs on two surfaces.
 */
function noProofParts(state: Pick<PostureState, 'runsWithoutProof'>): { head: string; sameDay: string; earlier: string; reason: string } | null {
  const fired = firedRunWithoutProof(state);
  if (fired === null) return null;
  const [latest, ...rest] = state.runsWithoutProof;
  const day = validationDay(latest.date);
  const others = rest.filter(r => validationDay(r.date) === day);
  const head = (latest.rulesFired ?? 0) > 0 ? firedRunWords(latest) : quietRunWords(latest);
  const sameDay = others.length > 0
    ? `and ${others.length} more ${runsWord(others.length)} the same day: ${others.map(sameDayRunWords).join(', ')}`
    : '';
  const earlier = fired !== latest && !others.includes(fired) ? `earlier, ${firedRunWords(fired)}` : '';
  return { head, sameDay, earlier, reason: reason(fired) };
}

/**
 * The head of the Proven block and the Proven lens's why line when no proof stands:
 * NO_RECORDED_DETECTION, or 'No proof: 1 rule fired in your run on 10/15/26 (status
 * untested); a run is proof only when its status is passed', naming the run the pill
 * shows (RP-F decision 41): 'No proof: no rule fired in the range run on 10/21/26 (status
 * untested); and 1 more run the same day: partial (1 rule fired); a run is proof only
 * when its status is passed'.
 */
export function provenNoneLine(state: Pick<PostureState, 'runsWithoutProof'>): string {
  const p = noProofParts(state);
  if (p === null) return NO_RECORDED_DETECTION;
  return `No proof: ${[p.head, p.sameDay, p.earlier, p.reason].filter(s => s !== '').join('; ')}`;
}

/**
 * The Proven lens cell's words (aria-label and tooltip) when no proof stands, or
 * null to keep the 0 stop's own words ('no recorded detection'): 'no proof, 1 rule
 * fired in your run on 10/15/26 (status untested)', the same run the why line, the
 * Proven block and the pill name (RP-F decision 41), with the same-day and earlier runs.
 */
export function provenNoneCellWords(state: Pick<PostureState, 'runsWithoutProof'>): string | null {
  const p = noProofParts(state);
  if (p === null) return null;
  return `no proof, ${[p.head, p.sameDay, p.earlier].filter(s => s !== '').join(', ')}`;
}

