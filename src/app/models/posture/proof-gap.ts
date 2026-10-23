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

/**
 * The head of the Proven block and the Proven lens's why line when no proof stands:
 * NO_RECORDED_DETECTION, or 'No proof: 1 rule fired in your run on 10/15/26 (status
 * untested); a run is proof only when its status is passed'.
 */
export function provenNoneLine(state: Pick<PostureState, 'runsWithoutProof'>): string {
  const run = firedRunWithoutProof(state);
  return run ? `No proof: ${firedRunWords(run)}; ${reason(run)}` : NO_RECORDED_DETECTION;
}

/**
 * The Proven lens cell's words (aria-label and tooltip) when no proof stands, or
 * null to keep the 0 stop's own words ('no recorded detection'): 'no proof, 1 rule
 * fired in your run on 10/15/26 (status untested)', the same run the why line and
 * the Proven block name.
 */
export function provenNoneCellWords(state: Pick<PostureState, 'runsWithoutProof'>): string | null {
  const run = firedRunWithoutProof(state);
  return run ? `no proof, ${firedRunWords(run)}` : null;
}
