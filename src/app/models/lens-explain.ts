// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// "Why this colour" (Phase 2 design §3 P2-18, E2.3-b): one sentence that says
// why a technique's cell has the colour it has on the lens on screen.
//
// - A registry lens (P2-13 to P2-15) explains from the technique's
//   PostureState and the cell its own `project` returns, so the words follow
//   the same data the cell is painted from.
// - A legacy lens (scored by the matrix switchboard) says
//   'score N of max M: <formula>', composed from the lens's own `formula`.
//
// Every rung word comes from the vocabulary module (postureBadge, proofLine,
// PROVEN through them); this file holds no rung-word literal, so the
// truth-vocabulary lint needs no allow here.
import type { LensCell, LensDefinition } from './heatmap-modes';
import type { CoveredBasis, CoveredMark, PostureState, ProofRecord, ProofScope, RunSummary } from './posture/posture.types';
import { PROVEN, postureBadge } from './posture/posture-vocabulary';
import { SCORE_ONLY_LENSES } from './lens-registry';
import { CONTRADICTED_WORDS, paintedTelemetryWords } from './posture/posture-ramp';
import { validationDay } from './local-date';
import { provenNoneLine } from './posture/proof-gap';
import { firedRuleCount } from './posture/fired-rules';
import { partialReason } from './posture/partial-cause';

/**
 * The head of the Proven block and the Proven lens when no proof stands (RP-F
 * decision 28), from proof-gap.ts: the Proven lens cell's aria-label and tooltip
 * name the same run (postureCellLabel), so the cell, the why line and the card agree.
 */
export { provenNoneLine };

/** The five Known reference families (EnrichmentService.referenceSignalCount). */
export const KNOWN_FAMILY_COUNT = 5;

/** The evidence card's Known block, as the Covered lens's None line names it. */
const KNOWN_BLOCK = 'Known';

/** What lensExplain reads besides the lens and its cell. */
export interface LensExplainContext {
  /** The technique's PostureState (PostureService.stateFor). */
  readonly state: PostureState;
  /** Legacy lenses: the highest score in the loaded domain, when the matrix scored the lens; else absent. */
  readonly max?: number | null;
  /** The D10 proof windows in days (PostureService.decayDays); a stale line names its window. */
  readonly decayDays?: Readonly<Record<ProofScope, number>>;
}

/** Plain words for each CoveredBasis (the Covered block and the Covered lines below). */
const BASIS_WORDS: Readonly<Record<CoveredBasis, string>> = {
  'capability-confirmed': 'capability confirmed',
  'rule-deployed': 'rule deployed',
  'mitigation-implemented': 'mitigation implemented',
  'control-implemented': 'control implemented',
  'technique-confirmed': 'technique confirmed',
  'telemetry-configured': 'telemetry configured',
  'own-run-blocked': 'blocked in your run, no named rule',
  'range-deployed': 'deployed in the range',
  'range-detection-authored': 'detection authored in the range',
  'range-telemetry-observed': 'telemetry observed in the range',
};

/** The words for one mark's basis. */
export function basisWords(basis: CoveredBasis): string {
  return BASIS_WORDS[basis] ?? basis;
}

/** A number as the card prints it: whole numbers as they are, others to two decimals. */
export function formatScore(n: number): string {
  return Number.isInteger(n) ? String(n) : String(Math.round(n * 100) / 100);
}

/** 'mitigation implemented via M1036, technique confirmed via M1038': the distinct basis and via of `marks`. */
function describeMarks(marks: readonly CoveredMark[]): string {
  const parts: string[] = [];
  for (const m of marks) {
    const part = basisWords(m.basis) + (m.via ? ` via ${m.via}` : '');
    if (!parts.includes(part)) parts.push(part);
  }
  return parts.join(', ');
}

/** Where the runs of yours are listed in full (the Detection Validation workbench). */
const SEE_VALIDATION = 'see Detection Validation';

/**
 * How many rules the best record's run fired (RP-F decision 30b): the run's own
 * firedRules count, which runInputs puts on each of its records (runRulesFired, the
 * same number as the run's RunSummary.rulesFired and the Validation pill's count).
 * It is never a count of the records that stand: per-rule supersession (decision 29)
 * can remove one record of a run and leave its others standing, and the Proven line
 * still names the run's own count. A hand-built record without runRulesFired counts
 * the distinct rules of the standing records of that same run (never of other runs).
 * Round 5 counted the standing records of the best record's run; main, before it,
 * the distinct rules of every standing record of every run.
 */
function rulesFired(best: ProofRecord, proof: readonly ProofRecord[]): number {
  if (typeof best.runRulesFired === 'number') return best.runRulesFired;
  return firedRuleCount({ detectionsFired: [], outcomes: proof.filter(p => p.runId === best.runId) });
}

/**
 * The best proof record's line: '<badge> on <date> by <source>; N rule(s) fired',
 * then the newest later run that left the proof standing (laterRunClause, RP-F
 * decision 29), so a Proven cell never hides a newer run the pill shows.
 */
function proofExplain(state: PostureState, decayDays?: Readonly<Record<ProofScope, number>>): string {
  const best = state.proof[0];
  const n = rulesFired(best, state.proof);
  let line = `${postureBadge(state)} on ${validationDay(best.date)} by ${best.source}; ${n} rule${n === 1 ? '' : 's'} fired`;
  if (state.bucket === 'stale' && decayDays && state.proofScope) {
    line += `; older than its ${decayDays[state.proofScope]}-day window`;
  }
  const later = laterRunClause(state);
  return later ? `${line}; ${later}` : line;
}

/** What a later run that left the proof standing did, on `day` (RP-F decision 29). */
function laterRunWords(run: RunSummary, day: string): string {
  if (run.status === 'partial') {
    // A range row maps 'telemetry-observed' to partial (statusForRow); an own run is
    // partial when some expected rule did not fire.
    return run.source.startsWith('lylat-range:') ? `a later run on ${day} observed telemetry only` : `a later partial run on ${day}`;
  }
  if (run.status === 'untested') return `a later untested run on ${day}`;
  if (run.status === 'no-telemetry') return `a later run on ${day} had no telemetry`;
  if (run.status === 'failed') return `a later run of another rule failed on ${day}`;
  // Only after a removed proof (laterRuns lists no passed run while proof stands): a
  // passed run newer than the remover holds no qualifying record of its own.
  if (run.status === 'passed') return `a later run passed on ${day} with no proof record`;
  return `a later run of another rule was ${run.status.replace(/-/g, ' ')} on ${day}`;
}

/**
 * The newest run of yours later than every standing proof record that left it
 * standing (PostureState.laterRuns, RP-F decision 29: proof supersession is per
 * rule, and an untested, partial or no-telemetry run, or a run of another rule, never
 * removes proof): 'a later run on 10/21/26 observed telemetry only', 'a later
 * untested run on 10/21/26', 'a later run of another rule failed on 10/21/26', with
 * '(N more later runs; see Detection Validation)' when there are more; '' with none.
 * The days are the local days the Detection Validation pill prints.
 */
export function laterRunClause(state: Pick<PostureState, 'laterRuns'>): string {
  return laterRunsWords(state.laterRuns ?? [], true);
}

/** The newest of `runs` in words, then '(N more later runs)', with '; see Detection Validation' inside when `see`. */
function laterRunsWords(runs: readonly RunSummary[], see: boolean): string {
  if (runs.length === 0) return '';
  const words = laterRunWords(runs[0], validationDay(runs[0].date));
  const more = runs.length - 1;
  return more > 0 ? `${words} (${more} more later run${more === 1 ? '' : 's'}${see ? `; ${SEE_VALIDATION}` : ''})` : words;
}

const CONTRADICTED_NOTE = '; a later failed run contradicts the marks';
const EXCLUDED_NOTE = '; not reproducible, so left out of the denominator';

/**
 * True when a later failed run outranks the technique's full marks: the state is
 * contradicted, and not only because a later run outranked its proof. A state contradicted
 * only because a later run outranked its proof (supersededProof, RP-F decision 16)
 * has no marks to name, so the marks note stays out of its lines.
 */
function marksContradicted(state: PostureState): boolean {
  return state.subStates.includes('contradicted')
    && (!state.supersededProof || state.covered.some(m => m.strength === 'full'));
}

/** The notes every posture line ends with: a contradicting run, an excluded technique. */
function postureNotes(state: PostureState): string {
  let notes = '';
  if (marksContradicted(state)) notes += CONTRADICTED_NOTE;
  if (state.excluded) notes += EXCLUDED_NOTE;
  return notes;
}

/**
 * True when the owner has recorded something about the technique that holds no
 * rung: a full mark a later failed run contradicts, or a not-reproducible verdict.
 * A None line must not then say nothing of theirs is recorded (RP-F round 1).
 */
function ownerRecordWithoutRung(state: PostureState): boolean {
  return state.subStates.includes('contradicted') || state.excluded;
}

/**
 * What the run that removed the proof did, as the superseded clause says it:
 * 'failed' or 'was not reproducible'. Only those two statuses remove proof (RP-F
 * decision 29, REMOVING_STATUSES in derive-posture.ts); an untested, partial or
 * no-telemetry run never does, and is named by laterRunClause instead.
 */
function latestRunWords(status: string): string {
  return status === 'failed' ? 'failed' : `was ${status.replace(/-/g, ' ')}`;
}

/**
 * What the outranked earlier run was, by its own status (RP-F round 3): 'run passed',
 * 'run was partial', 'run was untested', 'run was not reproducible'; with no run of
 * that id listed, only what the record holds: 'named rule fired'.
 */
function earlierRunWords(status: string | null): string {
  if (status === null) return 'named rule fired';
  if (status === 'passed') return 'run passed';
  return `run was ${status.replace(/-/g, ' ')}`;
}

/**
 * The run that outranked every proof record (RP-F decisions 16 and 29):
 * 'contradicted: latest run of the rule failed on 10/22/26; an earlier run passed on 10/21/26',
 * the earlier run named by its own status ('an earlier run was partial on ...'),
 * or '' when none did. It is the latest run OF THAT RULE (supersession is per rule),
 * so when a newer run of yours left nothing to remove (an untested or partial run,
 * a run of another rule), the clause names the newest one after it, as the proven
 * line does (laterRunClause): '...; an earlier run passed on 10/21/26; a later
 * untested run on 10/23/26' (RP-F round 4 repair: the pill shows that newer run).
 * 'contradicted: ' leads while the state is contradicted (the cell paints the
 * hatch, so its words say so, RP-F decision 17); a not-reproducible remover reads
 * 'latest run of the rule was not reproducible on ...' and contradicts nothing. The
 * days are the local days the Detection Validation pill prints.
 * A run that names no rule (a manual run recorded without a rule id, which decision 29
 * matches on source plus technique) is never called a run "of the rule" (RP-F decision
 * 39): 'latest run failed, no rule named, on 10/22/26; an earlier run passed on ...'.
 */
export function supersededClause(state: Pick<PostureState, 'supersededProof' | 'subStates' | 'laterRuns'>): string {
  const s = state.supersededProof;
  if (!s) return '';
  const later = laterRunsWords(state.laterRuns ?? [], false);
  const day = validationDay(s.latest.date);
  const latest = (s.latest.rules ?? []).length > 0
    ? `latest run of the rule ${latestRunWords(s.latest.status)} on ${day}`
    : `latest run ${latestRunWords(s.latest.status)}, no rule named, on ${day}`;
  return (state.subStates.includes('contradicted') ? 'contradicted: ' : '')
    + `${latest}; `
    + `an earlier ${earlierRunWords(s.earlierStatus)} on ${validationDay(s.earlier.date)}`
    + (later ? `; ${later}` : '');
}

/**
 * The runs of yours on the technique that yield no proof (RP-F decision 9):
 * '1 run of yours recorded, latest untested on 10/21/26', or '' with none.
 * It names the run's status and date only, never a rung: a run without a named
 * rule is not Proven, and nothing here says it covers the technique. When the
 * latest run of a rule outranked an earlier proof (RP-F decisions 16 and 29) it says that instead:
 * 'contradicted: latest run of the rule failed on 10/22/26; an earlier run passed on 10/21/26'.
 */
export function runsClause(state: Pick<PostureState, 'runsWithoutProof' | 'supersededProof' | 'subStates' | 'laterRuns'>): string {
  const superseded = supersededClause(state);
  if (superseded) return superseded;
  const runs = state.runsWithoutProof;
  if (runs.length === 0) return '';
  const latest = runs[0];
  return `${runs.length} run${runs.length === 1 ? '' : 's'} of yours recorded, latest ${latest.status} on ${validationDay(latest.date)}`;
}

/** '; <runsClause>; see Detection Validation', or '' with no run without proof. */
function runsNote(state: PostureState): string {
  const runs = runsClause(state);
  return runs ? `; ${runs}; ${SEE_VALIDATION}` : '';
}

/** runsNote when a later run outranked the proof (RP-F decision 16); '' otherwise (a Covered or partial line names no other run). */
function supersededNote(state: PostureState): string {
  return state.supersededProof ? runsNote(state) : '';
}

/**
 * The Posture lens: the technique's own rung, from its PostureState.
 *   'Proven (your run) on 10/21/26 by manual; 1 rule fired'
 *   'Covered (self-attested) from mitigation implemented via M1036'
 *   'Covered (self-attested, partial via M1038): reached only through a mitigation or control mapped to more techniques than the breadth threshold'
 *   'Covered (range, partial via wazuh:5) from range telemetry observed via wazuh:5: partial, no detection alerted'   (RP-F decision 31)
 *   'Known: mapped (3 of 5 reference families)'
 *   'Known: mapped (3 of 5 reference families); 1 run of yours recorded, latest passed on 10/21/26; see Detection Validation'
 *   'None: no reference data mapped and nothing of yours recorded'
 *   'None: no reference data mapped; 1 run of yours recorded, latest untested on 10/21/26; see Detection Validation'
 *   'None: no reference data mapped; a later failed run contradicts the marks'   (a contradicted mark or an excluded technique)
 */
export function postureExplain(state: PostureState, decayDays?: Readonly<Record<ProofScope, number>>): string {
  switch (state.bucket) {
    case 'proven':
    case 'stale':
      return proofExplain(state, decayDays) + postureNotes(state);
    case 'covered': {
      const marks = describeMarks(state.covered.filter(m => m.strength === 'full'));
      return postureBadge(state) + (marks ? ` from ${marks}` : '') + supersededNote(state) + postureNotes(state);
    }
    case 'partial':
      // RP-F decision 31: the reason follows the marks' typed cause (breadth or range
      // telemetry), never the threshold sentence for a telemetry-observed range row.
      return postureBadge(state) + partialReason(state) + supersededNote(state) + postureNotes(state);
    case 'known':
      return `${postureBadge(state)} (${state.knownSignals} of ${KNOWN_FAMILY_COUNT} reference families)` + runsNote(state) + postureNotes(state);
    default: {
      const runs = runsNote(state);
      if (runs) return 'None: no reference data mapped' + runs + postureNotes(state);
      return (ownerRecordWithoutRung(state) ? 'None: no reference data mapped' : 'None: no reference data mapped and nothing of yours recorded')
        + postureNotes(state);
    }
  }
}

/**
 * The Covered lens on a technique with no covered mark (RP-F item 2). The cell
 * is None on this lens, but the same card can list a recorded run or Known
 * reference data, so the line says which block holds it rather than claiming
 * nothing of the user's reaches the technique:
 *   'None: no covered (self-attested or range) mark; see the Proven block for its recorded result'
 *   'None: no covered (self-attested or range) mark; see the Known block for its reference data (3 of 5 reference families)'
 *   'None: a later failed run contradicts your covered (self-attested or range) marks'   (RP-F round 1)
 *   'None: no covered (self-attested or range) mark; not reproducible, so left out of the denominator'
 *   'None: no covered (self-attested or range) mark; 1 run of yours recorded, latest failed on 10/21/26; see Detection Validation'
 *   'None: nothing of yours reaches this technique'   (no run, no reference data, no mark, no verdict)
 * A run of yours that yields no proof (untested, failed, passed with no named
 * rule) is named with its status and date (RP-F decision 9), never as a rung.
 * A contradicted full mark or a not-reproducible verdict is the owner's own record,
 * so it is named instead of 'nothing of yours'; a contradicted mark is the head,
 * never 'no covered mark' followed by a note about 'the marks'.
 * The Covered lens is only on screen while owner words may render
 * (lensOnScreen), so the Covered words here are always gated on hasOwnerWords.
 * A stale run counts: it is still listed in the Proven block.
 */
function coveredNoneExplain(state: PostureState): string {
  const head = marksContradicted(state)
    ? 'None: a later failed run contradicts your covered (self-attested or range) marks'
    : 'None: no covered (self-attested or range) mark';
  const notes = state.excluded ? EXCLUDED_NOTE : '';
  if (state.proof.length > 0) return `${head}; see the ${PROVEN} block for its recorded result` + notes;
  if (state.knownSignals > 0) {
    return `${head}; see the ${KNOWN_BLOCK} block for its reference data (${state.knownSignals} of ${KNOWN_FAMILY_COUNT} reference families)`
      + runsNote(state) + notes;
  }
  if (state.runsWithoutProof.length > 0 || ownerRecordWithoutRung(state)) return head + runsNote(state) + notes;
  return 'None: nothing of yours reaches this technique';
}

/**
 * '; <how the state is contradicted>' for a lens whose own words do not already
 * say it (RP-F decision 17: a cell that paints or speaks the contradicted hatch
 * says so in its why line too): the run that outranked the proof (supersededClause,
 * which leads with 'contradicted: '), else 'contradicted by a later failed run'.
 * A not-reproducible run of the rule that removed the proof is named though it
 * contradicts nothing (only failed and not-reproducible runs remove proof, RP-F
 * decision 29); '' for a state with neither.
 */
function contradictionNote(state: PostureState): string {
  const superseded = supersededClause(state);
  if (superseded) return `; ${superseded}`;
  return state.subStates.includes('contradicted') ? `; ${CONTRADICTED_WORDS}` : '';
}

/**
 * '; not reproducible, so left out of the denominator' for an excluded state, or ''.
 * The Covered and Proven lenses paint the not-reproducible cross-hatch from the
 * same sub-state, so their why lines say it too (paints implies speaks, RP-F
 * decision 27); round 4 found only the Posture why line naming it on T1082.
 */
function exclusionNote(state: PostureState): string {
  return state.excluded ? EXCLUDED_NOTE : '';
}

/** A registry lens other than Posture: its cell's own words, with the marks or proof behind them. */
function registryExplain(def: LensDefinition, cell: LensCell, ctx: LensExplainContext): string {
  const { state } = ctx;
  if (def.value === 'posture') return postureExplain(state, ctx.decayDays);
  if (def.value === 'proven') {
    if (cell.score > 0 && state.proof.length > 0) return proofExplain(state, ctx.decayDays);
    return provenNoneLine(state) + contradictionNote(state) + exclusionNote(state);
  }
  if (def.value === 'covered') {
    if (cell.score === 2) {
      return `${cell.label} from ${describeMarks(state.covered.filter(m => m.strength === 'full'))}` + exclusionNote(state);
    }
    if (cell.score === 1) {
      // RP-F decision 31: by the partial marks' typed cause, as the Posture line says it.
      return `${cell.label}${partialReason(state)}` + contradictionNote(state) + exclusionNote(state);
    }
    return coveredNoneExplain(state);
  }
  // Status draws no hatch, but its stop comes from the marks a later failed run
  // contradicts, so its line names the contradiction (RP-F decision 17). A partial stop
  // beside a range telemetry partial names the telemetry clause its aria-label and tooltip
  // carry (paintedTelemetryWords, RP-F decision 40).
  if (def.value === 'status') {
    const telemetry = paintedTelemetryWords(state, { bucket: cell.bucket ?? 'none', subStates: cell.subStates ?? [] });
    return (cell.label ?? '') + (telemetry ? `, ${telemetry}` : '') + contradictionNote(state);
  }
  return cell.label ?? `score ${formatScore(cell.score)}`;
}

/**
 * Why `cell` has its colour on lens `def`.
 * - Registry lenses (def.project) explain from PostureState and the projected cell.
 * - A score-only registry lens (Reference depth) and every legacy lens say
 *   'score N of max M: <formula>'; a legacy lens the matrix has not scored in
 *   this session (no cell, or no max) says how its score is computed instead.
 */
export function lensExplain(def: LensDefinition, cell: LensCell | null, ctx: LensExplainContext): string {
  if (def.project && cell && !SCORE_ONLY_LENSES.has(def.value)) return registryExplain(def, cell, ctx);
  const max = SCORE_ONLY_LENSES.has(def.value) ? 100 : ctx.max;
  if (cell && typeof max === 'number') {
    return `score ${formatScore(cell.score)} of max ${formatScore(max)}: ${def.formula}`;
  }
  return `not scored on the matrix in this session; ${def.formula}`;
}
