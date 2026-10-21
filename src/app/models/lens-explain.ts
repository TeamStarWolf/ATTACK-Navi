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
import type { CoveredBasis, CoveredMark, PostureState, ProofRecord, ProofScope } from './posture/posture.types';
import { PROVEN, postureBadge } from './posture/posture-vocabulary';
import { SCORE_ONLY_LENSES } from './lens-registry';

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

/** The distinct detection references of a state's proof: the rules that fired or blocked. */
function rulesFired(proof: readonly ProofRecord[]): number {
  return new Set(proof.map(p => p.detectionRef)).size;
}

/** The best proof record's line: '<badge> on <date> by <source>; N rule(s) fired'. */
function proofExplain(state: PostureState, decayDays?: Readonly<Record<ProofScope, number>>): string {
  const best = state.proof[0];
  const n = rulesFired(state.proof);
  let line = `${postureBadge(state)} on ${best.date.slice(0, 10)} by ${best.source}; ${n} rule${n === 1 ? '' : 's'} fired`;
  if (state.bucket === 'stale' && decayDays && state.proofScope) {
    line += `; older than its ${decayDays[state.proofScope]}-day window`;
  }
  return line;
}

/** The notes every posture line ends with: a contradicting run, an excluded technique. */
function postureNotes(state: PostureState): string {
  let notes = '';
  if (state.subStates.includes('contradicted')) notes += '; a later failed run contradicts the marks';
  if (state.excluded) notes += '; not reproducible, so left out of the denominator';
  return notes;
}

/**
 * The Posture lens: the technique's own rung, from its PostureState.
 *   'Proven (your run) on 2026-10-21 by manual; 1 rule fired'
 *   'Covered (self-attested) from mitigation implemented via M1036'
 *   'Covered (self-attested, partial via M1038): reached only through a mitigation mapped to more techniques than the breadth threshold'
 *   'Known: mapped (3 of 5 reference families)'
 *   'None: no reference data mapped and nothing of yours recorded'
 */
export function postureExplain(state: PostureState, decayDays?: Readonly<Record<ProofScope, number>>): string {
  switch (state.bucket) {
    case 'proven':
    case 'stale':
      return proofExplain(state, decayDays) + postureNotes(state);
    case 'covered': {
      const marks = describeMarks(state.covered.filter(m => m.strength === 'full'));
      return postureBadge(state) + (marks ? ` from ${marks}` : '') + postureNotes(state);
    }
    case 'partial':
      return postureBadge(state)
        + ': reached only through a mitigation or control mapped to more techniques than the breadth threshold'
        + postureNotes(state);
    case 'known':
      return `${postureBadge(state)} (${state.knownSignals} of ${KNOWN_FAMILY_COUNT} reference families)` + postureNotes(state);
    default:
      return 'None: no reference data mapped and nothing of yours recorded' + postureNotes(state);
  }
}

/**
 * The Covered lens on a technique with no covered mark (RP-F item 2). The cell
 * is None on this lens, but the same card can list a recorded run or Known
 * reference data, so the line says which block holds it rather than claiming
 * nothing of the user's reaches the technique:
 *   'None: no covered (self-attested or range) mark; see the Proven block for its recorded result'
 *   'None: no covered (self-attested or range) mark; see the Known block for its reference data (3 of 5 reference families)'
 *   'None: nothing of yours reaches this technique'   (no run, no reference data)
 * The Covered lens is only on screen while owner words may render
 * (lensOnScreen), so the Covered words here are always gated on hasOwnerWords.
 * A stale run counts: it is still listed in the Proven block.
 */
function coveredNoneExplain(state: PostureState): string {
  const head = 'None: no covered (self-attested or range) mark';
  if (state.proof.length > 0) return `${head}; see the ${PROVEN} block for its recorded result` + postureNotes(state);
  if (state.knownSignals > 0) {
    return `${head}; see the ${KNOWN_BLOCK} block for its reference data (${state.knownSignals} of ${KNOWN_FAMILY_COUNT} reference families)`
      + postureNotes(state);
  }
  return 'None: nothing of yours reaches this technique' + postureNotes(state);
}

/** A registry lens other than Posture: its cell's own words, with the marks or proof behind them. */
function registryExplain(def: LensDefinition, cell: LensCell, ctx: LensExplainContext): string {
  const { state } = ctx;
  if (def.value === 'posture') return postureExplain(state, ctx.decayDays);
  if (def.value === 'proven') {
    return cell.score > 0 && state.proof.length > 0 ? proofExplain(state, ctx.decayDays) : 'No recorded detection for this technique';
  }
  if (def.value === 'covered') {
    if (cell.score === 2) {
      return `${cell.label} from ${describeMarks(state.covered.filter(m => m.strength === 'full'))}`;
    }
    if (cell.score === 1) {
      return `${cell.label}: reached only through a mitigation or control mapped to more techniques than the breadth threshold`;
    }
    return coveredNoneExplain(state);
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
