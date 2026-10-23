// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The words of a partial mark's cause (RP-F decision 31). A partial state is
// partial for one of two reasons, carried on the marks (CoveredMark.partialCause)
// and on the state (PostureState.partialCauses) where derivePosture and the store
// adapters produce them, never inferred from wording:
// - 'breadth': reached only through a mitigation or control mapped to more
//   techniques than the D16 breadth threshold. The why line keeps the threshold
//   sentence and the evidence card offers Confirm.
// - 'telemetry': a range row whose coverage_state is telemetry-observed. The why
//   line, on every lens and page, reads "range telemetry observed via <rule>:
//   partial, no detection alerted", the cell's aria-label says it too, and the card
//   offers "Record a run" instead of Confirm.
// Round 6 (letter A) found a telemetry-only range row on T1200 explained with the
// threshold sentence, and its Confirm minted a self-attested mark 'via wazuh:5'.
// No rung word here: these lines name a cause, never a rung.
import type { CoveredMark, PartialCause, PostureState } from './posture.types';

/** The breadth partial's reason (D16), as the why line has always said it. */
export const BREADTH_PARTIAL_WORDS =
  'reached only through a mitigation or control mapped to more techniques than the breadth threshold';

/** The tail of the range telemetry partial's words (RP-F decision 31). */
const TELEMETRY_PARTIAL_TAIL = 'partial, no detection alerted';

/**
 * The causes of a state's partial marks: the state's own partialCauses when
 * derivePosture set them, else the causes its partial marks name (a hand-built
 * state). Sorted and unique; empty when no partial mark names a cause.
 */
export function partialCausesOf(state: Pick<PostureState, 'covered'> & Partial<Pick<PostureState, 'partialCauses'>>): PartialCause[] {
  if (state.partialCauses) return [...state.partialCauses];
  const causes = new Set<PartialCause>();
  for (const m of state.covered) if (m.strength === 'partial' && m.partialCause) causes.add(m.partialCause);
  return [...causes].sort();
}

/** The distinct `via` of the partial marks of `cause`, in mark order. */
function viaOf(marks: readonly CoveredMark[], cause: PartialCause): string[] {
  const out: string[] = [];
  for (const m of marks) {
    if (m.strength === 'partial' && m.partialCause === cause && m.via && !out.includes(m.via)) out.push(m.via);
  }
  return out;
}

/**
 * 'range telemetry observed via wazuh:5: partial, no detection alerted' (RP-F decision
 * 31), naming every rule of the state's telemetry partial marks; without a rule,
 * 'range telemetry observed: partial, no detection alerted'.
 */
export function telemetryPartialWords(marks: readonly CoveredMark[]): string {
  const via = viaOf(marks, 'telemetry');
  return `range telemetry observed${via.length > 0 ? ` via ${via.join(', ')}` : ''}: ${TELEMETRY_PARTIAL_TAIL}`;
}

/**
 * What a partial line adds after its badge or cell label, by cause:
 * - breadth only: ': reached only through ... breadth threshold';
 * - telemetry only: ' from range telemetry observed via <rule>: partial, no detection alerted';
 * - both: the threshold sentence, then '; range telemetry observed via ...';
 * - no named cause (a hand-built mark): '' (the line names no cause rather than guess one).
 */
export function partialReason(state: Pick<PostureState, 'covered'> & Partial<Pick<PostureState, 'partialCauses'>>): string {
  const causes = partialCausesOf(state);
  const telemetry = causes.includes('telemetry') ? telemetryPartialWords(state.covered) : '';
  if (causes.includes('breadth')) return `: ${BREADTH_PARTIAL_WORDS}` + (telemetry ? `; ${telemetry}` : '');
  return telemetry ? ` from ${telemetry}` : '';
}
