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
// - 'telemetry': a range row whose coverage_state is telemetry-observed. The cause
//   carries the row's outcome (CoveredMark.telemetryOutcome, RP-F decision 35), set by
//   runInputs where the mark is produced, and the words follow it: outcome logged or
//   none reads "range telemetry observed via <rule>: partial, no detection alerted";
//   outcome alerted or blocked reads "range telemetry observed via <rule>: partial;
//   the rule alerted in this run, but the range reports telemetry-only coverage, so it
//   is not proof". The why line, the cell's aria-label and tooltip, the card's Covered
//   block and its "Record a run" tooltip all say it, and the card offers "Record a
//   run" instead of Confirm.
// Round 6 (letter A) found a telemetry-only range row on T1200 explained with the
// threshold sentence, and its Confirm minted a self-attested mark 'via wazuh:5'.
// Round 7 (letters A and G) found a telemetry row whose rule alerted (T1082 via
// wazuh:12) or blocked (T1083 via wazuh:13) read "no detection alerted" beside a pill
// that said the rule fired: the tail was fixed, not read from the row.
// Every surface that words a partial reads its cause through this file (RP-F decision
// 36): the why line and the cell (lens-explain, posture-ramp), the card's Covered block,
// the scenario table's reason and partial note (scenario-panel), the Report Builder's
// partial card and note and the HTML and PDF reports (report-split), and the Posture
// and Covered lens formulas (heatmap-modes). Round 7 found the scenario table and the
// Report Builder inferring a breadth cause from the partial bucket on telemetry-only
// range rows. Threshold or breadth wording outside this file is a defect
// (partial-cause-words.spec.ts).
// No rung word here: these lines name a cause, never a rung.
import type { CoveredMark, PartialCause, PostureState } from './posture.types';

/** The breadth partial's reason (D16), as the why line has always said it. */
export const BREADTH_PARTIAL_WORDS =
  'reached only through a mitigation or control mapped to more techniques than the breadth threshold';

/** The order every per-cause list names the causes in. */
export const PARTIAL_CAUSE_ORDER: readonly PartialCause[] = ['breadth', 'telemetry'];

/**
 * Each cause's label where a partial is counted or listed by cause (RP-F decision 36):
 * the Report Builder's partial card, the HTML and PDF reports, the scenario table's
 * reason and its partial note.
 */
export const PARTIAL_CAUSE_LABELS: Readonly<Record<PartialCause, string>> = {
  breadth: 'partial (broad mitigation, not confirmed per technique)',
  telemetry: 'partial (range telemetry, no alert credited)',
};

/** How many partial techniques have each cause (a technique with both causes counts under each). */
export type PartialCauseTally = Readonly<Record<PartialCause, number>>;

/**
 * Count the techniques in the partial bucket by cause (RP-F decision 36), from each
 * state's typed causes (partialCausesOf), never from the bucket alone. A technique
 * with both causes counts under each; a partial state that names no cause (a
 * hand-built one) counts under neither.
 */
export function tallyPartialCauses(
  states: Iterable<Pick<PostureState, 'bucket' | 'covered'> & Partial<Pick<PostureState, 'partialCauses'>>>,
): PartialCauseTally {
  const tally: Record<PartialCause, number> = { breadth: 0, telemetry: 0 };
  for (const s of states) {
    if (s.bucket !== 'partial') continue;
    for (const c of partialCausesOf(s)) tally[c]++;
  }
  return tally;
}

/** '<label>: <count>' for each cause with a count, in PARTIAL_CAUSE_ORDER (the partial card's and note's lines). */
export function partialCauseLines(tally: PartialCauseTally): string[] {
  return PARTIAL_CAUSE_ORDER.filter(c => tally[c] > 0).map(c => `${PARTIAL_CAUSE_LABELS[c]}: ${tally[c]}`);
}

/**
 * A partial technique's reason in the scenario table (RP-F decision 36): the label of
 * each of its causes, joined with '; '; 'partial' alone when no cause is named.
 */
export function partialCauseReason(state: Pick<PostureState, 'covered'> & Partial<Pick<PostureState, 'partialCauses'>>): string {
  const causes = partialCausesOf(state);
  return causes.length > 0 ? PARTIAL_CAUSE_ORDER.filter(c => causes.includes(c)).map(c => PARTIAL_CAUSE_LABELS[c]).join('; ') : 'partial';
}

/**
 * When a technique is partial, as the Posture and Covered lens formulas say it (RP-F
 * decision 36): both causes, never the breadth cause alone. The formulas wrap it:
 * 'partial when <this>' (Posture), '1 when <this> (partial, drawn dashed)' (Covered).
 */
export const PARTIAL_CAUSES_FORMULA =
  'only a mitigation or control mapped to more techniques than the breadth threshold in Settings (15 by default) reaches it, '
  + 'or only a range row reports it with telemetry-only coverage (telemetry observed, no alert credited, even when its rule fired)';

/** What counts as partial, as the Report Builder's note says it (RP-F decision 36). */
export const PARTIAL_CAUSES_NOTE =
  'a broad mitigation not confirmed per technique, or range telemetry with no alert credited, counts as partial';

/** The tail of a range telemetry partial whose row's outcome is logged or none (RP-F decision 31). */
const TELEMETRY_QUIET_TAIL = 'partial, no detection alerted';

/** How a telemetry partial's row ended, as its words group it: quiet (logged, none or unknown), alerted, blocked. */
type TelemetryFired = 'quiet' | 'alerted' | 'blocked';

/** The order the groups are named in: the quiet rows first, then the rows whose rule fired. */
const TELEMETRY_FIRED_ORDER: readonly TelemetryFired[] = ['quiet', 'alerted', 'blocked'];

/** The group of a telemetry mark, from the outcome its producer recorded (RP-F decision 35). */
function telemetryFired(m: CoveredMark): TelemetryFired {
  return m.telemetryOutcome === 'alerted' || m.telemetryOutcome === 'blocked' ? m.telemetryOutcome : 'quiet';
}

/**
 * The causes of a state's partial marks: the state's own partialCauses when
 * derivePosture set them, else the causes its partial marks name (a hand-built
 * state). Sorted and unique; empty when no partial mark names a cause.
 */
export function partialCausesOf(state: Pick<PostureState, 'covered'> & Partial<Pick<PostureState, 'partialCauses'>>): PartialCause[] {
  if (state.partialCauses) return [...state.partialCauses];
  const causes = new Set<PartialCause>();
  for (const m of state.covered ?? []) if (m.strength === 'partial' && m.partialCause) causes.add(m.partialCause);
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

/** One group's words: the rules it names, then the tail its outcome reads. */
function telemetryClause(via: readonly string[], fired: TelemetryFired): string {
  const head = `range telemetry observed${via.length > 0 ? ` via ${via.join(', ')}` : ''}`;
  if (fired === 'quiet') return `${head}: ${TELEMETRY_QUIET_TAIL}`;
  return `${head}: partial; ${via.length > 1 ? 'the rules' : 'the rule'} ${fired} in this run, `
    + 'but the range reports telemetry-only coverage, so it is not proof';
}

/**
 * The words of the state's range telemetry partial marks, by the outcome each mark's
 * row recorded (RP-F decisions 31 and 35), naming every rule of each group:
 *   logged or none:  'range telemetry observed via wazuh:5: partial, no detection alerted'
 *   alerted:         'range telemetry observed via wazuh:12: partial; the rule alerted in this run,
 *                     but the range reports telemetry-only coverage, so it is not proof'
 *   blocked:         the same with 'the rule blocked in this run'
 * Groups are joined with '; ', quiet rows first. Without a telemetry mark, or a rule,
 * 'range telemetry observed: partial, no detection alerted'.
 */
export function telemetryPartialWords(marks: readonly CoveredMark[]): string {
  const telemetry = marks.filter(m => m.strength === 'partial' && m.partialCause === 'telemetry');
  const clauses: string[] = [];
  for (const fired of TELEMETRY_FIRED_ORDER) {
    const group = telemetry.filter(m => telemetryFired(m) === fired);
    if (group.length > 0) clauses.push(telemetryClause(viaOf(group, 'telemetry'), fired));
  }
  return clauses.length > 0 ? clauses.join('; ') : telemetryClause([], 'quiet');
}

/**
 * The cause of one partial mark in words, for the card's Covered block (RP-F decisions
 * 35 and 36): a telemetry mark's telemetryPartialWords, a breadth mark's threshold
 * sentence; null for a full or planned mark, or a partial mark that names no cause.
 */
export function partialMarkWords(m: CoveredMark): string | null {
  if (m.strength !== 'partial') return null;
  if (m.partialCause === 'telemetry') return telemetryPartialWords([m]);
  if (m.partialCause === 'breadth') return BREADTH_PARTIAL_WORDS;
  return null;
}

/**
 * The tooltip of the card's "Record a run" on a telemetry partial (RP-F decision 35):
 * the mark's own words, then what the button does.
 */
export function recordRunTooltip(m: CoveredMark): string {
  return `${telemetryPartialWords([m])}; record a validation run of this technique in Detect > Validation`;
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
