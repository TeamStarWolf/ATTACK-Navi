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
// The words are per technique and per rule, never per row (RP-F decision 40):
// posture-adapters gives one telemetry mark per rule (the latest row of the rule, alerted
// or blocked when any run of the technique fired it, matched case-insensitively), and
// each mark is one clause dated by its run: "... (range run on 10/21/26)". A quiet rule
// beside a rule that fired reads "partial, this rule did not alert", so "no detection
// alerted" never stands beside a fired rule the pill or the Proven block counts.
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
import type { CoveredMark, PartialCause, PostureState, RunSummary } from './posture.types';
import { attackResultWords } from './fired-rules';
import { validationDay } from '../local-date';

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

/** The tail of a range telemetry partial when no rule fired anywhere in the technique's evidence (RP-F decision 31). */
const TELEMETRY_QUIET_TAIL = 'partial, no detection alerted';

/**
 * The tail of a quiet telemetry row's rule when another rule of the technique fired
 * (RP-F decision 40): the clause names this rule as quiet, never "no detection alerted"
 * beside a pill or a Proven block that counts a fired rule.
 */
const TELEMETRY_RULE_QUIET_TAIL = 'partial, this rule did not alert';

/** The same for a quiet row that names no rule while another rule of the technique fired. */
const TELEMETRY_UNNAMED_QUIET_TAIL = 'partial, no rule named';

/** How a telemetry partial's rule ended, as its words order it: quiet (logged, none or unknown), alerted, blocked. */
type TelemetryFired = 'quiet' | 'alerted' | 'blocked';

/** The order the clauses are named in: the quiet rules first, then the rules that fired. */
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

/**
 * One telemetry mark's clause (RP-F decisions 35 and 40): one rule, its outcome and its
 * run date (` (range run on <day>)`, the local day the Detection Validation pill prints).
 *   quiet, nothing fired:      'range telemetry observed via wazuh:5: partial, no detection alerted (range run on 10/20/26)'
 *   quiet, another rule fired: 'range telemetry observed via wazuh:202: partial, this rule did not alert (range run on 10/21/26)'
 *   fired in the row's run:    'range telemetry observed via wazuh:12: partial; the rule alerted in this run, but the
 *                               range reports telemetry-only coverage, so it is not proof (range run on 10/20/26)'
 *   fired in another run:      '... the rule alerted in a run on 10/20/26, but ...'
 */
function telemetryClause(m: CoveredMark): string {
  const head = `range telemetry observed${m.via ? ` via ${m.via}` : ''}`;
  const when = m.at ? ` (range run on ${validationDay(m.at)})` : '';
  const fired = telemetryFired(m);
  if (fired === 'quiet') {
    const tail = !m.techniqueFired ? TELEMETRY_QUIET_TAIL : m.via ? TELEMETRY_RULE_QUIET_TAIL : TELEMETRY_UNNAMED_QUIET_TAIL;
    return `${head}: ${tail}${when}`;
  }
  const where = m.telemetryFiredAt ? `in a run on ${validationDay(m.telemetryFiredAt)}` : 'in this run';
  return `${head}: partial; the rule ${fired} ${where}, but the range reports telemetry-only coverage, so it is not proof${when}`;
}

/**
 * The words of the state's range telemetry partial marks, one clause per rule (RP-F
 * decision 40: posture-adapters gives one telemetry mark per rule, the latest row of the
 * rule, alerted or blocked when any run of the technique fired it), quiet rules first,
 * then the rules that alerted, then those that blocked, joined with '; ':
 *   'range telemetry observed via wazuh:202: partial, this rule did not alert (range run on 10/21/26);
 *    range telemetry observed via wazuh:201: partial; the rule alerted in this run, but the range
 *    reports telemetry-only coverage, so it is not proof (range run on 10/21/26)'
 * Without a telemetry mark, 'range telemetry observed: partial, no detection alerted'.
 * Round 8 grouped the rows by outcome and worded each row alone, so T1113 read "no
 * detection alerted" for wazuh:202 beside a pill counting wazuh:201 as fired.
 */
export function telemetryPartialWords(marks: readonly CoveredMark[]): string {
  const telemetry = marks.filter(m => m.strength === 'partial' && m.partialCause === 'telemetry');
  const clauses: string[] = [];
  for (const fired of TELEMETRY_FIRED_ORDER) {
    for (const m of telemetry) {
      const clause = telemetryFired(m) === fired ? telemetryClause(m) : null;
      if (clause !== null && !clauses.includes(clause)) clauses.push(clause);
    }
  }
  return clauses.length > 0 ? clauses.join('; ') : `range telemetry observed: ${TELEMETRY_QUIET_TAIL}`;
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
 * The Covered words of a range run whose attack did not execute (RP-F decision 44): its
 * rows credit nothing, so the card's Covered block names it instead of a mark:
 *   'range run on 10/21/26 did not execute (errored): not credited'
 * It never reads "the rule alerted in this run" (round 8, T1027.013). Null for a run
 * that executed, or one that is not a range run.
 */
export function notCreditedWords(run: Pick<RunSummary, 'date' | 'source' | 'notExecuted'>): string | null {
  if (!run.notExecuted || !run.source.startsWith('lylat-range:')) return null;
  return `range run on ${validationDay(run.date)} did not execute (${attackResultWords(run.notExecuted)}): not credited`;
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
