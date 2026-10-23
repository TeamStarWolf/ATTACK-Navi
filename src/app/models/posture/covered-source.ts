// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Covered by source (RP-F decision 43), the way partial-cause.ts splits partial by
// cause (decision 36). A Covered technique is covered by what the owner attests
// (self-attested: a mitigation, a control, a confirmation or a run of theirs) or by what
// the range reports (range: a deployed or authored detection row), read from the
// qualifiers of the full marks that make the bucket, never assumed. The scenario
// table's reason (scenario-panel scenarioReason) and the Report Builder's Covered card,
// with the HTML and PDF reports (report-split coveredCardLines), read it here. Round 8
// read "You recorded a mitigation, control, confirmation or run (self-attested)" on
// T1005, T1037.001 and T1550.002, whose only full mark was a range row.
// The labels come from the vocabulary module (COVERED_SOURCE_LABELS); no rung word is
// written here.
import type { CoveredQualifier } from '../heatmap-modes';
import type { PostureState } from './posture.types';
import { COVERED_SOURCE_LABELS, lensLabel } from './posture-vocabulary';

/** The order every per-source list names the sources in. */
export const COVERED_SOURCE_ORDER: readonly CoveredQualifier[] = ['self-attested', 'range'];

/** How many Covered techniques each source covers (a technique covered by both counts under each). */
export type CoveredSourceTally = Readonly<Record<CoveredQualifier, number>>;

type SourceState = Pick<PostureState, 'bucket' | 'covered'> & Partial<Pick<PostureState, 'qualifiers'>>;

/**
 * The sources of a Covered technique: its state's qualifiers (derivePosture sets them
 * from the full marks that make the bucket, after a contradiction is applied), else the
 * qualifiers of its full marks (a hand-built state). Empty for any other bucket.
 */
export function coveredSourcesOf(state: SourceState): CoveredQualifier[] {
  if (state.bucket !== 'covered') return [];
  const from = state.qualifiers && state.qualifiers.length > 0
    ? state.qualifiers
    : (state.covered ?? []).filter(m => m.strength === 'full').map(m => m.qualifier);
  return COVERED_SOURCE_ORDER.filter(q => from.includes(q));
}

/** Count the Covered techniques by source (RP-F decision 43), from each state's own qualifiers. */
export function tallyCoveredSources(states: Iterable<SourceState>): CoveredSourceTally {
  const tally: Record<CoveredQualifier, number> = { 'self-attested': 0, range: 0 };
  for (const s of states) for (const q of coveredSourcesOf(s)) tally[q]++;
  return tally;
}

/** '<label>: <count>' for each source with a count, in COVERED_SOURCE_ORDER (the Covered card's lines). */
export function coveredSourceLines(tally: CoveredSourceTally): string[] {
  return COVERED_SOURCE_ORDER.filter(q => tally[q] > 0).map(q => `${COVERED_SOURCE_LABELS[q]}: ${tally[q]}`);
}

/**
 * A Covered technique's reason in the scenario table (RP-F decision 43): the label of
 * each of its sources, joined with '; '; the self-attested label never stands for a
 * range-only full mark. A state that names no source (a hand-built one) reads the
 * lens's own label, 'Covered (self-attested or range)', rather than guess one.
 */
export function coveredSourceReason(state: SourceState): string {
  const sources = coveredSourcesOf(state);
  return sources.length > 0 ? sources.map(q => COVERED_SOURCE_LABELS[q]).join('; ') : lensLabel('covered');
}
