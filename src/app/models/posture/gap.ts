// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The two matrix overlays of P2-17 (Phase 2 design §3 P2-17, E2.2-d): the
// Threat gaps predicate (S5, R17) and the My marks bar. Both read a
// technique's PostureState only; neither changes the lens colour
// (MatrixComponent.getCellColor), so every lens snapshot stays as it is.
//
// Threat gaps. A technique is a threat gap when it is threat-relevant AND the
// owner has nothing that holds for it:
//   threat-relevant: threatWeight >= q75, the 75th percentile of the threat
//                    profile's non-zero weights (minimum 1; §10.4 item 6), OR
//                    exposureWeight > 0 (Enterprise only, §1.16);
//   nothing holds:   bucket 'none' or 'known' (the epic's "None or Known
//                    only"), OR the 'contradicted' sub-state (a later failed
//                    run; §10.4 item 13). Partial is NOT a gap;
//   and the technique is not excluded (not reproducible, no proof).
// q75 is computed from the THREAT_WEIGHT_PROVIDER token (its `parents()` set
// and `weight()`), never from ThreatProfileService, so the matrix and the
// legend recompute it when the profile changes (Addendum 5).
//
// My marks. A 3 px bar on the left of every cell, whatever the lens (plan
// :295), coloured by the cell's bucket from the posture ramp tokens
// (posture-ramp.ts): partial (dashed, in the Covered blue), covered, proven,
// stale, and contradicted (the Posture lens's vermilion). None and known get
// no bar, so a fresh profile renders exactly what it did before.
import type { PostureBucket, PostureState } from './posture.types';
import { POSTURE_TOKENS, type PostureTheme } from './posture-ramp';

/** The View menu toggle's words (exact; gap.spec pins them). */
export const THREAT_GAP_TOGGLE_LABEL = 'Threat gaps: threat-relevant, posture None, Known only or contradicted';

/** The legend line shown while the overlay is on (§1.16: exposure is Enterprise-only). */
export const THREAT_GAP_EXPOSURE_NOTE = 'Exposure counts on Enterprise only';

/** The View menu toggle for the My marks bar (AppSettings.cellDisplay.myMarks). */
export const MY_MARKS_TOGGLE_LABEL = 'My marks';

/** The percentile of the profile's non-zero weights a technique must reach (§10.4 item 6). */
export const THREAT_GAP_PERCENTILE = 0.75;

/**
 * The threat-relevance threshold: the 75th percentile (nearest rank) of the
 * non-zero weights of the profile's parent techniques, and at least 1. A
 * profile with no weighted technique gives 1.
 */
export function threatGapThreshold(parents: Iterable<string>, weight: (techniqueStixId: string) => number): number {
  const weights: number[] = [];
  for (const id of parents) {
    const w = weight(id);
    if (w > 0) weights.push(w);
  }
  if (weights.length === 0) return 1;
  weights.sort((a, b) => a - b);
  const rank = Math.ceil(THREAT_GAP_PERCENTILE * weights.length);
  return Math.max(1, weights[rank - 1]);
}

/** True when the technique is a threat gap at threshold `q75` (see the header). */
export function isThreatGap(
  state: Pick<PostureState, 'bucket' | 'subStates' | 'threatWeight' | 'exposureWeight' | 'excluded'>,
  q75: number,
): boolean {
  if (state.excluded) return false;
  const relevant = state.threatWeight >= Math.max(1, q75) || state.exposureWeight > 0;
  if (!relevant) return false;
  return state.bucket === 'none' || state.bucket === 'known' || state.subStates.includes('contradicted');
}

/** The buckets that draw a My marks bar. */
export type MyMarkBucket = Extract<PostureBucket, 'partial' | 'covered' | 'proven' | 'stale'> | 'contradicted';

/**
 * The My marks bucket of a state: its own bucket when the owner has a mark that
 * holds (partial, covered, proven, stale), 'contradicted' when a later failed
 * run voided the marks, and null for none and known (no bar).
 */
export function myMarkBucket(state: Pick<PostureState, 'bucket' | 'subStates'>): MyMarkBucket | null {
  switch (state.bucket) {
    case 'partial':
    case 'covered':
    case 'proven':
    case 'stale':
      return state.bucket;
    default:
      return state.subStates.includes('contradicted') ? 'contradicted' : null;
  }
}

/** The Posture lens's contradicted pattern colour (Okabe-Ito vermilion, technique-cell.component.scss). */
export const MY_MARK_CONTRADICTED = '#d55e00';

/**
 * The bar's colour in a theme, from the posture ramp tokens. Partial uses the
 * Covered blue and the cell draws it dashed, as the Posture lens draws partial
 * as a dashed blue outline; contradicted is drawn hatched.
 */
export function myMarkFill(bucket: MyMarkBucket, theme: PostureTheme): string {
  const tokens = POSTURE_TOKENS[theme];
  switch (bucket) {
    case 'partial': return tokens.covered.fill;
    case 'contradicted': return MY_MARK_CONTRADICTED;
    default: return tokens[bucket].fill;
  }
}
