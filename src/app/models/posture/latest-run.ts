// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The one latest-run comparator (RP-F decision 24). The Detection Validation
// pill (ValidationService.latestFor) and the posture derivation (derive-posture)
// both pick a technique's latest run with it, so the pill and the evidence card
// never name different runs. Round 4 found them apart: latestFor compared the
// runDate strings while derive-posture used Date.parse, so a same-instant pair
// (S18 T1049), offset timestamps (S19 T1007) and an unparseable 'yesterday'
// (S22 T1497) each showed one run on the pill and another on the card.
//
// Order, newest first:
//   1. by instant, read by runTime (local-date.ts): a date-only runDate is its
//      local day, never UTC midnight (S27 T1059.001 in Chicago);
//   2. on the same instant, the run that proves less first: failed, no-telemetry,
//      not-reproducible, untested, partial, then passed (a tie never reads as a
//      pass); a status outside the store's six sorts after passed;
//   3. then by id, so the order is total and stable;
//   4. a run whose date runTime cannot read sorts OLDEST (after every dated run,
//      by status and id among themselves), and latestRun flags it as undated.
import { runTime } from '../local-date';

/** What the comparator reads of a run. */
export interface RunOrderKey {
  readonly date: string;
  readonly status: string;
  readonly id: string;
}

/** Same-instant precedence: a lower rank is the later run. */
const TIE_RANK: Readonly<Record<string, number>> = {
  failed: 0, 'no-telemetry': 1, 'not-reproducible': 2, untested: 3, partial: 4, passed: 5,
};
const UNKNOWN_STATUS_RANK = 6;

function tieRank(status: string): number {
  return Object.prototype.hasOwnProperty.call(TIE_RANK, status) ? TIE_RANK[status] : UNKNOWN_STATUS_RANK;
}

/** Newest first, as the header says. Usable with Array.prototype.sort. */
export function compareRunsNewestFirst(a: RunOrderKey, b: RunOrderKey): number {
  const ta = runTime(a.date);
  const tb = runTime(b.date);
  if (ta !== tb) {
    if (ta === null) return 1;
    if (tb === null) return -1;
    return tb - ta;
  }
  return tieRank(a.status) - tieRank(b.status) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/** The latest run, its instant, and whether its date was unreadable (then every run's was). */
export interface LatestRun<T> {
  readonly run: T;
  readonly t: number | null;
  /** True when the latest run's date is not a date: it sorted oldest, so no run of the set is dated. */
  readonly undated: boolean;
}

/** The latest of `runs` by compareRunsNewestFirst, or null for none. */
export function latestRun<T>(runs: readonly T[], key: (run: T) => RunOrderKey): LatestRun<T> | null {
  let best: T | null = null;
  let bestKey: RunOrderKey | null = null;
  for (const run of runs) {
    const k = key(run);
    if (bestKey === null || compareRunsNewestFirst(k, bestKey) < 0) {
      best = run;
      bestKey = k;
    }
  }
  if (bestKey === null) return null;
  const t = runTime(bestKey.date);
  return { run: best as T, t, undated: t === null };
}

/** `runs` newest first by compareRunsNewestFirst (a new array). */
export function sortRunsNewestFirst<T>(runs: readonly T[], key: (run: T) => RunOrderKey): T[] {
  return [...runs].sort((a, b) => compareRunsNewestFirst(key(a), key(b)));
}

/** The key of a stored run (ValidationRunV2). */
export function storedRunKey(r: { readonly runDate: string; readonly status: string; readonly id: string }): RunOrderKey {
  return { date: r.runDate, status: r.status, id: r.id };
}

/** The key of a run as derivePosture reads it (RunSummary). */
export function summaryRunKey(r: { readonly date: string; readonly status: string; readonly runId: string }): RunOrderKey {
  return { date: r.date, status: r.status, id: r.runId };
}
