// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The one date formatter for runs and proof (RP-F decision 16). The Detection
// Validation pill prints a run as "last run 10/21/26, 7:49 PM": Angular's
// formatDate in the viewer's local time zone. The evidence card and the "Why
// this colour" line print the same local day with the same formatter, so a run
// recorded after 19:00 in UTC-5 reads 10/21/26 on both, never the UTC day of
// its ISO timestamp (date.slice(0, 10) read 2026-10-22).
import { formatDate } from '@angular/common';

/** The locale the pill's DatePipe formats in (the app sets no LOCALE_ID, so Angular's default). */
const LOCALE = 'en-US';

/** The pill's run time format: '10/21/26, 7:49 PM'. */
export const VALIDATION_RUN_FORMAT = 'short';

/** The day part of VALIDATION_RUN_FORMAT: '10/21/26'. */
export const VALIDATION_DAY_FORMAT = 'shortDate';

/**
 * The viewer's zone as a fixed UTC offset in minutes (east positive), or null for
 * the browser's own zone (always null in the app). A spec runs the comparator and
 * the formatter "in" America/Chicago (-300 in October) or Asia/Tokyo (+540) with
 * setRunDateZoneForSpecs, since a browser test cannot set TZ.
 */
let fixedOffsetMinutes: number | null = null;

/** Specs only: read and print run dates as if the viewer's zone were `offsetMinutes` east of UTC; null restores the browser's zone. */
export function setRunDateZoneForSpecs(offsetMinutes: number | null): void {
  fixedOffsetMinutes = offsetMinutes;
}

const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * The one reading of a run date (RP-F decision 24), shared by the latest-run
 * comparator (latest-run.ts) and the day formatter below: milliseconds since the
 * epoch, or null when the value is not a date. A date-only 'YYYY-MM-DD'
 * (validated_at, a range row) is the START OF THAT LOCAL DAY, as the pill prints
 * it; Date.parse reads it as UTC midnight, which in Chicago is the evening before,
 * so a range run of 10/19 sorted before a manual run at 22:00 on 10/18 and the why
 * line read "latest run failed on 10/18/26; an earlier run passed on 10/19/26"
 * (S27 T1059.001). A date-only value that names no calendar day (2026-02-30) is
 * null. Anything else is Date.parse's reading (an ISO timestamp with or without
 * an offset; one without an offset is already local time).
 */
export function runTime(date: unknown): number | null {
  if (typeof date !== 'string') return null;
  const day = DATE_ONLY.exec(date.trim());
  if (day) {
    const [y, m, d] = [Number(day[1]), Number(day[2]) - 1, Number(day[3])];
    if (fixedOffsetMinutes !== null) {
      const utc = new Date(Date.UTC(y, m, d));
      utc.setUTCFullYear(y);
      const ok = utc.getUTCFullYear() === y && utc.getUTCMonth() === m && utc.getUTCDate() === d;
      return ok ? utc.getTime() - fixedOffsetMinutes * 60_000 : null;
    }
    const local = new Date(y, m, d);
    local.setFullYear(y);   // years 0-99: new Date(y, ...) reads them as 1900-1999
    return local.getFullYear() === y && local.getMonth() === m && local.getDate() === d ? local.getTime() : null;
  }
  const t = Date.parse(date);
  return Number.isNaN(t) ? null : t;
}

/** '+0900', '-0500': the zone argument formatDate takes for a fixed offset. */
function offsetZone(minutes: number): string {
  const abs = Math.abs(minutes);
  return `${minutes < 0 ? '-' : '+'}${String(Math.floor(abs / 60)).padStart(2, '0')}${String(abs % 60).padStart(2, '0')}`;
}

/** What a date runTime cannot read is flagged with wherever it is printed (RP-F decision 24). */
export const UNREADABLE_DATE_FLAG = 'unreadable date, sorted oldest';

/**
 * A value runTime cannot read, as every surface prints it: the value as recorded,
 * quoted, then flagged: "'yesterday' (unreadable date, sorted oldest)". The
 * latest-run comparator sorts such a run oldest (latest-run.ts, LatestRun.undated),
 * so the Validation pill's "last run", the card's runs line and the why line all
 * say why it is not ordered by its date (round 4 printed "failed on yesterday").
 */
export function unreadableDate(date: unknown): string {
  return `'${typeof date === 'string' ? date : ''}' (${UNREADABLE_DATE_FLAG})`;
}

/**
 * `date` in `format`, in local time, read by runTime: a date-only 'YYYY-MM-DD' is
 * that local day; a value runTime cannot read is quoted and flagged (unreadableDate).
 */
function format(date: string, fmt: string): string {
  const t = runTime(date);
  if (t === null) return unreadableDate(date);
  return fixedOffsetMinutes === null ? formatDate(t, fmt, LOCALE) : formatDate(t, fmt, LOCALE, offsetZone(fixedOffsetMinutes));
}

/** A run's or proof record's day, as the Detection Validation pill prints it: '10/21/26'. */
export function validationDay(date: string): string {
  return format(date, VALIDATION_DAY_FORMAT);
}

/** A run's date and time, as the Detection Validation pill prints it: '10/21/26, 7:49 PM'. */
export function validationDateTime(date: string): string {
  return format(date, VALIDATION_RUN_FORMAT);
}
