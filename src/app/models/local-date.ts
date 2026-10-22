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
 * `date` in `format`, in local time. A date-only 'YYYY-MM-DD' (validated_at) is
 * that local day; a string Date.parse cannot read is returned as it is.
 */
function format(date: string, fmt: string): string {
  if (typeof date !== 'string' || Number.isNaN(Date.parse(date))) return String(date ?? '');
  return formatDate(date, fmt, LOCALE);
}

/** A run's or proof record's day, as the Detection Validation pill prints it: '10/21/26'. */
export function validationDay(date: string): string {
  return format(date, VALIDATION_DAY_FORMAT);
}

/** A run's date and time, as the Detection Validation pill prints it: '10/21/26, 7:49 PM'. */
export function validationDateTime(date: string): string {
  return format(date, VALIDATION_RUN_FORMAT);
}
