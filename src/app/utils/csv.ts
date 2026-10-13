// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Leading characters that Excel, LibreOffice and Google Sheets interpret as
 * the start of a formula (or a DDE / command cell) when a CSV is opened:
 * `=`, `+`, `-`, `@`, tab and carriage return.
 */
const FORMULA_LEAD = /^[=+\-@\t\r]/;

/**
 * Serialise one value as a CSV cell that is safe to open in a spreadsheet.
 *
 * - Strings are always double-quoted, with embedded quotes doubled, so a
 *   value containing `"`, `,` or a newline cannot break out of its cell.
 * - A string whose first character would start a formula is prefixed with a
 *   single quote, the OWASP-recommended neutralisation, so that feed or CTI
 *   content such as `=HYPERLINK(...)` or `=cmd|' /C calc'!A0` is shown as
 *   literal text instead of being evaluated.
 * - Numbers and booleans are emitted bare (they cannot carry a formula).
 * - `null` and `undefined` become an empty quoted cell.
 *
 * Every CSV writer in the app goes through this helper; do not interpolate
 * untrusted text into a CSV line by hand.
 */
export function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '""';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  let text = typeof value === 'string' ? value : String(value);
  if (FORMULA_LEAD.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

/** Serialise a row of values with {@link csvCell} and join them with commas. */
export function csvRow(cells: readonly unknown[]): string {
  return cells.map(csvCell).join(',');
}

/**
 * Undo the {@link csvCell} formula neutralisation on a parsed cell value, so
 * a CSV this app exported can be re-imported without growing a leading `'`.
 * Only an apostrophe that is followed by a formula-leading character is
 * removed; any other leading apostrophe is user data and is kept.
 */
export function csvUnneutralise(text: string): string {
  return text.length > 1 && text[0] === "'" && FORMULA_LEAD.test(text.slice(1)) ? text.slice(1) : text;
}
