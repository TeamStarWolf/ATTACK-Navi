// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Pure, header-driven parser for the bulk implementation-status CSV import
// (Phase 2 design section 3, P2-06). It takes the raw text and the loaded
// domain and returns a preview the UI shows before anything is written; the
// write itself is ImplementationService.applyStatusCsv, which overwrites only
// the named mitigations in the one v1 status map. No new store, no second key.
//
// Why a parser rewrite was needed: the old importStatusCsv split on commas,
// never resolved Mxxxx to a STIX id, and skipped a header only when it began
// with "technique". So re-importing the app's own export (header
// `Mitigation ID,Mitigation Name,Status,...`, ids Mxxxx) matched nothing, and a
// documented `M1036,implemented` was stored under the literal "M1036" where no
// reader (all STIX-keyed) could see it while still inflating the owner-data
// counts. This resolves by ATT&CK id through the domain and previews the result.
import { csvUnneutralise } from '../utils/csv';
// Type-only so this model carries no runtime dependency on the service (cf.
// heatmap-modes.ts importing HeatmapMode type-only); the service imports back.
import type { ImplStatus } from '../services/implementation.service';
import type { Domain } from './domain';

/** The exact reason reported for an ATT&CK technique id in the id column. */
export const TECHNIQUE_ID_REASON = 'technique ids are not accepted; confirm per technique in the drawer';

/** A mitigation's status accepted from the file; `not-tracked` rows are skipped, not stored. */
const VALID_STATUSES: ReadonlySet<string> = new Set(['implemented', 'in-progress', 'planned', 'not-started']);

const TECH_ID = /^T\d{4}(\.\d{3})?$/i;              // ATT&CK technique / sub-technique id
const MIT_ATTACK_ID = /^M\d{4}$/i;                  // ATT&CK mitigation id (resolved to STIX)
const STIX_MIT = /^course-of-action--/i;           // a STIX mitigation id written verbatim

/** Header names (lower-cased) that identify the id column, in priority order. */
const ID_HEADERS = ['mitigation id', 'mitigation_id', 'technique_id'];

export interface CsvPreview {
  /** Rows resolved to a mitigation in the loaded domain; apply() writes these. */
  readonly matched: { readonly mitStixId: string; readonly status: ImplStatus }[];
  /** Rows with a valid status whose id did not resolve (technique ids, unknown mitigations). */
  readonly unmatched: { readonly row: number; readonly id: string; readonly reason: string }[];
  /** Malformed rows: no id, or a status that is neither valid nor `not-tracked`. */
  errors: number;
}

/**
 * Minimal RFC-4180 reader: fields may be double-quoted; a quoted field may hold
 * commas, newlines and doubled quotes (`""` -> `"`). Returns one array of cells
 * per record. A trailing newline does not add an empty record.
 */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  let started = false;   // a record has begun (so a final empty field still flushes)
  const n = text.length;
  for (let i = 0; i < n; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else { inQuotes = false; }
      } else {
        field += c;
      }
      continue;
    }
    if (c === '"') { inQuotes = true; started = true; continue; }
    if (c === ',') { row.push(field); field = ''; started = true; continue; }
    if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;   // CRLF as one terminator
      row.push(field); rows.push(row);
      row = []; field = ''; started = false;
      continue;
    }
    field += c; started = true;
  }
  if (started || field !== '' || row.length > 0) { row.push(field); rows.push(row); }
  return rows;
}

function findIdColumn(header: readonly string[]): number {
  for (const name of ID_HEADERS) {
    const i = header.indexOf(name);
    if (i >= 0) return i;
  }
  return -1;
}

/**
 * Build a preview of a bulk status CSV against the loaded domain. Accepts the
 * app's own export headers (`Mitigation ID,...,Status,...`), `mitigation_id,status`
 * and the legacy `technique_id,status`; resolves Mxxxx to a STIX id through the
 * domain; reports technique ids and unknown ids as unmatched; counts malformed
 * rows. Writes nothing.
 */
export function previewStatusCsv(text: string, domain: Domain): CsvPreview {
  const rows = parseCsv(text);
  // Keyed by STIX id so a file naming the same mitigation twice (two Mxxxx rows,
  // or an Mxxxx and its STIX id) counts as ONE matched mitigation; the last row
  // for that mitigation wins. preview.matched.length, the Apply button and
  // applyStatusCsv's return all then count distinct mitigations.
  const matchedByStix = new Map<string, ImplStatus>();
  const unmatched: { row: number; id: string; reason: string }[] = [];
  let errors = 0;
  const build = (): CsvPreview => ({
    matched: [...matchedByStix].map(([mitStixId, status]) => ({ mitStixId, status })),
    unmatched,
    errors,
  });
  if (rows.length === 0) return build();

  const header = rows[0].map((h) => h.trim().toLowerCase());
  const idCol = findIdColumn(header);
  const statusCol = header.indexOf('status');
  if (idCol < 0 || statusCol < 0) {
    // Unrecognised header: no id/status column by name. Count the data rows so
    // the UI reports the file as unusable rather than silently importing zero.
    errors = rows.slice(1).filter((r) => r.some((c) => c.trim() !== '')).length;
    return build();
  }

  const mitByAttackId = new Map((domain.mitigations ?? []).map((m) => [m.attackId.toUpperCase(), m.id]));
  const mitStixIds = new Set((domain.mitigations ?? []).map((m) => m.id));

  for (let i = 1; i < rows.length; i++) {
    const cells = rows[i];
    if (cells.every((c) => c.trim() === '')) continue;                 // blank line
    const id = csvUnneutralise((cells[idCol] ?? '').trim());
    const status = csvUnneutralise((cells[statusCol] ?? '').trim()).toLowerCase();
    const rowNo = i + 1;                                               // 1-based, header is row 1

    if (!id) { errors++; continue; }                                  // no id
    if (status === 'not-tracked') continue;                           // export placeholder: skip
    if (!VALID_STATUSES.has(status)) { errors++; continue; }          // bad status

    if (TECH_ID.test(id)) {
      unmatched.push({ row: rowNo, id: id.toUpperCase(), reason: TECHNIQUE_ID_REASON });
      continue;
    }
    let stix: string | undefined;
    if (STIX_MIT.test(id)) stix = mitStixIds.has(id) ? id : undefined;
    else if (MIT_ATTACK_ID.test(id)) stix = mitByAttackId.get(id.toUpperCase());

    if (stix) {
      matchedByStix.set(stix, status as ImplStatus);                  // last row for this mitigation wins
    } else {
      const shown = MIT_ATTACK_ID.test(id) ? id.toUpperCase() : id;
      const reason = MIT_ATTACK_ID.test(id) || STIX_MIT.test(id)
        ? `no mitigation with this id in ${domain.name}`
        : 'unrecognised id (expected a mitigation id)';
      unmatched.push({ row: rowNo, id: shown, reason });
    }
  }
  return build();
}
