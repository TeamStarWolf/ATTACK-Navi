// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// SourceRecord: one row per data source the application ships or fetches
// (product plan section 6.3, epic E1.3). The registry is the single place that
// says whether a source actually loaded; a loader that fails records 'failed'
// with the error and never reports 'loaded'.

/**
 * Where the data comes from.
 * - bundled: a file shipped in src/assets that the app reads at runtime.
 * - live: fetched from an upstream service while the app runs.
 * - seed: a table compiled into the code, derived from an upstream source.
 * - project-authored: written by hand for this project; it has no upstream.
 */
export type SourceKind = 'bundled' | 'live' | 'seed' | 'project-authored';

/**
 * Load state of a source.
 * - pending: not requested yet in this session (on-demand sources stay here until used).
 * - loading: a request is in flight.
 * - loaded: data arrived and has at least one row.
 * - failed: the request or the parse failed; `lastError` says why. Never shown as loaded.
 * - empty: the request succeeded but carried no usable rows.
 * - stale: data is present but known to lag its upstream (`note` says how).
 * - archived-upstream: data is present (or withdrawn) and the upstream is archived or withdrawn.
 */
export type SourceStatus =
  | 'pending'
  | 'loading'
  | 'loaded'
  | 'failed'
  | 'empty'
  | 'stale'
  | 'archived-upstream';

/** Statuses that mean usable data is on hand. */
export const DATA_PRESENT_STATUSES: readonly SourceStatus[] = ['loaded', 'stale', 'archived-upstream'];

/** Ids of the licence notes in LICENCE_NOTES (source-inventory.ts). */
export type LicenceNoteId =
  | 'attack'
  | 'f3-apache-2.0'
  | 'cwe'
  | 'capec'
  | 'ssvc-sei-mit'
  | 'nvd'
  | 'cve'
  | 'epss'
  | 'kev-cc0'
  | 'd3fend'
  | 'car-apache-2.0'
  | 'engage-apache-2.0'
  | 'ctid-apache-2.0'
  | 'atomic-mit'
  | 'sigma-drl-1.1'
  | 'mdecrevoisier-cc0'
  | 'otrf-mit'
  | 'misp-cc0-mit'
  | 'trickest-mit'
  | 'galeax-gpl-3.0'
  | 'ipsum-unlicense'
  | 'payloads-mit'
  | 'mukul975-apache-2.0'
  | 'exploitdb-terms'
  | 'elastic-license-2.0'
  | 'splunk-apache-2.0'
  | 'm365-hunting-mit'
  | 'sentinel-attack-mit'
  | 'cyb3r-monk-bsd-3'
  | 'nuclei-mit'
  | 'query-library'
  | 'project-mit';

export interface LicenceNote {
  /** Licence or terms, in words. */
  licence: string;
  /** Where THIRD_PARTY_NOTICES.md covers it, or a statement that it does not yet. */
  notice: string;
}

/** The static half of a record: what the source is. */
export interface SourceDefinition {
  /** Stable kebab-case id; the future #/source/:id route uses it. */
  id: string;
  /** Human-readable name. */
  name: string;
  kind: SourceKind;
  /** Version, release, ref or generation stamp. Live sources name the ref they follow ('main, unpinned'). */
  version?: string;
  /** YYYY-MM-DD the content was last reviewed; for project files, the last commit date of the file. */
  reviewedDate?: string;
  /** Upstream URL, or the literal 'no upstream'. */
  upstream: string;
  licence: LicenceNoteId;
  /** The section 6.3 inventory row this source belongs to, or 'not in 6.3' for an extra source. */
  inventoryRow: string;
  /** The code that loads or holds it. */
  owner: string;
  /** Fetched only when a view asks for it (stays 'pending' until then). */
  onDemand?: boolean;
  /** YYYY-MM-DD the upstream was archived or withdrawn; a successful load reports 'archived-upstream'. */
  archivedUpstream?: string;
  /** Status before any load attempt. Defaults: 'pending' for bundled/live, 'loaded' for compiled seeds and tables. */
  initialStatus?: SourceStatus;
  /** One line of context (why stale, what is withdrawn, who reads it). */
  note?: string;
}

/** The live half: definition plus what happened this session. */
export interface SourceRecord extends SourceDefinition {
  status: SourceStatus;
  /** Why the last attempt failed; null unless status is 'failed'. */
  lastError: string | null;
  /** ISO timestamp of the last successful load; null until one happens. */
  lastLoadedAt: string | null;
  /** Rows the last successful load produced, when the loader counts them. */
  rows: number | null;
}
