// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The toolbar vintage chip and the Briefing strip (product plan 6.4, epic E1.4).
// Pure functions, so the wording each one shows and announces is unit-tested
// without a component.
import { SourceRecord } from './source-record';

/** The ATT&CK domains, mirrored from DataService.AttackDomain (kept here so this file has no service import). */
export type VintageDomain = 'enterprise' | 'ics' | 'mobile' | 'f3';

/** Where the domain on screen came from (DataService.freshness$). */
export type BundleFreshness = 'bundled' | 'cached' | 'live' | null;

/** What the vintage chip says about the release on screen. */
export interface Vintage {
  /** 'ATT&CK', or 'F3' for the CTID Fight Fraud Framework. */
  framework: string;
  /** The release on screen; before the first load, the pinned release. */
  version: string;
  /** The pinned (bundled) release of this domain. */
  pinnedVersion: string;
  /**
   * pinned: the bundle shipped with the build (decision D2);
   * session: a newer release the user chose for this session only;
   * cached: a cached live copy (no longer emitted since E1.4, kept for the type);
   * loading: nothing is on screen yet.
   */
  state: 'pinned' | 'session' | 'cached' | 'loading';
  /** YYYY-MM-DD from the bundle's own x-mitre-collection 'modified', or '' when it states none. */
  date: string;
}

/** The aggregate source dot of plan 6.4: ok / stale / failed / n/a. */
export type SourceDot = 'ok' | 'stale' | 'failed' | 'n/a';

/** The release on screen, as the vintage chip states it. */
export function vintageOf(
  domain: VintageDomain,
  loaded: { attackVersion: string; attackModified: string } | null,
  freshness: BundleFreshness,
  pinnedVersion: string,
): Vintage {
  const framework = domain === 'f3' ? 'F3' : 'ATT&CK';
  if (!loaded || !freshness) {
    return { framework, version: pinnedVersion, pinnedVersion, state: 'loading', date: '' };
  }
  const state = freshness === 'bundled' ? 'pinned' : freshness === 'live' ? 'session' : 'cached';
  return {
    framework,
    version: loaded.attackVersion || pinnedVersion,
    pinnedVersion,
    state,
    date: /^\d{4}-\d{2}-\d{2}/.test(loaded.attackModified ?? '') ? loaded.attackModified.slice(0, 10) : '',
  };
}

/** The word the chip shows for each state. */
export function vintageStateLabel(state: Vintage['state']): string {
  switch (state) {
    case 'pinned': return 'pinned';
    case 'session': return 'this session only';
    case 'cached': return 'cached';
    default: return 'loading';
  }
}

/** The chip's accessible name and tooltip: everything it shows, in words, and where it leads. */
export function vintageDescription(v: Vintage, dot: SourceDot, counts: { failed: number; stale: number }): string {
  const parts: string[] = [];
  if (v.state === 'loading') {
    parts.push(`${v.framework} ${v.version} (pinned), loading`);
  } else if (v.state === 'session') {
    parts.push(`${v.framework} ${v.version}, chosen for this session only; the pinned release is ${v.pinnedVersion}`);
  } else {
    parts.push(`${v.framework} ${v.version} (${vintageStateLabel(v.state)})`);
  }
  if (v.state !== 'loading') {
    parts.push(v.date ? `bundle dated ${v.date}` : 'the bundle states no release date');
  }
  parts.push(sourceDotDescription(dot, counts));
  return `${parts.join('; ')}. Open data health.`;
}

function sourceDotDescription(dot: SourceDot, counts: { failed: number; stale: number }): string {
  switch (dot) {
    case 'failed': return `sources: ${counts.failed} failed`;
    case 'stale': return `sources: ${counts.stale} stale, none failed`;
    case 'ok': return 'sources: none failed or stale';
    default: return 'sources: no status yet';
  }
}

/** How many sources are failed and stale now. */
export function sourceCounts(records: readonly SourceRecord[]): { failed: number; stale: number } {
  return {
    failed: records.filter(r => r.status === 'failed').length,
    stale: records.filter(r => r.status === 'stale').length,
  };
}

/** One dot for every source: failed beats stale beats ok; n/a when there are no records. */
export function aggregateSourceDot(records: readonly SourceRecord[]): SourceDot {
  if (!records.length) return 'n/a';
  const { failed, stale } = sourceCounts(records);
  if (failed) return 'failed';
  if (stale) return 'stale';
  return 'ok';
}

/** The date a stand-in snapshot was taken ('snapshot of YYYY-MM-DD' in its version), or its version. */
export function snapshotDateOf(record: SourceRecord): string {
  const m = /snapshot of (\d{4}-\d{2}-\d{2})/.exec(record.version ?? '');
  return m ? m[1] : (record.reviewedDate ?? record.version ?? 'an unknown date');
}

/** The ATT&CK update offer, as DataService.update$ states it (structural, so this file needs no service import). */
export interface BriefingUpdate {
  status: string;
  pinnedVersion?: string;
  liveVersion?: string;
}

/** One sentence of the Briefing strip. */
export interface BriefingItem {
  kind: 'failed' | 'empty' | 'snapshot' | 'update';
  text: string;
}

/** At most this many source names are spelled out per sentence; the rest are counted. */
export const BRIEFING_NAME_LIMIT = 3;

function nameList(names: string[]): string {
  if (names.length <= BRIEFING_NAME_LIMIT) return names.join(', ');
  const more = names.length - BRIEFING_NAME_LIMIT;
  return `${names.slice(0, BRIEFING_NAME_LIMIT).join(', ')} and ${more} more`;
}

function hasData(r: SourceRecord | undefined): boolean {
  return !!r && ['loaded', 'stale', 'archived-upstream'].includes(r.status) && (r.rows ?? 1) > 0;
}

/**
 * What the Briefing strip says, in order: failed sources, empty sources, the stand-in
 * snapshots in use ('using snapshot of <date>'), and the ATT&CK update on offer or in
 * use. An empty list means there is nothing to report.
 */
export function briefingItems(records: readonly SourceRecord[], update: BriefingUpdate | null): BriefingItem[] {
  const items: BriefingItem[] = [];
  const failed = records.filter(r => r.status === 'failed');
  if (failed.length) {
    const lead = failed.length === 1 ? '1 source failed' : `${failed.length} sources failed`;
    items.push({ kind: 'failed', text: `${lead}: ${nameList(failed.map(r => r.name))}.` });
  }
  const empty = records.filter(r => r.status === 'empty');
  if (empty.length) {
    const lead = empty.length === 1 ? '1 source returned no rows' : `${empty.length} sources returned no rows`;
    items.push({ kind: 'empty', text: `${lead}: ${nameList(empty.map(r => r.name))}.` });
  }
  const byId = new Map(records.map(r => [r.id, r]));
  for (const standIn of records) {
    if (!standIn.fallbackFor) continue;
    const target = byId.get(standIn.fallbackFor);
    if (!target || (target.status !== 'failed' && target.status !== 'empty') || !hasData(standIn)) continue;
    items.push({ kind: 'snapshot', text: `${target.name}: using snapshot of ${snapshotDateOf(standIn)}.` });
  }
  if (update?.status === 'available' && update.liveVersion) {
    items.push({
      kind: 'update',
      text: `ATT&CK ${update.liveVersion} is available; this view stays on ${update.pinnedVersion || 'the pinned release'} (pinned) unless you choose it for this session.`,
    });
  } else if (update?.status === 'applied' && update.liveVersion) {
    items.push({
      kind: 'update',
      text: `Using ATT&CK ${update.liveVersion} for this session only; the pinned release is ${update.pinnedVersion || 'unknown'}.`,
    });
  }
  return items;
}

/** The text the strip shows and its live region announces. */
export const BRIEFING_ALL_CLEAR = 'No source failures so far this session.';

export function briefingMessage(items: readonly BriefingItem[]): string {
  return items.length ? items.map(i => i.text).join(' ') : BRIEFING_ALL_CLEAR;
}
