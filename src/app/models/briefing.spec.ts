// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  BRIEFING_ALL_CLEAR,
  BRIEFING_REASON_LIMIT,
  EMPTY_SOURCE_DETAIL,
  TREE_LISTING_EMPTY_DETAIL,
  TREE_LISTING_SOURCE_IDS,
  emptyDetailOf,
  shortReason,
  aggregateSourceDot,
  briefingItems,
  briefingMessage,
  snapshotDateOf,
  vintageOf,
} from './briefing';
import { SourceRecord } from './source-record';

function rec(id: string, status: SourceRecord['status'], extra: Partial<SourceRecord> = {}): SourceRecord {
  return {
    id, name: `Source ${id}`, kind: 'live', upstream: 'no upstream', licence: 'project-mit',
    inventoryRow: 'test', owner: 'test', status, lastError: null, lastLoadedAt: null, rows: null, ...extra,
  };
}

describe('briefing model (E1.4 vintage chip and Briefing strip)', () => {
  describe('vintageOf', () => {
    it('is loading, at the pinned version, until a domain and its freshness are known', () => {
      expect(vintageOf('enterprise', null, null, '19.2')).toEqual(
        { framework: 'ATT&CK', version: '19.2', pinnedVersion: '19.2', state: 'loading', date: '' });
    });

    it('maps freshness to pinned / session / cached and reads the date from attackModified', () => {
      const d = { attackVersion: '19.2', attackModified: '2026-08-05T21:33:58.496Z' };
      expect(vintageOf('ics', d, 'bundled', '19.2').state).toBe('pinned');
      expect(vintageOf('ics', d, 'bundled', '19.2').date).toBe('2026-08-05');
      expect(vintageOf('ics', d, 'live', '19.2').state).toBe('session');
      expect(vintageOf('ics', d, 'cached', '19.2').state).toBe('cached');
      expect(vintageOf('f3', { attackVersion: '1.2', attackModified: '' }, 'bundled', '1.2'))
        .toEqual({ framework: 'F3', version: '1.2', pinnedVersion: '1.2', state: 'pinned', date: '' });
    });
  });

  it('aggregateSourceDot: n/a with no records, then failed > stale > ok', () => {
    expect(aggregateSourceDot([])).toBe('n/a');
    expect(aggregateSourceDot([rec('a', 'loaded'), rec('b', 'pending')])).toBe('ok');
    expect(aggregateSourceDot([rec('a', 'loaded'), rec('b', 'stale')])).toBe('stale');
    expect(aggregateSourceDot([rec('a', 'failed'), rec('b', 'stale')])).toBe('failed');
  });

  it('snapshotDateOf reads the date from a "snapshot of" version, else falls back', () => {
    expect(snapshotDateOf(rec('s', 'loaded', { version: 'snapshot of 2026-10-16, catalogVersion 2026.10.16' }))).toBe('2026-10-16');
    expect(snapshotDateOf(rec('s', 'loaded', { version: 'v3', reviewedDate: '2026-10-01' }))).toBe('2026-10-01');
    expect(snapshotDateOf(rec('s', 'loaded', { version: 'v3' }))).toBe('v3');
  });

  describe('briefingItems', () => {
    it('reports nothing when no source failed and no update is pending', () => {
      const items = briefingItems([rec('a', 'loaded'), rec('b', 'pending'), rec('c', 'loading')], { status: 'idle' });
      expect(items).toEqual([]);
      expect(briefingMessage(items)).toBe(BRIEFING_ALL_CLEAR);
    });

    it('names sources that failed to load, at most three, and counts the rest', () => {
      const one = briefingItems([rec('a', 'failed')], null);
      expect(briefingMessage(one)).toBe('1 source failed to load: Source a.');
      const five = briefingItems(['a', 'b', 'c', 'd', 'e'].map(id => rec(id, 'failed')), null);
      expect(briefingMessage(five)).toBe('5 sources failed to load: Source a, Source b, Source c and 2 more.');
    });

    it('gives each failed source a short reason: no URL, no aside, at most BRIEFING_REASON_LIMIT characters', () => {
      const items = briefingItems([
        rec('a', 'failed', { lastError: 'GitHub rate limit reached (60 requests per hour per address); resets at 14:05' }),
        rec('b', 'failed', { lastError: 'not found (branch or path moved): https://api.github.com/repos/o/r/git/trees/main?recursive=1' }),
        rec('c', 'failed', { lastError: 'HTTP 503 Service Unavailable from https://x.test/a' }),
      ], null);
      expect(briefingMessage(items)).toBe(
        '3 sources failed to load: Source a (GitHub rate limit reached; resets at 14:05), Source b (not found), '
        + 'Source c (HTTP 503 Service Unavailable).');
      expect(shortReason('x'.repeat(200)).length).toBe(BRIEFING_REASON_LIMIT);
      expect(shortReason('x'.repeat(200)).endsWith('...')).toBeTrue();
      expect(shortReason(null)).toBe('');
    });

    it('names sources that answered with nothing usable, apart from failed ones, with no reason, retry or technique-id wording', () => {
      // Not tree listings (an empty KEV, EPSS or NVD answer reads this way): no claim about technique ids.
      const one = briefingItems([rec('a', 'empty', { rows: 0 })], null);
      expect(one.map(i => i.kind)).toEqual(['empty']);
      expect(briefingMessage(one)).toBe('1 source answered with nothing usable: Source a.');
      const four = briefingItems(['a', 'b', 'c', 'd'].map(id => rec(id, 'empty', { rows: 0 })), null);
      expect(briefingMessage(four)).toBe('4 sources answered with nothing usable: Source a, Source b, Source c and 1 more.');
      expect(briefingMessage(four)).not.toMatch(/did not load|failed|retry|returned no rows|technique ids/i);
    });

    it("says 'no technique ids' only for the four tree listings, and marks a tree listing in a mixed list", () => {
      expect(TREE_LISTING_SOURCE_IDS).toEqual(['elastic-tree', 'splunk-tree', 'sentinel-attack-tree', 'mdecrevoisier-sigma-tree']);
      const trees = briefingItems(TREE_LISTING_SOURCE_IDS.map(id => rec(id, 'empty', { rows: 0 })), null);
      expect(briefingMessage(trees)).toBe(
        '4 sources answered with no technique ids: Source elastic-tree, Source splunk-tree, Source sentinel-attack-tree and 1 more.');
      const mixed = briefingItems([rec('cisa-kev', 'empty', { rows: 0 }), rec('elastic-tree', 'empty', { rows: 0 })], null);
      expect(briefingMessage(mixed)).toBe(
        '2 sources answered with nothing usable: Source cisa-kev, Source elastic-tree (no technique ids).');
      expect(emptyDetailOf('elastic-tree')).toBe(TREE_LISTING_EMPTY_DETAIL);
      expect(emptyDetailOf('epss')).toBe(EMPTY_SOURCE_DETAIL);
      expect(EMPTY_SOURCE_DETAIL).not.toContain('technique');
    });

    it('says the failed and the empty groups as two sentences when both exist', () => {
      const items = briefingItems([
        rec('e1', 'empty', { rows: 0 }),
        rec('f1', 'failed', { lastError: 'network error: https://x.test/a' }),
        rec('e2', 'empty', { rows: 0 }),
        rec('ok', 'loaded', { rows: 3 }),
      ], null);
      expect(items.map(i => i.kind)).toEqual(['failed', 'empty']);
      expect(briefingMessage(items)).toBe(
        '1 source failed to load: Source f1 (network error). 2 sources answered with nothing usable: Source e1, Source e2.');
    });

    it("adds 'using snapshot of <date>' only when the stand-in holds data and its source failed", () => {
      const snap = (status: SourceRecord['status'], rows: number | null = 1400) =>
        rec('kev-snap', status, { kind: 'bundled', fallbackFor: 'kev', version: 'snapshot of 2026-10-16, catalogVersion 2026.10.16', rows });
      const kevFailed = rec('kev', 'failed', { name: 'CISA KEV' });
      expect(briefingItems([kevFailed, snap('loaded')], null).map(i => i.kind)).toEqual(['failed', 'snapshot']);
      expect(briefingMessage(briefingItems([kevFailed, snap('loaded')], null)))
        .toBe('1 source failed to load: CISA KEV. CISA KEV: using snapshot of 2026-10-16.');
      expect(briefingItems([kevFailed, snap('pending')], null).map(i => i.kind)).toEqual(['failed']);
      expect(briefingItems([kevFailed, snap('loaded', 0)], null).map(i => i.kind)).toEqual(['failed']);
      expect(briefingItems([rec('kev', 'loaded'), snap('loaded')], null)).toEqual([]);
    });

    it('announces the update offer and the session release, and nothing for other check states', () => {
      expect(briefingMessage(briefingItems([], { status: 'available', pinnedVersion: '19.2', liveVersion: '20.0' })))
        .toBe('ATT&CK 20.0 is available; this view stays on 19.2 (pinned) unless you choose it for this session.');
      expect(briefingMessage(briefingItems([], { status: 'applied', pinnedVersion: '19.2', liveVersion: '20.0' })))
        .toBe('Using ATT&CK 20.0 for this session only; the pinned release is 19.2.');
      for (const status of ['idle', 'checking', 'up-to-date']) {
        expect(briefingItems([], { status, pinnedVersion: '19.2', liveVersion: '19.2' })).toEqual([]);
      }
    });
  });
});
