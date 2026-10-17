// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  BRIEFING_ALL_CLEAR,
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

    it('names failed sources, at most three, and counts the rest', () => {
      const one = briefingItems([rec('a', 'failed')], null);
      expect(briefingMessage(one)).toBe('1 source failed: Source a.');
      const five = briefingItems(['a', 'b', 'c', 'd', 'e'].map(id => rec(id, 'failed')), null);
      expect(briefingMessage(five)).toBe('5 sources failed: Source a, Source b, Source c and 2 more.');
    });

    it("adds 'using snapshot of <date>' only when the stand-in holds data and its source failed", () => {
      const snap = (status: SourceRecord['status'], rows: number | null = 1400) =>
        rec('kev-snap', status, { kind: 'bundled', fallbackFor: 'kev', version: 'snapshot of 2026-10-16, catalogVersion 2026.10.16', rows });
      const kevFailed = rec('kev', 'failed', { name: 'CISA KEV' });
      expect(briefingItems([kevFailed, snap('loaded')], null).map(i => i.kind)).toEqual(['failed', 'snapshot']);
      expect(briefingMessage(briefingItems([kevFailed, snap('loaded')], null)))
        .toBe('1 source failed: CISA KEV. CISA KEV: using snapshot of 2026-10-16.');
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
