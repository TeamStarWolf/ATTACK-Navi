// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { SourceId, V2Envelope, V2Store, fingerprint, readV2, replaceSource, upsertById, writeV2 } from './storage-envelope';

interface Rec extends V2Envelope { readonly id: string; readonly note: string }

const rec = (id: string, source: SourceId, note = id): Rec => ({
  id, note, source, domain: 'enterprise', attackVersion: '19.2',
  createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:00:00.000Z',
});

const isRec = (x: unknown): x is Rec =>
  typeof x === 'object' && x !== null && typeof (x as Rec).id === 'string' && typeof (x as Rec).source === 'string';

const KEY = 'navi.v2.storage-envelope-spec';

describe('storage envelope (Phase 2 design §2.3)', () => {
  beforeEach(() => localStorage.removeItem(KEY));
  afterEach(() => localStorage.removeItem(KEY));

  describe('replaceSource', () => {
    it('replaces only the named source and keeps every other record byte-identical, kept first', () => {
      const existing = [rec('a', 'manual'), rec('b', 'lylat-range:CORNERIA-ROOT-01'), rec('c', 'layer:Red team'), rec('d', 'lylat-range:CORNERIA-ROOT-01')];
      const before = JSON.stringify(existing);
      const incoming = [rec('e', 'lylat-range:CORNERIA-ROOT-01'), rec('f', 'lylat-range:CORNERIA-ROOT-01')];
      const out = replaceSource(existing, incoming, 'lylat-range:CORNERIA-ROOT-01');
      expect(out.map(r => r.id)).toEqual(['a', 'c', 'e', 'f']);
      expect(out[0]).toBe(existing[0]);
      expect(out[1]).toBe(existing[2]);
      expect(JSON.stringify(out.slice(0, 2))).toBe(JSON.stringify([existing[0], existing[2]]));
      expect(JSON.stringify(existing)).withContext('input is not mutated').toBe(before);
    });

    it('with no incoming records, removes the source; with an unknown source, appends', () => {
      const existing = [rec('a', 'manual'), rec('b', 'layer:x')];
      expect(replaceSource(existing, [], 'layer:x').map(r => r.id)).toEqual(['a']);
      expect(replaceSource(existing, [rec('c', 'layer:y')], 'layer:y').map(r => r.id)).toEqual(['a', 'b', 'c']);
    });
  });

  describe('upsertById', () => {
    it('replaces in place, appends new ids and never deletes', () => {
      const existing = [rec('a', 'manual', 'old a'), rec('b', 'manual'), rec('c', 'wizard')];
      const out = upsertById(existing, [rec('b', 'manual', 'new b'), rec('z', 'manual')]);
      expect(out.map(r => r.id)).toEqual(['a', 'b', 'c', 'z']);
      expect(out[1].note).toBe('new b');
      expect(out[0]).toBe(existing[0]);
      expect(upsertById(existing, []).length).toBe(existing.length);
      expect(existing[1].note).withContext('input is not mutated').toBe('b');
    });

    it('when incoming repeats an id, the last one wins', () => {
      const out = upsertById([rec('a', 'manual')], [rec('n', 'manual', 'first'), rec('n', 'manual', 'second'), rec('a', 'manual', 'a2')]);
      expect(out.map(r => [r.id, r.note])).toEqual([['a', 'a2'], ['n', 'second']]);
    });
  });

  describe('fingerprint', () => {
    it('is deterministic FNV-1a 32-bit hex plus the length', () => {
      expect(fingerprint('')).toBe('811c9dc5:0');
      expect(fingerprint('a')).toBe('e40c292c:1');
      expect(fingerprint('foobar')).toBe('bf9cf968:6');
      const raw = JSON.stringify({ 'attack-pattern--1': [{ id: 'r1', result: 'detected' }] });
      expect(fingerprint(raw)).toBe(fingerprint(raw));
      expect(fingerprint(raw)).toMatch(/^[0-9a-f]{8}:\d+$/);
    });

    it('differs when one character changes, and reads UTF-16 code units', () => {
      const raw = '{"runs":[{"id":"r1","result":"detected"}]}';
      const changed = raw.replace('r1', 'r2');
      expect(changed.length).toBe(raw.length);
      expect(fingerprint(changed)).not.toBe(fingerprint(raw));
      expect(fingerprint('\u{1F600}').endsWith(':2')).withContext('a surrogate pair is two code units').toBeTrue();
    });
  });

  describe('readV2 / writeV2', () => {
    it('round-trips a store', () => {
      const store: V2Store<Rec> = { schema: 2, migratedFromV1Fingerprint: 'deadbeef:12', tombstones: ['x'], records: [rec('a', 'manual')] };
      expect(writeV2(KEY, store)).toBeTrue();
      expect(readV2<Rec>(KEY, isRec)).toEqual(store);
    });

    it('returns an empty store when the key is absent', () => {
      expect(readV2<Rec>(KEY, isRec)).toEqual({ schema: 2, tombstones: [], records: [] });
    });

    it('returns an empty store on corrupt JSON or a value that is not a schema-2 store', () => {
      const empty: V2Store<Rec> = { schema: 2, tombstones: [], records: [] };
      for (const raw of ['{not json', 'null', '42', '"text"', '[]', '{"schema":1,"tombstones":[],"records":[]}',
        '{"schema":2,"tombstones":[]}', '{"schema":2,"records":[]}', '{"schema":2,"tombstones":{},"records":[]}']) {
        localStorage.setItem(KEY, raw);
        expect(readV2<Rec>(KEY, isRec)).withContext(raw).toEqual(empty);
      }
    });

    it('skips records that fail the guard, drops non-string tombstones and a non-string fingerprint', () => {
      localStorage.setItem(KEY, JSON.stringify({
        schema: 2, migratedFromV1Fingerprint: 7, tombstones: ['t1', 3, null],
        records: [rec('a', 'manual'), { id: 1 }, null, rec('b', 'wizard')],
      }));
      const store = readV2<Rec>(KEY, isRec);
      expect(store.records.map(r => r.id)).toEqual(['a', 'b']);
      expect(store.tombstones).toEqual(['t1']);
      expect('migratedFromV1Fingerprint' in store).toBeFalse();
    });

    it('returns an empty store when storage throws on read (quota, disabled storage)', () => {
      spyOn(Storage.prototype, 'getItem').and.throwError(new DOMException('denied', 'SecurityError'));
      expect(readV2<Rec>(KEY, isRec)).toEqual({ schema: 2, tombstones: [], records: [] });
    });

    it('returns false when storage throws on write', () => {
      spyOn(Storage.prototype, 'setItem').and.throwError(new DOMException('full', 'QuotaExceededError'));
      expect(writeV2(KEY, { schema: 2, tombstones: [], records: [] })).toBeFalse();
    });
  });
});
