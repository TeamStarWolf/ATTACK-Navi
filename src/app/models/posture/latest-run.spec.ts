// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The one latest-run comparator (RP-F decision 24) and the one run-date reading
// it shares with the pill's day (local-date.ts runTime / validationDay).
import { compareRunsNewestFirst, latestRun, sortRunsNewestFirst, storedRunKey, summaryRunKey, type RunOrderKey } from './latest-run';
import { runTime, setRunDateZoneForSpecs, validationDay } from '../local-date';

const CHICAGO = -300;   // America/Chicago in October (CDT)
const TOKYO = 540;      // Asia/Tokyo

const key = (id: string, date: string, status = 'passed'): RunOrderKey => ({ id, date, status });
const ids = (runs: readonly RunOrderKey[]) => sortRunsNewestFirst(runs, k => k).map(k => k.id);

describe('runTime: the one run-date reading (RP-F decision 24)', () => {
  afterEach(() => setRunDateZoneForSpecs(null));

  it('a date-only value is the start of that local day, in the browser zone', () => {
    expect(runTime('2026-10-19')).toBe(new Date(2026, 9, 19).getTime());
  });

  for (const [zone, offset] of [['America/Chicago', CHICAGO], ['Asia/Tokyo', TOKYO]] as const) {
    it(`${zone}: a date-only value is local midnight, and the pill's day prints that day`, () => {
      setRunDateZoneForSpecs(offset);
      expect(runTime('2026-10-19')).toBe(Date.UTC(2026, 9, 19) - offset * 60_000);
      expect(validationDay('2026-10-19')).toBe('10/19/26');
      // A timestamp is its instant; its local day follows the zone.
      expect(runTime('2026-10-19T03:00:00Z')).toBe(Date.UTC(2026, 9, 19, 3));
      expect(validationDay('2026-10-19T03:00:00Z')).toBe(offset < 0 ? '10/18/26' : '10/19/26');
    });
  }

  it('a value that is not a date, or names no calendar day, is null and prints as it is', () => {
    for (const bad of ['yesterday', '', 'not a date', '2026-02-30', '2026-13-01']) {
      expect(runTime(bad)).withContext(bad).toBeNull();
    }
    expect(runTime(undefined)).toBeNull();
    expect(runTime(42)).toBeNull();
    expect(validationDay('yesterday')).toBe('yesterday');
    setRunDateZoneForSpecs(TOKYO);
    expect(runTime('2026-02-30')).toBeNull();
  });

  it('a two-digit year stays that year', () => {
    expect(new Date(runTime('0099-01-01') as number).getFullYear()).toBe(99);
    setRunDateZoneForSpecs(CHICAGO);
    expect(new Date((runTime('0099-01-01') as number) + 12 * 3_600_000).getUTCFullYear()).toBe(99);
  });
});

describe('compareRunsNewestFirst / latestRun (RP-F decision 24)', () => {
  afterEach(() => setRunDateZoneForSpecs(null));

  it('orders by instant, never by the runDate string (S19 T1007: offset timestamps)', () => {
    // '2026-10-21T01:30:00+09:00' is 16:30Z on the 20th: earlier than 20:00Z, though its string sorts later.
    const passed = key('p', '2026-10-21T01:30:00+09:00', 'passed');
    const failed = key('f', '2026-10-20T20:00:00Z', 'failed');
    expect(ids([passed, failed])).toEqual(['f', 'p']);
    expect(latestRun([passed, failed], k => k)!.run.id).toBe('f');
  });

  it('on the same instant the run that proves less is the later one, then by id (S18 T1049)', () => {
    const at = '2026-10-20T10:00:00.000Z';
    const order = ['failed', 'no-telemetry', 'not-reproducible', 'untested', 'partial', 'passed', 'some-new-status'];
    const shuffled = [...order].reverse().map((s, i) => key(`r${i}`, at, s));
    expect(sortRunsNewestFirst(shuffled, k => k).map(k => k.status)).toEqual(order);
    expect(ids([key('b', at, 'passed'), key('a', at, 'passed')])).toEqual(['a', 'b']);
    expect(compareRunsNewestFirst(key('a', at), key('a', at))).toBe(0);
  });

  it('an unparseable date sorts oldest, and latestRun flags it (S22 T1497: runDate "yesterday")', () => {
    const runs = [key('y', 'yesterday', 'failed'), key('p', '2026-10-01T00:00:00Z', 'passed'), key('n', 'never', 'passed')];
    expect(ids(runs)).toEqual(['p', 'y', 'n']);
    const latest = latestRun(runs, k => k)!;
    expect([latest.run.id, latest.undated, latest.t]).toEqual(['p', false, Date.parse('2026-10-01T00:00:00Z')]);
    const onlyUndated = latestRun([key('y', 'yesterday', 'failed')], k => k)!;
    expect([onlyUndated.run.id, onlyUndated.undated, onlyUndated.t]).toEqual(['y', true, null]);
  });

  it('latestRun of no runs is null', () => {
    expect(latestRun([], (k: RunOrderKey) => k)).toBeNull();
  });

  // S27 T1059.001: a date-only range run of 10/19 and a manual run at 22:00 on 10/18
  // Chicago time. Date.parse read the date-only value as UTC midnight (19:00 on 10/18
  // in Chicago), so the manual run sorted later and the why line put a later date on
  // the earlier run.
  it('S27 T1059.001 in America/Chicago: the date-only run of 10/19 is the later run', () => {
    setRunDateZoneForSpecs(CHICAGO);
    const range = key('range', '2026-10-19', 'passed');
    const manual = key('manual', '2026-10-18T22:00:00-05:00', 'failed');
    expect(ids([manual, range])).toEqual(['range', 'manual']);
    expect([validationDay(range.date), validationDay(manual.date)]).toEqual(['10/19/26', '10/18/26']);
  });

  it('S27 T1059.001 in Asia/Tokyo: the manual run is 12:00 on 10/19, after the range day began', () => {
    setRunDateZoneForSpecs(TOKYO);
    const range = key('range', '2026-10-19', 'passed');
    const manual = key('manual', '2026-10-18T22:00:00-05:00', 'failed');
    expect(ids([range, manual])).toEqual(['manual', 'range']);
    expect([validationDay(manual.date), validationDay(range.date)]).toEqual(['10/19/26', '10/19/26']);
  });

  it('the keys of a stored run and of a RunSummary read the same fields', () => {
    expect(storedRunKey({ id: 'a', runDate: 'd', status: 's' })).toEqual({ id: 'a', date: 'd', status: 's' });
    expect(summaryRunKey({ runId: 'a', date: 'd', status: 's' })).toEqual({ id: 'a', date: 'd', status: 's' });
  });
});
