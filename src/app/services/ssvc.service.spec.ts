// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { KEV_LIVE, KEV_UNAVAILABLE, NvdCveItem, kevSnapshot } from '../models/cve';
import { DECISION_BLOCKED, DEFAULT_ENVIRONMENT, SsvcResult, SsvcService } from './ssvc.service';

/** Minimal stand-ins for the two CERT/CC tables, in the asset's own shape. */
const TABLES = {
  __meta: { source: 'test', generated: '2026-01-01' },
  tables: {
    'cisa-coordinator': {
      id: 'cisa-coordinator',
      label: 'CISA Coordinator SSVC v2.0.3',
      describes: 'Prioritization outcome',
      url: 'https://example.invalid/coordinator.csv',
      columns: [
        'Exploitation v1.1.0',
        'Automatable v2.0.0',
        'Technical Impact v1.0.0',
        'Mission and Well-Being Impact v1.0.0',
      ],
      outcomeColumn: 'CISA Levels v1.1.0 (cisa)',
      outcomes: ['track', 'act'],
      rows: [
        { key: ['active', 'yes', 'total', 'medium'], outcome: 'act' },
        { key: ['none', 'no', 'partial', 'medium'], outcome: 'track' },
      ],
    },
    'bod-26-04': {
      id: 'bod-26-04',
      label: 'CISA BOD 26-04 Remediation Timelines v1.0.0',
      describes: 'Remediation timeline',
      url: 'https://example.invalid/bod.csv',
      columns: [
        'In KEV v1.0.0 (cisa)',
        'Publicly Exposed v1.0.0 (cisa)',
        'Automatable v2.0.0',
        'Technical Impact v1.0.0',
      ],
      outcomeColumn: 'CISA BOD 26-04 Remediation Timelines v1.0.0 (cisa)',
      outcomes: ['3 days & forensic investigation', 'fix on system upgrade'],
      rows: [
        { key: ['yes', 'yes', 'yes', 'total'], outcome: '3 days & forensic investigation' },
        { key: ['no', 'no', 'no', 'partial'], outcome: 'fix on system upgrade' },
      ],
    },
  },
};

function cve(over: Partial<NvdCveItem> = {}): NvdCveItem {
  return {
    id: 'CVE-2021-44228',
    description: 'test',
    cvssScore: 10,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    severity: 'CRITICAL',
    cwes: [],
    cpes: [],
    published: '',
    lastModified: '',
    references: [],
    mappedAttackIds: [],
    isKev: true,
    kevKnownRansomware: true,
    ...over,
  };
}

describe('SsvcService', () => {
  let service: SsvcService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ imports: [HttpClientTestingModule] });
    service = TestBed.inject(SsvcService);
    httpMock = TestBed.inject(HttpTestingController);
    httpMock.expectOne('assets/data/ssvc-decision-tables.json').flush(TABLES);
  });

  afterEach(() => httpMock.verify());

  it('loads the decision tables', () => {
    expect(service.available).toBe(true);
  });

  it('derives the worst case for a KEV CVE with a total-impact network vector', () => {
    const r = service.evaluate(cve());
    expect(r.action).toBe('act');
    expect(r.timeline).toBe('3 days & forensic investigation');
  });

  it('records the basis of every decision point', () => {
    const r = service.evaluate(cve());
    expect(r.points.every(p => p.basis.length > 0)).toBe(true);
  });

  it('marks the two environmental points as environmental, not derived', () => {
    const r = service.evaluate(cve());
    const kinds = new Map(r.points.map(p => [p.label, p.kind]));
    expect(kinds.get('Publicly Exposed')).toBe('environmental');
    expect(kinds.get('Mission & Well-Being')).toBe('environmental');
    expect(kinds.get('Exploitation')).toBe('derived');
  });

  it('falls back conservatively and warns when no CVSS vector is published', () => {
    const r = service.evaluate(cve({ cvssVector: null, isKev: false }));
    const values = new Map(r.points.map(p => [p.label, p.value]));
    expect(values.get('Automatable')).toBe('no');
    expect(values.get('Technical Impact')).toBe('partial');
    expect(r.warnings.some(w => w.includes('provisional'))).toBe(true);
  });

  it('honours an analyst override and says so in the basis', () => {
    const r = service.evaluate(
      cve({ isKev: false }),
      { exposed: 'no', mission: 'medium' },
      { exploitation: 'none', automatable: 'no', impact: 'partial' },
      KEV_LIVE,
    );
    expect(r.action).toBe('track');
    expect(r.timeline).toBe('fix on system upgrade');
    const point = r.points.find(p => p.label === 'Automatable');
    expect(point?.kind).toBe('override');
    expect(point?.basis).toContain('override');
  });

  it('treats an Exploit-tagged NVD reference as a public PoC', () => {
    const r = service.evaluate(
      cve({ isKev: false, references: [{ url: 'https://e.invalid', tags: ['Exploit'] }] }),
      DEFAULT_ENVIRONMENT,
      {},
      KEV_LIVE,
    );
    expect(r.points.find(p => p.label === 'Exploitation')?.value).toBe('public poc');
  });

  // Plan E1.3: missing or failed KEV is exploitation UNKNOWN, never 'track'.
  describe('when no KEV catalogue is on hand (E1.3)', () => {
    /** A CVE that would resolve to 'track' / 'fix on system upgrade' if absence from KEV meant 'not exploited'. */
    const quiet = () => cve({ isKev: false, kevKnownRansomware: false, cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N' });
    const notExposed = { exposed: 'no' as const, mission: 'medium' as const };
    const point = (r: SsvcResult, label: string) => r.points.find(p => p.label === label)!;

    it('reads that CVE as track when the live catalogue is loaded (the control case)', () => {
      const r = service.evaluate(quiet(), notExposed, {}, KEV_LIVE);
      expect(r.action).toBe('track');
      expect(r.timeline).toBe('fix on system upgrade');
      expect(r.actionBlocked).toBeNull();
      expect(r.timelineBlocked).toBeNull();
    });

    it('treats exploitation and KEV membership as unknown and blocks both outcomes, never track', () => {
      const r = service.evaluate(quiet(), notExposed, {}, KEV_UNAVAILABLE);
      expect(point(r, 'Exploitation').value).toBe('unknown');
      expect(point(r, 'Exploitation').basis).toContain('did not load');
      expect(point(r, 'In KEV').value).toBe('unknown');
      expect(r.action).toBe('');
      expect(r.timeline).toBe('');
      expect(r.actionBlocked).toBe('exploitation unknown');
      expect(r.timelineBlocked).toBe('KEV membership unknown');
      expect(r.warnings[0]).toContain('Decision blocked: exploitation unknown');
      expect(r.warnings[0]).toContain('Provisional: exploitation unknown');
      expect(DECISION_BLOCKED).toBe('decision blocked: exploitation unknown');
    });

    it('defaults to no catalogue: a caller that does not pass KEV status gets a blocked decision', () => {
      const r = service.evaluate(quiet(), notExposed);
      expect(r.action).not.toBe('track');
      expect(r.actionBlocked).toBe('exploitation unknown');
    });

    it('never yields track for any input combination while KEV is unknown', () => {
      for (const exposed of ['yes', 'no'] as const) {
        for (const mission of ['low', 'medium', 'high'] as const) {
          for (const references of [[], [{ url: 'https://e.invalid', tags: ['Exploit'] }]]) {
            const r = service.evaluate(cve({ isKev: false, references }), { exposed, mission }, {}, KEV_UNAVAILABLE);
            expect(r.action).withContext(`${exposed}/${mission}/${references.length}`).toBe('');
            expect(r.actionBlocked).toBe('exploitation unknown');
          }
        }
      }
    });

    it('offers unknown as the shown value, so the override control can display it', () => {
      const r = service.evaluate(quiet(), notExposed, {}, KEV_UNAVAILABLE);
      expect(point(r, 'Exploitation').options[0]).toBe('unknown');
      expect(point(r, 'Automatable').options).not.toContain('unknown');
    });

    it('still decides from positive KEV evidence the record carries (a KEV-flagged dossier)', () => {
      const r = service.evaluate(cve(), DEFAULT_ENVIRONMENT, {}, KEV_UNAVAILABLE);
      expect(point(r, 'Exploitation').value).toBe('active');
      expect(r.action).toBe('act');
      expect(r.actionBlocked).toBeNull();
    });

    it('lets an analyst override unblock the decision, and says which input is still unknown', () => {
      const onlyExploitation = service.evaluate(quiet(), notExposed, { exploitation: 'none', automatable: 'no', impact: 'partial' }, KEV_UNAVAILABLE);
      expect(onlyExploitation.action).toBe('track');
      expect(onlyExploitation.actionBlocked).toBeNull();
      expect(onlyExploitation.timelineBlocked).toBe('KEV membership unknown');
      expect(onlyExploitation.warnings[0]).toContain('Set In KEV by hand');

      const both = service.evaluate(quiet(), notExposed, { exploitation: 'none', inKev: 'no', automatable: 'no', impact: 'partial' }, KEV_UNAVAILABLE);
      expect(both.timeline).toBe('fix on system upgrade');
      expect(both.timelineBlocked).toBeNull();
    });
  });

  describe('with the bundled KEV snapshot (E1.3)', () => {
    it('decides from the snapshot and names its date in every KEV-derived basis', () => {
      const r = service.evaluate(cve(), DEFAULT_ENVIRONMENT, {}, kevSnapshot('2026-10-16'));
      expect(r.action).toBe('act');
      const exploitation = r.points.find(p => p.label === 'Exploitation')!;
      expect(exploitation.value).toBe('active');
      expect(exploitation.basis).toContain('bundled CISA KEV snapshot of 2026-10-16');
      expect(r.points.find(p => p.label === 'In KEV')!.basis).toContain('snapshot of 2026-10-16');
    });

    it('reads absence from the snapshot as not in KEV, dated, and marks the outcome provisional', () => {
      const r = service.evaluate(
        cve({ isKev: false, kevKnownRansomware: false }),
        { exposed: 'no', mission: 'medium' },
        { automatable: 'no', impact: 'partial' },
        kevSnapshot('2026-10-16'),
      );
      expect(r.action).toBe('track');
      expect(r.actionBlocked).toBeNull();
      expect(r.points.find(p => p.label === 'Exploitation')!.basis).toContain('snapshot of 2026-10-16');
      expect(r.warnings.some(w => w.includes('snapshot of 2026-10-16') && w.includes('provisional'))).toBe(true);
    });
  });

  it('sorts by urgency and by deadline', () => {
    expect(service.actionRank('act')).toBeLessThan(service.actionRank('track'));
    expect(service.timelineDays('3 days')).toBe(3);
    expect(service.timelineDays('fix on system upgrade')).toBe(Number.MAX_SAFE_INTEGER);
  });
});
