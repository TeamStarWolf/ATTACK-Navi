// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { NvdCveItem } from '../models/cve';
import { SsvcService } from './ssvc.service';

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
    );
    expect(r.points.find(p => p.label === 'Exploitation')?.value).toBe('public poc');
  });

  it('sorts by urgency and by deadline', () => {
    expect(service.actionRank('act')).toBeLessThan(service.actionRank('track'));
    expect(service.timelineDays('3 days')).toBe(3);
    expect(service.timelineDays('fix on system upgrade')).toBe(Number.MAX_SAFE_INTEGER);
  });
});
