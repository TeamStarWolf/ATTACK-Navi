// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import {
  CisaSsvcService,
  decideSsvc,
  ssvcDecisionRange,
  parseCisaSsvcRecord,
} from './cisa-ssvc.service';

/** Build a minimal CVE 5.0 record carrying a CISA SSVC ADP container. */
function recordWithSsvc(options: Record<string, string>[], extra: Record<string, unknown> = {}): any {
  return {
    containers: {
      cna: { metrics: [] },
      adp: [
        { providerMetadata: { shortName: 'CVE' }, metrics: [] },
        {
          providerMetadata: { shortName: 'CISA-ADP' },
          metrics: [
            {
              other: {
                type: 'ssvc',
                content: { id: 'CVE-TEST', role: 'CISA Coordinator', options, version: '2.0.3', timestamp: '2025-02-04T14:25:34Z', ...extra },
              },
            },
          ],
        },
      ],
    },
  };
}

describe('CISA SSVC decision tree (CISA Coordinator v2.0.3)', () => {
  it('maps Log4Shell inputs (active/yes/total) to Act at the default M&W=medium', () => {
    expect(decideSsvc('active', 'yes', 'total')).toBe('Act');
  });

  it('matches the published medium column for representative rows', () => {
    expect(decideSsvc('none', 'no', 'partial')).toBe('Track');
    expect(decideSsvc('poc', 'no', 'total')).toBe('Track*');      // row 16
    expect(decideSsvc('active', 'no', 'total')).toBe('Attend');   // row 28
    expect(decideSsvc('active', 'yes', 'partial')).toBe('Attend');// row 31
  });

  it('honors the Mission & Well-being axis when supplied', () => {
    expect(decideSsvc('active', 'yes', 'total', 'low')).toBe('Attend');  // row 33
    expect(decideSsvc('active', 'yes', 'total', 'high')).toBe('Act');    // row 35
    expect(decideSsvc('none', 'no', 'total', 'high')).toBe('Track*');    // row 5
  });

  it('reports the decision range across M&W, least→most severe', () => {
    expect(ssvcDecisionRange('active', 'yes', 'total')).toEqual(['Attend', 'Act']);
    expect(ssvcDecisionRange('active', 'yes', 'partial')).toEqual(['Attend', 'Act']);
    expect(ssvcDecisionRange('none', 'no', 'partial')).toEqual(['Track']); // invariant
  });
});

describe('parseCisaSsvcRecord', () => {
  it('extracts the three published decision points and computes the decision', () => {
    const rec = recordWithSsvc([
      { Exploitation: 'active' },
      { Automatable: 'yes' },
      { 'Technical Impact': 'total' },
    ]);
    const a = parseCisaSsvcRecord('CVE-2021-44228', rec);
    expect(a).not.toBeNull();
    expect(a!.exploitation).toBe('active');
    expect(a!.automatable).toBe('yes');
    expect(a!.technicalImpact).toBe('total');
    expect(a!.decision).toBe('Act');
    expect(a!.role).toBe('CISA Coordinator');
    expect(a!.version).toBe('2.0.3');
  });

  it('normalizes "public poc" exploitation to the poc branch', () => {
    const rec = recordWithSsvc([
      { Exploitation: 'public poc' },
      { Automatable: 'no' },
      { 'Technical Impact': 'total' },
    ]);
    const a = parseCisaSsvcRecord('CVE-X', rec);
    expect(a!.exploitation).toBe('poc');
    expect(a!.decision).toBe('Track*'); // poc/no/total @ medium
  });

  it('returns null when the record has no SSVC container', () => {
    expect(parseCisaSsvcRecord('CVE-X', { containers: { adp: [] } })).toBeNull();
    expect(parseCisaSsvcRecord('CVE-X', {})).toBeNull();
  });

  it('returns null when a required decision point is missing', () => {
    const rec = recordWithSsvc([{ Exploitation: 'active' }, { Automatable: 'yes' }]);
    expect(parseCisaSsvcRecord('CVE-X', rec)).toBeNull();
  });
});

describe('CisaSsvcService', () => {
  let service: CisaSsvcService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(CisaSsvcService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('fetches, parses and caches an assessment', () => {
    let result: any = undefined;
    service.fetchSsvc('cve-2021-44228').subscribe(a => (result = a));
    const req = http.expectOne('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
    req.flush(recordWithSsvc([
      { Exploitation: 'active' }, { Automatable: 'yes' }, { 'Technical Impact': 'total' },
    ]));
    expect(result.decision).toBe('Act');
    expect(service.getSsvc('CVE-2021-44228')!.decision).toBe('Act');

    // Second call is served from cache (no new HTTP request).
    service.fetchSsvc('CVE-2021-44228').subscribe();
    http.expectNone('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
  });

  it('records an error (not an absence) when the fetch fails, and never throws', () => {
    let result: any = 'unset';
    expect(() =>
      service.fetchSsvc('CVE-9999-0001').subscribe(a => (result = a)),
    ).not.toThrow();
    const req = http.expectOne('https://cveawg.mitre.org/api/cve/CVE-9999-0001');
    req.error(new ProgressEvent('error'), { status: 0, statusText: 'CORS' });
    expect(result).toBeNull();
    expect(service.hasError('CVE-9999-0001')).toBe(true);
    expect(service.getSsvc('CVE-9999-0001')).toBeNull();
  });

  it('badgeClass maps each decision to its SCSS modifier', () => {
    expect(service.badgeClass('Act')).toBe('ssvc-badge--act');
    expect(service.badgeClass('Attend')).toBe('ssvc-badge--attend');
    expect(service.badgeClass('Track*')).toBe('ssvc-badge--track-star');
    expect(service.badgeClass('Track')).toBe('ssvc-badge--track');
  });
});
