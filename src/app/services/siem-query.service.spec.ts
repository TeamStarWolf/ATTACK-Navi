// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { SiemQueryService, SiemQuery } from './siem-query.service';

const STUB_QUERIES = {
  queries: {
    'T1003.001': [
      {
        platform: 'splunk',
        title: 'LSASS dump',
        description: 'Detect LSASS handle access',
        dataSource: 'Sysmon EventCode 10',
        confidence: 'high',
        query: 'index=windows EventCode=10 TargetImage=lsass',
      },
      {
        platform: 'elastic',
        title: 'LSASS dump (KQL)',
        description: 'Same in KQL',
        dataSource: 'winlogbeat-sysmon',
        confidence: 'high',
        query: 'process where TargetImage : "lsass.exe"',
      },
    ],
  },
};

describe('SiemQueryService', () => {
  let service: SiemQueryService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(SiemQueryService);
    httpMock = TestBed.inject(HttpTestingController);
    const req = httpMock.expectOne('assets/technique-queries.json');
    req.flush(STUB_QUERIES);
  });

  afterEach(() => httpMock.verify());

  it('returns the count of techniques with curated queries', () => {
    expect(service.getCuratedTechniqueCount()).toBe(1);
  });

  it('hasCuratedQueries returns true for known IDs and false for unknown', () => {
    expect(service.hasCuratedQueries('T1003.001')).toBe(true);
    expect(service.hasCuratedQueries('T9999')).toBe(false);
  });

  it('getQueriesForTechnique returns curated queries when present (ignoring tactic)', () => {
    const queries = service.getQueriesForTechnique('T1003.001', 'credential-access');
    expect(queries.length).toBe(2);
    expect(queries[0].platform).toBe('splunk');
    expect(queries[0].platformLabel).toBe('Splunk SPL');
    expect(queries[1].platform).toBe('elastic');
    expect(queries[1].platformLabel).toBe('Elastic KQL');
  });

  it('falls back to tactic templates for techniques without curated queries', () => {
    const queries = service.getQueriesForTechnique('T1059', 'execution');
    // tactic template should fire for "execution" — at least one platform query
    expect(queries.length).toBeGreaterThan(0);
    // tactic-template title is templated with the technique ID
    expect(queries.some(q => q.title.includes('T1059'))).toBe(true);
  });

  it('returns empty array when neither curated nor tactic match', () => {
    const queries = service.getQueriesForTechnique('T9999', 'made-up-tactic');
    expect(queries).toEqual([]);
  });

  it('getQueryForPlatform returns the matching platform query', () => {
    const q = service.getQueryForPlatform('T1003.001', 'credential-access', 'splunk');
    expect(q).not.toBeNull();
    expect(q!.platform).toBe('splunk');
    expect(q!.title).toBe('LSASS dump');
  });

  it('getQueryForPlatform returns null when platform missing', () => {
    const q = service.getQueryForPlatform('T1003.001', 'credential-access', 'chronicle');
    expect(q).toBeNull();
  });

  it('getAllPlatforms returns all 5 supported platforms', () => {
    const platforms = service.getAllPlatforms();
    expect(platforms).toEqual(jasmine.arrayContaining(
      ['splunk', 'elastic', 'microsoft', 'chronicle', 'crowdstrike'] as Array<SiemQuery['platform']>
    ));
  });

  it('getAvailableTactics returns at least the canonical 14 tactics', () => {
    const tactics = service.getAvailableTactics();
    expect(tactics).toContain('credential-access');
    expect(tactics).toContain('execution');
    expect(tactics.length).toBeGreaterThanOrEqual(10);
  });

  it('getAllQueriesForTechnique deduplicates across multiple tactics', () => {
    const queries = service.getAllQueriesForTechnique('T1003.001', ['credential-access', 'discovery']);
    // Curated queries take precedence — same titles, no duplicates
    expect(queries.length).toBe(2);
  });
});
