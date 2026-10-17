// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { EPSS_CHECK_TIMEOUT_MS, EpssService } from './epss.service';
import { SourceRegistryService } from './source-registry.service';

describe('EpssService', () => {
  let service: EpssService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(EpssService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('returns immediately when all CVEs are cached or input is empty', (done) => {
    service.fetchScores([]).subscribe(map => {
      expect(map.size).toBe(0);
      done();
    });
    httpMock.expectNone(() => true); // no HTTP call
  });

  it('fetches scores for uncached CVEs and caches them', (done) => {
    service.fetchScores(['CVE-2024-0001', 'CVE-2024-0002']).subscribe(map => {
      expect(map.size).toBe(2);
      expect(map.get('CVE-2024-0001')!.epss).toBe(0.42);
      expect(map.get('CVE-2024-0002')!.epss).toBe(0.18);
      // Subsequent fetch should hit cache (no new HTTP)
      service.fetchScores(['CVE-2024-0001']).subscribe(cached => {
        expect(cached.get('CVE-2024-0001')!.epss).toBe(0.42);
        done();
      });
    });

    const req = httpMock.expectOne(r => r.url.includes('first.org'));
    req.flush({
      data: [
        { cve: 'CVE-2024-0001', epss: '0.42', percentile: '0.95', date: '2026-04-17' },
        { cve: 'CVE-2024-0002', epss: '0.18', percentile: '0.50', date: '2026-04-17' },
      ],
    });
  });

  // E1.3: the data-health EPSS entry used to be a hard-coded of(true). It is now a real
  // check against the API, and its outcome is the 'epss' SourceRecord.
  describe('availability check (E1.3)', () => {
    let registry: SourceRegistryService;
    let result: boolean | undefined;
    beforeEach(() => {
      registry = TestBed.inject(SourceRegistryService);
      result = undefined;
    });

    it('makes one small GET and records loaded when the API answers with a score', () => {
      service.checkAvailability().subscribe(r => (result = r));
      expect(registry.get('epss').status).toBe('loading');
      const req = httpMock.expectOne(r => r.url === 'https://api.first.org/data/v1/epss?limit=1');
      expect(req.request.method).toBe('GET');
      req.flush({ data: [{ cve: 'CVE-2024-3400', epss: '0.9', percentile: '0.99', date: '2026-10-17' }] });
      expect(result).toBeTrue();
      expect(registry.get('epss').status).toBe('loaded');
      expect(registry.get('epss').lastLoadedAt).not.toBeNull();
    });

    it('records failed with the reason when the API errors, and never reports it up', () => {
      service.checkAvailability().subscribe(r => (result = r));
      httpMock.expectOne(r => r.url === 'https://api.first.org/data/v1/epss?limit=1').error(new ProgressEvent('error'), { status: 0, statusText: 'Unknown Error' });
      expect(result).toBeFalse();
      const record = registry.get('epss');
      expect(record.status).toBe('failed');
      expect(record.lastError).toContain('network error');
      expect(record.lastLoadedAt).toBeNull();
    });

    it('records failed when the API does not answer in time', fakeAsync(() => {
      service.checkAvailability().subscribe(r => (result = r));
      const req = httpMock.expectOne(r => r.url === 'https://api.first.org/data/v1/epss?limit=1');
      tick(EPSS_CHECK_TIMEOUT_MS + 1);
      expect(req.cancelled).toBeTrue();
      expect(result).toBeFalse();
      expect(registry.get('epss').status).toBe('failed');
      expect(registry.get('epss').lastError).toBe('no answer within 8 s from https://api.first.org/data/v1/epss');
    }));

    it('records empty when the API answers with no scores', () => {
      service.checkAvailability().subscribe(r => (result = r));
      httpMock.expectOne(r => r.url === 'https://api.first.org/data/v1/epss?limit=1').flush({ data: [] });
      expect(result).toBeFalse();
      expect(registry.get('epss').status).toBe('empty');
    });

    it('does not check again once scores have loaded this session', () => {
      registry.succeed('epss', null);
      service.checkAvailability().subscribe(r => (result = r));
      httpMock.expectNone(() => true);
      expect(result).toBeTrue();
    });
  });
});
