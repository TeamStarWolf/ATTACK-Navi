// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { EpssService } from './epss.service';

describe('EpssService', () => {
  let service: EpssService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
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
});
