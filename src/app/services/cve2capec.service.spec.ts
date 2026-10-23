// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Cve2CapecService } from './cve2capec.service';
import { SourceRegistryService } from './source-registry.service';

const isYearFile = (r: { url: string }) => /\/Galeax\/CVE2CAPEC\/main\/database\/CVE-\d{4}\.jsonl\.gz$/.test(r.url);

describe('Cve2CapecService', () => {
  let service: Cve2CapecService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(Cve2CapecService);
  });

  it('returns empty array for getChainForTechnique on unknown id', () => {
    expect(service.getChainForTechnique('T9999')).toEqual([]);
  });

  it('returns null for getChainForCve on unknown id', () => {
    expect(service.getChainForCve('CVE-9999-9999')).toBeNull();
  });

  it('returns 0 chain count for unknown id', () => {
    expect(service.getChainCount('T9999')).toBe(0);
  });

  it('returns empty defenses array for unknown id', () => {
    expect(service.getDefensesForTechnique('T9999')).toEqual([]);
  });

  // The two year files are about 56 MiB of gzip that inflate to about 1.7 GB: they are
  // fetched only when a view asks, never because the service was created.
  describe('on demand', () => {
    let http: HttpTestingController;
    let registry: SourceRegistryService;

    beforeEach(() => {
      http = TestBed.inject(HttpTestingController);
      registry = TestBed.inject(SourceRegistryService);
    });

    it('makes no request on construction, and the source reads pending', () => {
      http.expectNone(() => true);
      expect(registry.get('cve2capec-runtime').status).toBe('pending');
      // Reading the (empty) index does not start a download either.
      service.getChainCount('T1190');
      http.expectNone(() => true);
    });

    it('requests each year file exactly once after loadOnDemand(), even when called twice', () => {
      service.loadOnDemand();
      service.loadOnDemand();
      const year = new Date().getFullYear();
      const requests = http.match(isYearFile);
      expect(requests.map(r => r.request.url.split('/').pop())).toEqual([`CVE-${year}.jsonl.gz`, `CVE-${year - 1}.jsonl.gz`]);
      expect(registry.get('cve2capec-runtime').status).toBe('loading');
      http.verify();
    });

    it('records a failure on the cve2capec-runtime source by name, and loaded$ stays false', fakeAsync(() => {
      let loaded = true;
      service.loaded$.subscribe(v => (loaded = v));
      service.loadOnDemand();
      // retryWithBackoff: the first attempt and three retries at 1 s, 2 s and 4 s.
      for (const delay of [0, 1000, 2000, 4000]) {
        tick(delay);
        for (const r of http.match(isYearFile)) r.flush(new Blob(['gone']), { status: 404, statusText: 'Not Found' });
      }
      tick();
      http.verify();
      const record = registry.get('cve2capec-runtime');
      expect(record.status).toBe('failed');
      expect(record.lastError).toContain('not found');
      expect(loaded).toBeFalse();
    }));

    it('retry() loads even when nothing asked before ("Load now"), and a later loadOnDemand() adds no request', () => {
      service.retry();
      expect(http.match(isYearFile).length).toBe(2);
      service.loadOnDemand();
      http.expectNone(isYearFile);
    });
  });
});
