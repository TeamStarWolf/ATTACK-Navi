// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { AttackCveService } from './attack-cve.service';

/**
 * Match a request by its host, not by substring.
 *
 * `url.includes('api.github.com')` matches any URL that merely contains that text
 * anywhere — including one whose real host is something else entirely. Comparing the
 * parsed host is both accurate and what CodeQL's incomplete-url-substring rule asks for.
 */
function fromHost(host: string): (r: { url: string }) => boolean {
  return r => {
    try {
      return new URL(r.url).host === host;
    } catch {
      return false;
    }
  };
}

describe('AttackCveService', () => {
  let service: AttackCveService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AttackCveService);
  });

  describe('getCvesForTechnique', () => {
    it('returns an array (possibly empty) for any input', () => {
      const cves = service.getCvesForTechnique('T1190');
      expect(Array.isArray(cves)).toBe(true);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getCvesForTechnique('T9999')).toEqual([]);
    });
  });

  describe('getMappingForCve', () => {
    it('returns undefined for unknown CVE', () => {
      expect(service.getMappingForCve('CVE-9999-9999')).toBeUndefined();
    });
  });

  describe('getKevCvesForTechnique', () => {
    it('returns an array', () => {
      expect(Array.isArray(service.getKevCvesForTechnique('T1190'))).toBe(true);
    });
  });

  describe('getExploitCvesForTechnique', () => {
    it('returns an array of strings', () => {
      const exploits = service.getExploitCvesForTechnique('T1190');
      expect(Array.isArray(exploits)).toBe(true);
      exploits.forEach(c => expect(typeof c).toBe('string'));
    });
  });

  describe('searchCves', () => {
    it('returns empty for empty query', () => {
      expect(service.searchCves('')).toEqual([]);
    });

    it('returns empty for unknown id', () => {
      expect(service.searchCves('CVE-9999-99999')).toEqual([]);
    });
  });

  describe('KEV snapshot discovery', () => {
    // CTID publishes each KEV mapping under mappings/kev/attack-<ver>/kev-<MM.DD.YYYY>/.
    // A pinned path keeps serving an old snapshot forever once a newer one lands, and
    // does so silently, because the old file is still there.
    function discover(
      versions: string[],
      snapshots: string[],
      opts: { failApi?: boolean } = {},
    ): { url: string } {
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({
        providers: [provideHttpClient(), provideHttpClientTesting()],
      });
      const svc = TestBed.inject(AttackCveService);
      const mock = TestBed.inject(HttpTestingController);

      mock.expectOne(r => new URL(r.url).pathname.includes('attack_to_cve')).flush('');

      const api = mock.expectOne(fromHost('api.github.com'));
      if (opts.failApi) {
        api.flush('rate limited', { status: 403, statusText: 'Forbidden' });
      } else {
        api.flush(versions.map(name => ({ name, type: 'dir' })));
        const sub = mock.expectOne(fromHost('api.github.com'));
        sub.flush(snapshots.map(name => ({ name, type: 'dir' })));
      }

      const data = mock.expectOne(fromHost('raw.githubusercontent.com'));
      const url = data.request.url;
      data.flush({ mapping_objects: [] });
      mock.verify();
      return { url };
    }

    it('picks the highest ATT&CK version, then the latest snapshot date', () => {
      const { url } = discover(
        ['attack-14.1', 'attack-16.1', 'attack-9.0'],
        ['kev-07.28.2025', 'kev-02.13.2025', 'kev-11.04.2024'],
      );
      expect(url).toContain('/attack-16.1/kev-07.28.2025/');
      expect(url).toContain('kev-07.28.2025_attack-16.1-enterprise.json');
    });

    it('compares versions numerically, not as strings', () => {
      // '9.0' sorts above '16.1' lexically; 16.1 is the newer release.
      const { url } = discover(['attack-9.0', 'attack-16.1'], ['kev-01.01.2025']);
      expect(url).toContain('/attack-16.1/');
    });

    it('compares snapshot dates by year, not by leading month', () => {
      // '11.04.2024' sorts above '02.13.2025' as a string; 2025 is newer.
      const { url } = discover(['attack-16.1'], ['kev-11.04.2024', 'kev-02.13.2025']);
      expect(url).toContain('kev-02.13.2025');
    });

    it('falls back to the pinned snapshot when the listing is unavailable', () => {
      // Rate limiting must not cost the mapping entirely.
      const { url } = discover([], [], { failApi: true });
      expect(url).toContain('kev-07.28.2025');
    });

    it('falls back to the pinned snapshot when a discovered path does not serve', fakeAsync(() => {
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({
        providers: [provideHttpClient(), provideHttpClientTesting()],
      });
      TestBed.inject(AttackCveService);
      const mock = TestBed.inject(HttpTestingController);

      mock.expectOne(r => new URL(r.url).pathname.includes('attack_to_cve')).flush('');
      mock.expectOne(fromHost('api.github.com'))
        .flush([{ name: 'attack-99.9', type: 'dir' }]);
      mock.expectOne(fromHost('api.github.com'))
        .flush([{ name: 'kev-01.01.2099', type: 'dir' }]);

      // retryWithBackoff makes 3 further attempts at 1s, 2s and 4s before giving up.
      const fail = () =>
        mock.expectOne(r => new URL(r.url).pathname.includes('attack-99.9'))
          .flush('gone', { status: 404, statusText: 'Not Found' });
      fail();
      for (const delay of [1000, 2000, 4000]) {
        tick(delay);
        fail();
      }

      // Only now does the pinned snapshot get its turn.
      mock.expectOne(r => new URL(r.url).pathname.includes('kev-07.28.2025')).flush({ mapping_objects: [] });
      mock.verify();
    }));
  });
});
