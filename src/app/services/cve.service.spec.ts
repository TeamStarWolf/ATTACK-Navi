// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { CveService } from './cve.service';
import { CapecService } from './capec.service';
import { SourceRegistryService } from './source-registry.service';

const KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
const KEV_FALLBACK_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const KEV_SNAPSHOT_URL = 'assets/data/kev-snapshot.json';
const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const LAST_KEV_COUNT_KEY = 'mitre-nav-last-kev-count';

const KEV_ENTRY = {
  cveID: 'CVE-2021-44228', vendorProject: 'Apache', product: 'Log4j2', vulnerabilityName: 'Log4Shell',
  dateAdded: '2021-12-10', shortDescription: '', requiredAction: '', dueDate: '2021-12-24',
  knownRansomwareCampaignUse: 'Known', notes: '',
};

const nvdRecord = (id: string) => ({
  cve: { id, descriptions: [{ lang: 'en', value: 'x' }], metrics: {}, weaknesses: [], references: [] },
});

describe('CveService', () => {
  let service: CveService;
  let httpMock: HttpTestingController;

  const capecEntry = (id: string, attackIds: string[], cweIds: string[]) => ({
    id, name: id, description: '', likelihood: '', severity: '', attackIds, cweIds,
    url: `https://capec.mitre.org/data/definitions/${id.replace('CAPEC-', '')}.html`,
  });

  const mockCapec = {
    getCapecForCwe: (cwe: string) =>
      cwe === 'CWE-89' ? [capecEntry('CAPEC-66', ['T1190', 'T1059'], ['CWE-89'])] : [],
    getCapecForTechnique: (attackId: string) =>
      attackId === 'T1190' ? [capecEntry('CAPEC-66', ['T1190'], ['CWE-89', 'CWE-20'])] : [],
  };

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: CapecService, useValue: mockCapec },
      ],
    });
    service = TestBed.inject(CveService);
    httpMock = TestBed.inject(HttpTestingController);
    localStorage.removeItem(LAST_KEV_COUNT_KEY);
  });

  afterEach(() => localStorage.removeItem(LAST_KEV_COUNT_KEY));

  describe('loadKev', () => {
    const failBoth = () => {
      httpMock.expectOne(KEV_URL).error(new ProgressEvent('error'));
      httpMock.expectOne(KEV_FALLBACK_URL).error(new ProgressEvent('error'));
    };
    /** Both live feeds fail, then the bundled snapshot fails too: no catalogue at all. */
    const failAll = () => {
      failBoth();
      httpMock.expectOne(KEV_SNAPSHOT_URL).error(new ProgressEvent('error'));
    };

    it('reports a loaded catalogue only when one actually arrived', () => {
      service.loadKev();
      httpMock.expectOne(KEV_URL).flush({ vulnerabilities: [KEV_ENTRY] });

      expect(service.kevAvailable).toBe(true);
      expect(service.kevError).toBeNull();
      expect(service.isKev('CVE-2021-44228')).toBe(true);
      expect(localStorage.getItem(LAST_KEV_COUNT_KEY)).toBe('1');
    });

    it('does not report a failed fetch as a loaded, empty catalogue', () => {
      let loaded: boolean | undefined;
      service.kevLoaded$.subscribe(v => (loaded = v));
      service.loadKev();
      failAll();

      expect(loaded).toBe(false);
      expect(service.kevAvailable).toBe(false);
      expect(service.kevError).toContain('could not be loaded');
      // No count is recorded for a catalogue that never arrived.
      expect(localStorage.getItem(LAST_KEV_COUNT_KEY)).toBeNull();
    });

    it('retries on the next loadKev() after a failure, and clears the error on success', () => {
      service.loadKev();
      failAll();
      expect(service.kevError).not.toBeNull();

      service.loadKev();
      httpMock.expectOne(KEV_URL).flush({ vulnerabilities: [KEV_ENTRY] });
      expect(service.kevAvailable).toBe(true);
      expect(service.kevError).toBeNull();
    });

    it('treats a 200 with no entries as a failure, not a catalogue of zero CVEs', () => {
      service.loadKev();
      httpMock.expectOne(KEV_URL).flush({ vulnerabilities: [] });
      httpMock.expectOne(KEV_SNAPSHOT_URL).error(new ProgressEvent('error'));
      expect(service.kevAvailable).toBe(false);
      expect(service.kevError).toContain('no KEV entries');
    });

    it('does not fire a second request while one is in flight', () => {
      service.loadKev();
      service.loadKev();
      expect(httpMock.match(KEV_URL).length).toBe(1);
    });

    // E1.3: a dated, bundled snapshot stands in when the live feed fails.
    describe('bundled snapshot fallback (E1.3)', () => {
      const SNAPSHOT = {
        __meta: { snapshotDate: '2026-10-16', catalogVersion: '2026.10.16' },
        vulnerabilities: [{ ...KEV_ENTRY, cveID: 'CVE-2024-3400', dateAdded: '2024-04-12' }],
      };

      it('requests the snapshot only after both live feeds fail', () => {
        service.loadKev();
        httpMock.expectNone(KEV_SNAPSHOT_URL);
        httpMock.expectOne(KEV_URL).flush({ vulnerabilities: [KEV_ENTRY] });
        httpMock.expectNone(KEV_SNAPSHOT_URL);
        expect(service.kevSnapshotDate).toBeNull();
        expect(service.kevContext).toEqual({ available: true, snapshotDate: null });
      });

      it('uses the snapshot of its date when the live feed fails, and records both sources truthfully', () => {
        const registry = TestBed.inject(SourceRegistryService);
        const dates: (string | null)[] = [];
        service.kevSnapshotDate$.subscribe(d => dates.push(d));
        service.loadKev();
        failBoth();
        httpMock.expectOne(KEV_SNAPSHOT_URL).flush(SNAPSHOT);

        expect(service.kevAvailable).toBe(true);
        expect(service.kevSnapshotDate).toBe('2026-10-16');
        expect(dates).toEqual([null, '2026-10-16']);
        expect(service.kevContext).toEqual({ available: true, snapshotDate: '2026-10-16' });
        expect(service.isKev('CVE-2024-3400')).toBe(true);
        // The live failure stays visible: the snapshot is a stand-in, not a recovery.
        expect(service.kevError).toContain('could not be loaded');
        expect(registry.get('cisa-kev').status).toBe('failed');
        const snap = registry.get('cisa-kev-snapshot');
        expect(snap.status).toBe('loaded');
        expect(snap.rows).toBe(1);
        expect(snap.version).toContain('snapshot of 2026-10-16');
        // The new-KEV badge counts live catalogues only.
        expect(localStorage.getItem(LAST_KEV_COUNT_KEY)).toBeNull();
      });

      it('reports no catalogue (exploitation unknown) when the snapshot fails too', () => {
        const registry = TestBed.inject(SourceRegistryService);
        service.loadKev();
        failAll();
        expect(service.kevAvailable).toBe(false);
        expect(service.kevSnapshotDate).toBeNull();
        expect(service.kevContext).toEqual({ available: false, snapshotDate: null });
        expect(registry.get('cisa-kev-snapshot').status).toBe('failed');
      });

      it('does not use an undated snapshot', () => {
        const registry = TestBed.inject(SourceRegistryService);
        service.loadKev();
        failBoth();
        httpMock.expectOne(KEV_SNAPSHOT_URL).flush({ vulnerabilities: SNAPSHOT.vulnerabilities });
        expect(service.kevAvailable).toBe(false);
        expect(registry.get('cisa-kev-snapshot').status).toBe('failed');
        expect(registry.get('cisa-kev-snapshot').lastError).toContain('snapshotDate');
      });

      it('tries the live feed again on Retry while the snapshot stands in, and the live catalogue replaces it', () => {
        service.loadKev();
        failBoth();
        httpMock.expectOne(KEV_SNAPSHOT_URL).flush(SNAPSHOT);
        expect(service.kevSnapshotDate).toBe('2026-10-16');

        service.loadKev();
        httpMock.expectOne(KEV_URL).flush({ vulnerabilities: [KEV_ENTRY] });
        expect(service.kevSnapshotDate).toBeNull();
        expect(service.kevError).toBeNull();
        expect(service.kevContext).toEqual({ available: true, snapshotDate: null });
        expect(service.isKev('CVE-2021-44228')).toBe(true);
        expect(service.isKev('CVE-2024-3400')).toBe(false);
        // Once live, loadKev() is a no-op.
        service.loadKev();
        httpMock.expectNone(KEV_URL);
      });

      it('keeps the snapshot (without refetching it) when a Retry of the live feed fails again', () => {
        service.loadKev();
        failBoth();
        httpMock.expectOne(KEV_SNAPSHOT_URL).flush(SNAPSHOT);
        service.loadKev();
        failBoth();
        httpMock.expectNone(KEV_SNAPSHOT_URL);
        expect(service.kevSnapshotDate).toBe('2026-10-16');
        expect(service.kevAvailable).toBe(true);
      });

      it('never lets a late snapshot replace a live catalogue', () => {
        service.loadKevSnapshot();
        service.loadKev();
        httpMock.expectOne(KEV_URL).flush({ vulnerabilities: [KEV_ENTRY] });
        httpMock.expectOne(KEV_SNAPSHOT_URL).flush(SNAPSHOT);
        expect(service.kevSnapshotDate).toBeNull();
        expect(service.isKev('CVE-2024-3400')).toBe(false);
      });
    });
  });

  describe('fetchCve', () => {
    it('emits and caches the record NVD returns', () => {
      let result: any;
      service.fetchCve('cve-2024-3400').subscribe(r => (result = r));
      httpMock.expectOne(`${NVD_API}?cveId=CVE-2024-3400`).flush({ vulnerabilities: [nvdRecord('CVE-2024-3400')] });

      expect(result?.id).toBe('CVE-2024-3400');
      expect(service.getCachedCve('CVE-2024-3400')?.id).toBe('CVE-2024-3400');
    });

    it('emits null when NVD has no such CVE', () => {
      let result: any = 'unset';
      service.fetchCve('CVE-2024-99999').subscribe(r => (result = r));
      httpMock.expectOne(`${NVD_API}?cveId=CVE-2024-99999`).flush({ vulnerabilities: [] });
      expect(result).toBeNull();
    });

    it('errors the subscriber and mirrors the failure on error$', () => {
      let failed = false;
      let error: string | null = null;
      service.error$.subscribe(e => (error = e));
      service.fetchCve('CVE-2024-3400').subscribe({ error: () => (failed = true) });
      httpMock
        .expectOne(`${NVD_API}?cveId=CVE-2024-3400`)
        .flush('rate limited', { status: 429, statusText: 'Too Many Requests' });

      expect(failed).toBe(true);
      expect(error).toContain('NVD API error');
    });
  });

  describe('searchCves', () => {
    it('clears the spinner and sets error$ on an HTTP failure', () => {
      let loading: boolean | undefined;
      let error: string | null = null;
      service.loading$.subscribe(v => (loading = v));
      service.error$.subscribe(e => (error = e));
      service.searchCves('CVE-2024-3400');
      expect(loading).toBe(true);
      httpMock
        .expectOne(`${NVD_API}?cveId=CVE-2024-3400`)
        .flush('forbidden', { status: 403, statusText: 'Forbidden' });

      expect(loading).toBe(false);
      expect(error).toContain('NVD API error');
    });

    it('publishes results and caches them on success', () => {
      let results: any[] = [];
      service.searchResults$.subscribe(r => (results = r));
      service.searchCves('CVE-2024-3400');
      httpMock.expectOne(`${NVD_API}?cveId=CVE-2024-3400`).flush({ vulnerabilities: [nvdRecord('CVE-2024-3400')] });

      expect(results.map(r => r.id)).toEqual(['CVE-2024-3400']);
      expect(service.getCachedCve('CVE-2024-3400')).not.toBeNull();
    });
  });

  describe('mapCwesToAttackIds (CWE→CAPEC→ATT&CK chain)', () => {
    it('maps CWEs to techniques via published CAPEC chains', () => {
      expect(service.mapCwesToAttackIds(['CWE-89'])).toEqual(['T1059', 'T1190']);
    });

    it('returns no mappings for CWEs without a published chain', () => {
      expect(service.mapCwesToAttackIds(['CWE-99999'])).toEqual([]);
      expect(service.mapCwesToAttackIds([])).toEqual([]);
    });
  });

  describe('getAttackToCweIds', () => {
    it('returns CWEs published as related to a technique', () => {
      const cwes = service.getAttackToCweIds('T1190');
      expect(cwes).toContain('CWE-89');
      expect(cwes).toContain('CWE-20');
    });

    it('returns empty array for unknown technique', () => {
      expect(service.getAttackToCweIds('T9999')).toEqual([]);
    });

    it('returns empty array for empty input', () => {
      expect(service.getAttackToCweIds('')).toEqual([]);
    });
  });

  describe('cache helpers', () => {
    it('getCachedCve returns null for unknown id', () => {
      expect(service.getCachedCve('CVE-9999-99999')).toBeNull();
    });

    it('getCachedCves returns empty for empty input', () => {
      expect(service.getCachedCves([])).toEqual([]);
    });

    it('getAllCachedCves returns array (initially empty)', () => {
      const all = service.getAllCachedCves();
      expect(Array.isArray(all)).toBe(true);
    });
  });
});
