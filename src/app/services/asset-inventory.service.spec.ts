// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { AssetInventoryService } from './asset-inventory.service';
import { AttackCveService, CveAttackMapping } from './attack-cve.service';
import { CveService } from './cve.service';
import { EpssService } from './epss.service';
import { BehaviorSubject, of } from 'rxjs';

// The CTID ATT&CK-to-CVE mapping stub: it loads on demand, so it can land after an asset
// is added. `ctid` is what the readers answer; `ctidLoaded$` is its loaded$.
let ctid: CveAttackMapping[] = [];
let ctidLoaded$ = new BehaviorSubject<boolean>(false);
function ctidStub() {
  return {
    loaded$: ctidLoaded$,
    loadOnDemand: jasmine.createSpy('loadOnDemand'),
    getCvesForTechnique: (id: string) => ctid.filter(m => [...m.primaryImpact, ...m.exploitationTechnique].includes(id)),
    getAllCtidMappings: () => ctid,
    getMappingForCve: (id: string) => ctid.find(m => m.cveId === id),
  };
}

describe('AssetInventoryService', () => {
  let service: AssetInventoryService;

  beforeEach(() => {
    localStorage.clear();
    ctid = [];
    ctidLoaded$ = new BehaviorSubject<boolean>(false);
    TestBed.configureTestingModule({
      providers: [
        AssetInventoryService,
        { provide: AttackCveService, useValue: ctidStub() },
        { provide: CveService, useValue: { fetchCveDetails: () => of([]) } },
        { provide: EpssService, useValue: { fetchScores: () => of(new Map()) } },
      ],
    });
    service = TestBed.inject(AssetInventoryService);
  });

  afterEach(() => localStorage.clear());

  describe('getAll', () => {
    it('starts empty', () => {
      expect(service.getAll()).toEqual([]);
    });
  });

  describe('addAsset', () => {
    it('appends a normalized asset with auto id and timestamp', () => {
      const a = service.addAsset({ hostname: 'web-01', os: 'linux', software: ['nginx'] });
      expect(a.id).toBeTruthy();
      expect(a.hostname).toBe('web-01');
      expect(a.addedAt).toBeTruthy();
      expect(service.getAll().length).toBe(1);
    });

    it('persists across service instances via localStorage', () => {
      service.addAsset({ hostname: 'web-01', os: 'linux' });
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({
        providers: [
          AssetInventoryService,
          { provide: AttackCveService, useValue: ctidStub() },
          { provide: CveService, useValue: { fetchCveDetails: () => of([]) } },
          { provide: EpssService, useValue: { fetchScores: () => of(new Map()) } },
        ],
      });
      const fresh = TestBed.inject(AssetInventoryService);
      expect(fresh.getAll().length).toBe(1);
    });
  });

  describe('removeAsset', () => {
    it('removes by id', () => {
      const a = service.addAsset({ hostname: 'doomed', os: 'linux' });
      service.removeAsset(a.id);
      expect(service.getAll()).toEqual([]);
    });
  });

  describe('exportCsv', () => {
    it('returns a CSV string with headers + a row per asset', () => {
      service.addAsset({ hostname: 'web-01', os: 'linux', software: ['nginx', 'openssl'] });
      const csv = service.exportCsv();
      expect(csv).toContain('hostname');
      expect(csv).toContain('web-01');
    });

    it('quotes and formula-neutralises every cell', () => {
      service.addAsset({ hostname: '=HYPERLINK("http://x/","y")', os: 'linux', software: ['a "b"'], tags: ['@t'] });
      const row = service.exportCsv().split('\n')[1];
      expect(row).toBe(`"'=HYPERLINK(""http://x/"",""y"")","linux","a ""b""","'@t","medium"`);
    });

    it('round-trips its own export through importCsv without adding apostrophes', () => {
      service.addAsset({ hostname: '-db01', os: 'say "hi", ok', software: ['nginx', 'openssl'], tags: ['=prod'], criticality: 'high' });
      const csv = service.exportCsv();
      service.clearAll();
      const [asset] = service.importCsv(csv);
      expect(asset.hostname).toBe('-db01');
      expect(asset.os).toBe('say "hi", ok');
      expect(asset.software).toEqual(['nginx', 'openssl']);
      expect(asset.tags).toEqual(['=prod']);
      expect(asset.criticality).toBe('high');
    });
  });

  describe('exposure and the on-demand CTID mapping', () => {
    const log4j: CveAttackMapping = {
      cveId: 'CVE-2021-44228', description: 'Apache Log4j2 JNDI remote code execution', primaryImpact: ['T1059'],
      secondaryImpact: [], exploitationTechnique: ['T1190'], capabilityGroup: 'code_injection', comments: [],
      references: [], phase: '', source: 'ctid-kev',
    };
    let latest: Map<string, number>;
    beforeEach(() => service.exposureMap$.subscribe(m => (latest = m)));

    it('an asset added before the mapping arrived gets its exposure when the mapping lands', () => {
      service.addAsset({ hostname: 'app-01', os: '', software: ['log4j'] });
      // The curated heuristic alone (no CTID rows yet).
      const before = new Map(latest);
      expect(before.has('T1059')).toBeTrue();

      // The mapping arrives: its software-name match adds the CTID techniques of the CVE
      // that names log4j, exactly as an add made with the mapping in would.
      ctid = [{ ...log4j, primaryImpact: ['T1203'], exploitationTechnique: ['T1210'] }];
      ctidLoaded$.next(true);
      expect(latest.get('T1203')).toBe(1);
      expect(latest.get('T1210')).toBe(1);

      const withMappingFirst = new Map(latest);
      service.clearAll();
      service.addAsset({ hostname: 'app-01', os: '', software: ['log4j'] });
      expect(latest).toEqual(withMappingFirst);
    });

    it('does not recompute when the mapping lands with no assets', () => {
      const spy = spyOn(service, 'recomputeExposure').and.callThrough();
      ctidLoaded$.next(true);
      expect(spy).not.toHaveBeenCalled();
    });
  });
});
