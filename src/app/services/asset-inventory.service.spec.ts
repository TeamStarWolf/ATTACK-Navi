// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { AssetInventoryService } from './asset-inventory.service';
import { AttackCveService } from './attack-cve.service';
import { CveService } from './cve.service';
import { EpssService } from './epss.service';
import { of } from 'rxjs';

describe('AssetInventoryService', () => {
  let service: AssetInventoryService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        AssetInventoryService,
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [], getAllCtidMappings: () => [] } },
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
          { provide: AttackCveService, useValue: { getCvesForTechnique: () => [], getAllCtidMappings: () => [] } },
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
});
