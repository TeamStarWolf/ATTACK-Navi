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
  });
});
