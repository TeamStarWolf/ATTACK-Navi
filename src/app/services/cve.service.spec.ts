// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CveService } from './cve.service';
import { CapecService } from './capec.service';

describe('CveService', () => {
  let service: CveService;

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
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: CapecService, useValue: mockCapec },
      ],
    });
    service = TestBed.inject(CveService);
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
