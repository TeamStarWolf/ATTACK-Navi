// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CveService, CWE_TO_ATTACK } from './cve.service';

describe('CveService', () => {
  let service: CveService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(CveService);
  });

  describe('getAttackToCweIds', () => {
    it('returns CWEs that map to a known ATT&CK technique', () => {
      const cwes = service.getAttackToCweIds('T1190');
      // T1190 (Exploit Public-Facing) maps to multiple CWEs
      expect(cwes.length).toBeGreaterThan(0);
      expect(cwes).toContain('CWE-20');
    });

    it('returns empty array for unknown technique', () => {
      expect(service.getAttackToCweIds('T9999')).toEqual([]);
    });

    it('returns empty array for empty input', () => {
      expect(service.getAttackToCweIds('')).toEqual([]);
    });
  });

  describe('CWE_TO_ATTACK constant', () => {
    it('contains entries for common CWE classes', () => {
      expect(CWE_TO_ATTACK['CWE-79']).toBeTruthy();
      expect(CWE_TO_ATTACK['CWE-89']).toBeTruthy();
      expect(CWE_TO_ATTACK['CWE-22']).toContain('T1190');
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
