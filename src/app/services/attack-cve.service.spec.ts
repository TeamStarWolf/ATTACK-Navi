// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { AttackCveService } from './attack-cve.service';

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
});
