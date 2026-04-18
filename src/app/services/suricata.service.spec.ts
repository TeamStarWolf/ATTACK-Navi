// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { SuricataService } from './suricata.service';

describe('SuricataService', () => {
  let service: SuricataService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(SuricataService);
  });

  describe('getRules', () => {
    it('returns array (possibly empty) for any technique', () => {
      expect(Array.isArray(service.getRules('T1059'))).toBe(true);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getRules('T9999')).toEqual([]);
    });
  });

  describe('hasRules', () => {
    it('returns false for unknown technique', () => {
      expect(service.hasRules('T9999')).toBe(false);
    });
  });

  describe('getRuleCount', () => {
    it('returns a non-negative number', () => {
      expect(service.getRuleCount()).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getSupportedTechniqueIds', () => {
    it('returns an array', () => {
      expect(Array.isArray(service.getSupportedTechniqueIds())).toBe(true);
    });
  });
});
