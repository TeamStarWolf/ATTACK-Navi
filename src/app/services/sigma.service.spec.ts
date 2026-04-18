// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { SigmaService } from './sigma.service';

describe('SigmaService', () => {
  let service: SigmaService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(SigmaService);
  });

  describe('getRuleCount', () => {
    it('returns 0 for unknown technique', () => {
      expect(service.getRuleCount('T9999')).toBe(0);
    });

    it('returns a non-negative number for any input', () => {
      expect(service.getRuleCount('T1059')).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getHeatScore', () => {
    it('returns a non-negative number', () => {
      expect(service.getHeatScore('T1059')).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getLiveCounts', () => {
    it('returns a Map', () => {
      expect(service.getLiveCounts() instanceof Map).toBe(true);
    });
  });

  describe('getCachedRules', () => {
    it('returns undefined for unknown technique before any fetch', () => {
      expect(service.getCachedRules('T9999')).toBeUndefined();
    });
  });
});
