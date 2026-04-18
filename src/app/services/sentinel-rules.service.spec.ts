// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { SentinelRulesService } from './sentinel-rules.service';

describe('SentinelRulesService', () => {
  let service: SentinelRulesService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(SentinelRulesService);
  });

  describe('getRuleCount', () => {
    it('returns 0 for unknown technique before any load', () => {
      expect(service.getRuleCount('T9999')).toBe(0);
    });
  });

  describe('getRulesForTechnique', () => {
    it('returns empty array before any load', () => {
      expect(service.getRulesForTechnique('T9999')).toEqual([]);
    });
  });

  describe('loadOnDemand', () => {
    it('does not throw when called', () => {
      expect(() => service.loadOnDemand()).not.toThrow();
    });
  });
});
