// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { AtomicService } from './atomic.service';

describe('AtomicService', () => {
  let service: AtomicService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AtomicService);
  });

  describe('getTests', () => {
    it('returns array (possibly empty) for any input', () => {
      const tests = service.getTests('T1059.001');
      expect(Array.isArray(tests)).toBe(true);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getTests('T9999')).toEqual([]);
    });
  });

  describe('getTestCount', () => {
    it('returns 0 for unknown technique', () => {
      expect(service.getTestCount('T9999')).toBe(0);
    });

    it('matches getTests().length for known IDs', () => {
      const id = 'T1059.001';
      expect(service.getTestCount(id)).toBe(service.getTests(id).length);
    });
  });

  describe('getAtomicUrl', () => {
    it('returns a GitHub URL containing the technique id', () => {
      const url = service.getAtomicUrl('T1003.001');
      expect(url).toContain('T1003.001');
      expect(url).toContain('github.com');
    });
  });

  describe('getHeatScore', () => {
    it('returns a number ≥ 0', () => {
      const score = service.getHeatScore('T1059');
      expect(score).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getLiveCounts', () => {
    it('returns a ReadonlyMap', () => {
      const m = service.getLiveCounts();
      expect(m instanceof Map).toBe(true);
    });
  });
});
