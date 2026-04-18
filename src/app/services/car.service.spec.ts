// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CARService } from './car.service';

describe('CARService', () => {
  let service: CARService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(CARService);
  });

  describe('getAll', () => {
    it('returns the bundled CAR analytic catalogue', () => {
      const all = service.getAll();
      expect(all.length).toBeGreaterThan(0);
      expect(all[0].id).toMatch(/^CAR-/);
      expect(all[0].name).toBeTruthy();
      expect(all[0].url).toContain('car.mitre.org');
    });
  });

  describe('getAnalytics', () => {
    it('returns analytics for a known mapped technique', () => {
      const analytics = service.getAnalytics('T1059.003');
      expect(analytics.length).toBeGreaterThanOrEqual(1);
      expect(analytics[0].attackIds).toContain('T1059.003');
    });

    it('returns empty array for unknown technique', () => {
      expect(service.getAnalytics('T9999')).toEqual([]);
    });
  });

  describe('getLiveCount', () => {
    it('returns the current count for a known technique', () => {
      const count = service.getLiveCount('T1059.003');
      expect(count).toBeGreaterThanOrEqual(1);
    });

    it('returns 0 for unknown technique', () => {
      expect(service.getLiveCount('T9999')).toBe(0);
    });
  });
});
