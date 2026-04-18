// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { D3fendService } from './d3fend.service';

describe('D3fendService', () => {
  let service: D3fendService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(D3fendService);
  });

  describe('getAllTechniques', () => {
    it('returns the bundled D3FEND mapping list', () => {
      const all = service.getAllTechniques();
      expect(all.length).toBeGreaterThan(0);
      expect(all[0].id).toMatch(/^D3-/);
      expect(all[0].url).toContain('d3fend');
    });
  });

  describe('getCountermeasures', () => {
    it('returns countermeasures for a known mapped technique', () => {
      const cms = service.getCountermeasures('T1059');
      expect(cms.length).toBeGreaterThanOrEqual(1);
      expect(cms[0].attackIds).toContain('T1059');
    });

    it('returns empty array for unknown technique', () => {
      expect(service.getCountermeasures('T9999')).toEqual([]);
    });
  });

  describe('getAllByCategory', () => {
    it('groups countermeasures by category', () => {
      const grouped = service.getAllByCategory();
      expect(grouped.size).toBeGreaterThanOrEqual(1);
      const categoryNames = [...grouped.keys()];
      // Should contain at least one of the known D3FEND tactic categories
      expect(categoryNames.some(c => ['Harden', 'Detect', 'Isolate', 'Deceive', 'Evict'].includes(c))).toBe(true);
    });
  });
});
