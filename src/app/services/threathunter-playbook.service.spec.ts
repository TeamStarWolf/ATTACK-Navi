// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { ThreatHunterPlaybookService } from './threathunter-playbook.service';

describe('ThreatHunterPlaybookService', () => {
  let service: ThreatHunterPlaybookService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ThreatHunterPlaybookService);
  });

  describe('getPlaybookCount', () => {
    it('returns a non-negative number', () => {
      expect(service.getPlaybookCount('T1059')).toBeGreaterThanOrEqual(0);
    });

    it('returns 0 for unknown technique', () => {
      expect(service.getPlaybookCount('T9999')).toBe(0);
    });
  });

  describe('getPlaybookUrl', () => {
    it('returns null for unknown technique', () => {
      expect(service.getPlaybookUrl('T9999')).toBeNull();
    });
  });

  describe('getHeatScore', () => {
    it('returns a non-negative number', () => {
      expect(service.getHeatScore('T1059')).toBeGreaterThanOrEqual(0);
    });
  });
});
