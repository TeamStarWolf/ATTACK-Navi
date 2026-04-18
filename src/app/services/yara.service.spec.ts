// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { YaraService } from './yara.service';

describe('YaraService', () => {
  let service: YaraService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(YaraService);
  });

  describe('getAllPatterns', () => {
    it('returns the bundled YARA pattern catalogue', () => {
      const all = service.getAllPatterns();
      expect(Array.isArray(all)).toBe(true);
      expect(all.length).toBeGreaterThan(0);
    });
  });

  describe('getPattern', () => {
    it('returns null for unknown technique', () => {
      expect(service.getPattern('T9999')).toBeNull();
    });
  });

  describe('hasPattern', () => {
    it('returns false for unknown technique', () => {
      expect(service.hasPattern('T9999')).toBe(false);
    });
  });
});
