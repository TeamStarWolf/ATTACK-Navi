// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { YaraService } from './yara.service';
import { AttackIdResolverService } from './attack-id-resolver.service';

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

  describe('retired technique ids', () => {
    it('finds the v19 event-log-clearing pattern under T1685.005', () => {
      expect(service.getPattern('T1685.005')?.meta['description']).toBe('Detects Windows event log clearing');
    });

    it('matches a table key that the loaded release retired to its replacement', () => {
      // Simulate a future release retiring T1059.001 in favour of T1999.001.
      TestBed.inject(AttackIdResolverService).setSupersededBy(new Map([['T1059.001', 'T1999.001']]));
      expect(service.getPattern('T1999.001')?.attackId).toBe('T1059.001');
      // A layer still carrying the retired id reaches the same pattern.
      expect(service.getPattern('T1059.001')?.attackId).toBe('T1059.001');
    });
  });

  describe('hasPattern', () => {
    it('returns false for unknown technique', () => {
      expect(service.hasPattern('T9999')).toBe(false);
    });
  });
});
