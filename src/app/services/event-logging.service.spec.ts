// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { EventLoggingService } from './event-logging.service';

describe('EventLoggingService', () => {
  let service: EventLoggingService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(EventLoggingService);
  });

  describe('getLoggingConfig', () => {
    it('returns config(s) for a known mapped technique', () => {
      const cfg = service.getLoggingConfig('T1059.001');  // PowerShell
      expect(cfg.length).toBeGreaterThanOrEqual(1);
      expect(cfg[0].source).toBeTruthy();
      expect(cfg[0].command).toBeTruthy();
    });

    it('returns empty for unknown technique', () => {
      expect(service.getLoggingConfig('T9999')).toEqual([]);
    });
  });

  describe('getConfigCount', () => {
    it('matches getLoggingConfig length', () => {
      const id = 'T1059.001';
      expect(service.getConfigCount(id)).toBe(service.getLoggingConfig(id).length);
    });

    it('returns 0 for unknown technique', () => {
      expect(service.getConfigCount('T9999')).toBe(0);
    });
  });

  describe('getAllMappedTechniques', () => {
    it('returns a non-empty list of mapped technique IDs', () => {
      const ids = service.getAllMappedTechniques();
      expect(ids.length).toBeGreaterThan(0);
      ids.forEach(id => expect(id).toMatch(/^T\d+/));
    });
  });
});
