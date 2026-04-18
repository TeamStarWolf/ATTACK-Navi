// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { ZeekService } from './zeek.service';

describe('ZeekService', () => {
  let service: ZeekService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(ZeekService);
  });

  describe('getScripts', () => {
    it('returns array (possibly empty) for any technique', () => {
      expect(Array.isArray(service.getScripts('T1071'))).toBe(true);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getScripts('T9999')).toEqual([]);
    });
  });

  describe('hasScripts', () => {
    it('returns false for unknown technique', () => {
      expect(service.hasScripts('T9999')).toBe(false);
    });
  });

  describe('getScriptCount', () => {
    it('returns a non-negative number', () => {
      expect(service.getScriptCount()).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getSupportedTechniqueIds', () => {
    it('returns an array', () => {
      expect(Array.isArray(service.getSupportedTechniqueIds())).toBe(true);
    });
  });
});
