// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BloodHoundService } from './bloodhound.service';

describe('BloodHoundService', () => {
  let service: BloodHoundService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(BloodHoundService);
  });

  describe('getAllPaths', () => {
    it('returns the bundled BloodHound path catalogue', () => {
      const paths = service.getAllPaths();
      expect(Array.isArray(paths)).toBe(true);
      expect(paths.length).toBeGreaterThan(0);
    });
  });

  describe('getPathsForTechnique', () => {
    it('returns paths array (possibly empty) for any technique', () => {
      const result = service.getPathsForTechnique('T1078');
      expect(Array.isArray(result)).toBe(true);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getPathsForTechnique('T9999')).toEqual([]);
    });
  });

  describe('getPathByName', () => {
    it('returns null for unknown name', () => {
      expect(service.getPathByName('made-up-name-xyz')).toBeNull();
    });
  });
});
