// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { C2MappingService } from './c2-mapping.service';

describe('C2MappingService', () => {
  let service: C2MappingService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(C2MappingService);
  });

  describe('getCapabilitiesForTechnique', () => {
    it('returns array (possibly empty) for any input', () => {
      expect(Array.isArray(service.getCapabilitiesForTechnique('T1059'))).toBe(true);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getCapabilitiesForTechnique('T9999')).toEqual([]);
    });
  });

  describe('getFrameworks', () => {
    it('returns a deduplicated framework list', () => {
      const fws = service.getFrameworks();
      expect(Array.isArray(fws)).toBe(true);
      const unique = new Set(fws);
      expect(unique.size).toBe(fws.length);
    });
  });

  describe('getByFramework', () => {
    it('returns capabilities scoped to the requested framework', () => {
      const fws = service.getFrameworks();
      if (fws.length === 0) {
        expect(service.getByFramework('NoSuchFramework')).toEqual([]);
        return;
      }
      const first = fws[0];
      const caps = service.getByFramework(first);
      caps.forEach(c => expect(c.framework).toBe(first));
    });
  });
});
