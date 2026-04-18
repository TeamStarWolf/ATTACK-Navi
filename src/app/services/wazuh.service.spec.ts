// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { WazuhService } from './wazuh.service';

describe('WazuhService', () => {
  let service: WazuhService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(WazuhService);
  });

  describe('getAllRules', () => {
    it('returns the bundled Wazuh rule catalogue', () => {
      const all = service.getAllRules();
      expect(Array.isArray(all)).toBe(true);
      expect(all.length).toBeGreaterThan(0);
    });
  });

  describe('getRulesForTechnique', () => {
    it('returns array (possibly empty) for any technique', () => {
      expect(Array.isArray(service.getRulesForTechnique('T1059'))).toBe(true);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getRulesForTechnique('T9999')).toEqual([]);
    });
  });

  describe('getRulesByGroup', () => {
    it('returns matching group rules or empty', () => {
      const all = service.getAllRules();
      if (all.length === 0) return;
      const group = (all[0] as any).group;
      if (group) {
        const rules = service.getRulesByGroup(group);
        expect(rules.length).toBeGreaterThanOrEqual(1);
      }
    });
  });
});
