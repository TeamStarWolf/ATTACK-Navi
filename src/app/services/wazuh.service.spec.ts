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

    it('every catalogue entry carries a group, a rule id and at least one technique', () => {
      for (const rule of service.getAllRules()) {
        expect(rule.ruleGroup).toBeTruthy();
        expect(rule.ruleId).toMatch(/^\d+$/);
        expect(rule.techniqueIds.length).toBeGreaterThan(0);
      }
    });
  });

  describe('getRulesForTechnique', () => {
    it('returns exactly the catalogue rules that list the technique', () => {
      const expected = service
        .getAllRules()
        .filter(r => r.techniqueIds.includes('T1059'))
        .map(r => r.ruleId)
        .sort();
      const rules = service.getRulesForTechnique('T1059');

      // The catalogue maps several rules to T1059 today; the lookup must return
      // every one of them and nothing else.
      expect(expected.length).toBeGreaterThanOrEqual(2);
      expect(rules.map(r => r.ruleId).sort()).toEqual(expected);
      expect(rules.every(r => r.techniqueIds.includes('T1059'))).toBeTrue();
    });

    it('does not fall a sub-technique back to its parent', () => {
      // T1059.001 is mapped directly (PowerShell audit); T1059.999 is not.
      expect(service.getRulesForTechnique('T1059.001').length).toBeGreaterThan(0);
      expect(service.getRulesForTechnique('T1059.999')).toEqual([]);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getRulesForTechnique('T9999')).toEqual([]);
    });
  });

  describe('getRulesByGroup', () => {
    it('returns only the rules whose ruleGroup matches', () => {
      const rules = service.getRulesByGroup('windows_defender');
      expect(rules.length).toBe(1);
      expect(rules[0].ruleId).toBe('61050');
      expect(rules[0].ruleGroup).toBe('windows_defender');
    });

    it('returns every rule of every group in the catalogue', () => {
      const all = service.getAllRules();
      const groups = [...new Set(all.map(r => r.ruleGroup))];
      expect(groups.length).toBeGreaterThan(1);
      for (const group of groups) {
        const rules = service.getRulesByGroup(group);
        expect(rules.length).toBe(all.filter(r => r.ruleGroup === group).length);
        expect(rules.every(r => r.ruleGroup === group)).toBeTrue();
      }
    });

    it('returns empty for an unknown group', () => {
      expect(service.getRulesByGroup('no_such_group')).toEqual([]);
    });
  });
});
