// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import {
  ENTERPRISE_TACTIC_ORDER,
  resolveTacticEntry,
  tacticAliases,
  tacticDisplayName,
  tacticIndex,
  tacticLabel,
  tacticOrderFor,
  tacticsEquivalent,
  techniqueBelongsToColumn,
} from './attack-tactics';
import { Domain } from '../models/domain';
import { Tactic } from '../models/tactic';

function tactic(shortname: string, name: string, order: number): Tactic {
  return { id: `x-mitre-tactic--${shortname}`, attackId: 'TA0000', name, shortname, description: '', url: '', order };
}

/** A Domain stub carrying only what the tactic helpers read. */
function domainWith(tactics: Tactic[]): Domain {
  return { tactics } as unknown as Domain;
}

describe('attack-tactics helpers', () => {
  describe('ENTERPRISE_TACTIC_ORDER', () => {
    it('is the v19 kill chain: stealth and defense-impairment replace defense-evasion', () => {
      expect(ENTERPRISE_TACTIC_ORDER).not.toContain('defense-evasion');
      const privesc = ENTERPRISE_TACTIC_ORDER.indexOf('privilege-escalation');
      expect(ENTERPRISE_TACTIC_ORDER[privesc + 1]).toBe('stealth');
      expect(ENTERPRISE_TACTIC_ORDER[privesc + 2]).toBe('defense-impairment');
      expect(ENTERPRISE_TACTIC_ORDER[privesc + 3]).toBe('credential-access');
      expect(ENTERPRISE_TACTIC_ORDER[0]).toBe('reconnaissance');
      expect(ENTERPRISE_TACTIC_ORDER[ENTERPRISE_TACTIC_ORDER.length - 1]).toBe('impact');
      expect(ENTERPRISE_TACTIC_ORDER.length).toBe(15);
    });
  });

  describe('tacticAliases', () => {
    it('starts with the slug itself and lists the other generations', () => {
      expect(tacticAliases('stealth')[0]).toBe('stealth');
      expect(tacticAliases('stealth')).toContain('defense-evasion');
      expect(tacticAliases('defense-evasion')).toEqual(jasmine.arrayContaining(['stealth', 'defense-impairment']));
      expect(tacticAliases('evasion')).toContain('stealth');
    });

    it('returns only the slug for tactics that were never renamed', () => {
      expect(tacticAliases('execution')).toEqual(['execution']);
      expect(tacticAliases('made-up')).toEqual(['made-up']);
    });

    it('tacticsEquivalent is symmetric across generations', () => {
      expect(tacticsEquivalent('defense-evasion', 'stealth')).toBeTrue();
      expect(tacticsEquivalent('stealth', 'defense-evasion')).toBeTrue();
      expect(tacticsEquivalent('execution', 'stealth')).toBeFalse();
    });
  });

  describe('resolveTacticEntry', () => {
    const table: Record<string, string> = { 'stealth': 'S', 'execution': 'E' };

    it('prefers the exact key', () => {
      expect(resolveTacticEntry(table, 'execution')).toEqual({ key: 'execution', value: 'E' });
    });

    it('falls back to an alias and reports which key matched', () => {
      expect(resolveTacticEntry(table, 'defense-evasion')).toEqual({ key: 'stealth', value: 'S' });
      expect(resolveTacticEntry(table, 'evasion')).toEqual({ key: 'stealth', value: 'S' });
      expect(resolveTacticEntry(table, 'defense-impairment')).toEqual({ key: 'stealth', value: 'S' });
    });

    it('returns undefined when neither the slug nor an alias is present', () => {
      expect(resolveTacticEntry(table, 'impact')).toBeUndefined();
      expect(resolveTacticEntry({}, 'stealth')).toBeUndefined();
    });

    it('never resolves through inherited Object properties', () => {
      expect(resolveTacticEntry(table, 'constructor')).toBeUndefined();
    });
  });

  describe('tacticOrderFor', () => {
    it('uses the domain order (matrix tactic_refs), not the static list', () => {
      const d = domainWith([
        tactic('impact', 'Impact', 2),
        tactic('evasion', 'Evasion', 1),
        tactic('initial-access', 'Initial Access', 0),
      ]);
      expect(tacticOrderFor(d)).toEqual(['initial-access', 'evasion', 'impact']);
    });

    it('falls back to the Enterprise v19 order without a domain', () => {
      expect(tacticOrderFor(null)).toEqual([...ENTERPRISE_TACTIC_ORDER]);
      expect(tacticOrderFor(domainWith([]))).toEqual([...ENTERPRISE_TACTIC_ORDER]);
    });
  });

  describe('tacticIndex', () => {
    it('positions a legacy slug where its successor sits', () => {
      const order = ENTERPRISE_TACTIC_ORDER;
      expect(tacticIndex(order, 'defense-evasion')).toBe(order.indexOf('stealth'));
      expect(tacticIndex(order, 'stealth')).toBe(order.indexOf('stealth'));
      expect(tacticIndex(order, 'unknown')).toBe(-1);
    });

    it('positions a v19 slug in a Mobile-style order that still has defense-evasion', () => {
      const mobile = ['initial-access', 'execution', 'defense-evasion', 'impact'];
      expect(tacticIndex(mobile, 'defense-impairment')).toBe(2);
    });
  });

  describe('tacticLabel / tacticDisplayName', () => {
    it('title-cases slugs', () => {
      expect(tacticLabel('defense-impairment')).toBe('Defense Impairment');
      expect(tacticLabel('stealth')).toBe('Stealth');
      expect(tacticLabel('command-and-control')).toBe('Command And Control');
    });

    it('prefers the loaded domain name, including through aliases', () => {
      const d = domainWith([tactic('command-and-control', 'Command and Control', 0), tactic('stealth', 'Stealth', 1)]);
      expect(tacticDisplayName(d, 'command-and-control')).toBe('Command and Control');
      expect(tacticDisplayName(d, 'defense-evasion')).toBe('Stealth');
      expect(tacticDisplayName(d, 'impact')).toBe('Impact');
      expect(tacticDisplayName(null, 'defense-impairment')).toBe('Defense Impairment');
    });
  });

  describe('techniqueBelongsToColumn', () => {
    const v19 = new Set(ENTERPRISE_TACTIC_ORDER);

    it('matches a column directly', () => {
      expect(techniqueBelongsToColumn(['stealth'], 'stealth', v19)).toBeTrue();
      expect(techniqueBelongsToColumn(['stealth'], 'impact', v19)).toBeFalse();
    });

    it('places a pre-v19 defense-evasion technique in both successor columns', () => {
      expect(techniqueBelongsToColumn(['defense-evasion'], 'stealth', v19)).toBeTrue();
      expect(techniqueBelongsToColumn(['defense-evasion'], 'defense-impairment', v19)).toBeTrue();
      expect(techniqueBelongsToColumn(['defense-evasion'], 'execution', v19)).toBeFalse();
    });

    it('does not alias a slug the loaded domain still has', () => {
      const mobile = new Set(['initial-access', 'defense-evasion', 'impact']);
      expect(techniqueBelongsToColumn(['defense-evasion'], 'defense-evasion', mobile)).toBeTrue();
      // a v19-tagged custom technique lands in Mobile's defense-evasion column
      expect(techniqueBelongsToColumn(['stealth'], 'defense-evasion', mobile)).toBeTrue();
    });
  });
});
