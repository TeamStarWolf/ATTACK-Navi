// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Plan P1 row E1.6: "data-source ids are normalised case-insensitively
// (macOS:unifiedlog vs macos:unifiedlog)"; acceptance "the data-source filter
// lists each component once". The rendered filter is checked in
// matrix-controls.component.spec.ts; these cases pin the rule and run it over
// the bundled ATT&CK releases with the production parser.
import { HttpClient } from '@angular/common/http';
import { DataService } from '../services/data.service';
import { Domain } from '../models/domain';
import {
  canonicalDataSourceSpellings,
  dataSourceKey,
  distinctDataSourceNames,
  sameDataSource,
} from './data-source-names';

describe('data-source names (E1.6)', () => {
  it('compares names case-insensitively, ignoring surrounding space', () => {
    expect(dataSourceKey(' macOS:unifiedlog ')).toBe('macos:unifiedlog');
    expect(sameDataSource('macOS:unifiedlog', 'macos:unifiedlog')).toBeTrue();
    expect(sameDataSource('NSM:Flow', 'NSM:FLow')).toBeTrue();
    expect(sameDataSource('NSM:Flow', 'NSM:Firewall')).toBeFalse();
    expect(sameDataSource(null, 'x')).toBeFalse();
  });

  it('keeps the spelling used most often, whatever the order of the input', () => {
    const names = ['macOS:unifiedlog', 'macos:unifiedlog', 'macos:unifiedlog', 'WinEventLog:Sysmon'];
    for (const order of [names, [...names].reverse()]) {
      const canonical = canonicalDataSourceSpellings(order);
      expect(canonical.get('macos:unifiedlog')).toBe('macos:unifiedlog');
      expect(canonical.get('wineventlog:sysmon')).toBe('WinEventLog:Sysmon');
      expect(canonical.size).toBe(2);
    }
  });

  it('breaks a tie by ordinal order, so the choice is deterministic', () => {
    expect(canonicalDataSourceSpellings(['EDR:telemetry', 'EDR:Telemetry']).get('edr:telemetry')).toBe('EDR:Telemetry');
    expect(canonicalDataSourceSpellings(['EDR:Telemetry', 'EDR:telemetry']).get('edr:telemetry')).toBe('EDR:Telemetry');
  });

  it('lists each source once, empty names dropped', () => {
    expect(distinctDataSourceNames(['macOS:unifiedlog', '', 'macos:unifiedlog', 'macos:unifiedlog', 'File']))
      .toEqual(['File', 'macos:unifiedlog']);
  });

  describe('over the bundled ATT&CK releases (production parser)', () => {
    const domains: Record<string, Domain> = {};

    beforeAll(async () => {
      const parser = new DataService(null as unknown as HttpClient) as unknown as {
        parseBundle(bundle: unknown, name?: string): Domain;
      };
      for (const d of ['enterprise', 'ics', 'mobile']) {
        const bundle = await fetch(`/assets/data/${d}-attack.json`).then(r => r.json());
        domains[d] = parser.parseBundle(bundle, d);
      }
    }, 120000);

    for (const d of ['enterprise', 'ics', 'mobile']) {
      it(`${d}: no two data components name one source in different spellings`, () => {
        const names = domains[d].dataComponents.map(dc => dc.dataSourceName).filter(Boolean);
        const spellings = new Map<string, Set<string>>();
        for (const n of names) {
          if (!spellings.has(dataSourceKey(n))) spellings.set(dataSourceKey(n), new Set());
          spellings.get(dataSourceKey(n))!.add(n);
        }
        const split = [...spellings.values()].filter(s => s.size > 1).map(s => [...s]);
        expect(split).withContext('sources with more than one spelling').toEqual([]);
        expect(names).toContain('macos:unifiedlog');
        expect(names).not.toContain('macOS:unifiedlog');
      });
    }

    it('enterprise: both unifiedlog components (File Access, Driver Metadata) sit under one source', () => {
      const unified = domains['enterprise'].dataComponents.filter(dc => sameDataSource(dc.dataSourceName, 'macos:unifiedlog'));
      expect(unified.map(dc => dc.name).sort()).toEqual(['Driver Metadata', 'File Access']);
      expect(new Set(unified.map(dc => dc.dataSourceName))).toEqual(new Set(['macos:unifiedlog']));
    });
  });
});
