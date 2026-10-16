// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { DataService } from './data.service';
import { Domain } from '../models/domain';

// The bundled snapshots in src/assets/data power bundled-first loading and the
// air-gapped build. The three ATT&CK domains must ship the same release (ICS and
// Mobile were once left at 18.1 after Enterprise moved to 19.2, so the ICS matrix
// showed retired techniques and missed new ones) and that release must be the one
// the library layers, the Lylat layers and scripts/validate-curated-threat-layers.mjs
// are written against. Bump these constants together with a data refresh.
const BUNDLED_ATTACK_VERSION = '19.2';
const BUNDLED_F3_VERSION = '1.2';
const ATTACK_DOMAINS = ['enterprise', 'ics', 'mobile'] as const;
const BUNDLE_FILES = [...ATTACK_DOMAINS, 'f3'].map(domain => `${domain}-attack.json`);
const FETCH_TIMEOUT_MS = 120_000; // enterprise-attack.json is ~54 MB

describe('bundled data snapshots', () => {
  const bundles = new Map<string, any>();
  const parsed = new Map<string, Domain>();
  let service: DataService;

  beforeAll(async () => {
    for (const file of BUNDLE_FILES) {
      const response = await fetch(`assets/data/${file}`);
      if (!response.ok) throw new Error(`assets/data/${file}: HTTP ${response.status}`);
      bundles.set(file, await response.json());
    }
  }, FETCH_TIMEOUT_MS);

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [{ provide: HttpClient, useValue: { get: () => of({}) } }],
    });
    service = TestBed.inject(DataService);
  });

  // parseBundle is the same code path the app runs on the bundled file; parsing the
  // real snapshot is what proves the domain loads.
  function domainOf(file: string): Domain {
    if (!parsed.has(file)) parsed.set(file, (service as any).parseBundle(bundles.get(file), file));
    return parsed.get(file)!;
  }

  function collectionVersion(file: string): string {
    return bundles.get(file).objects.find((obj: any) => obj.type === 'x-mitre-collection')?.x_mitre_version ?? '';
  }

  for (const domain of ATTACK_DOMAINS) {
    it(`ships ATT&CK ${BUNDLED_ATTACK_VERSION} for the ${domain} domain`, () => {
      expect(domainOf(`${domain}-attack.json`).attackVersion).toBe(BUNDLED_ATTACK_VERSION);
    });
  }

  it('ships one ATT&CK release across the enterprise, ics and mobile snapshots', () => {
    const versions = ATTACK_DOMAINS.map(domain => collectionVersion(`${domain}-attack.json`));
    expect(new Set(versions).size).withContext(versions.join(' / ')).toBe(1);
  });

  it(`ships CTID F3 ${BUNDLED_F3_VERSION}`, () => {
    expect(collectionVersion('f3-attack.json')).toBe(BUNDLED_F3_VERSION);
  });

  it('parses every bundled domain into a non-empty matrix', () => {
    for (const file of BUNDLE_FILES) {
      const domain = domainOf(file);
      expect(domain.tactics.length).withContext(`${file} tactics`).toBeGreaterThan(0);
      expect(domain.techniques.length).withContext(`${file} techniques`).toBeGreaterThan(0);
      for (const technique of domain.techniques) {
        expect(technique.tacticShortnames.every(shortname => domain.tactics.some(tactic => tactic.shortname === shortname)))
          .withContext(`${file} ${technique.attackId} tactics ${technique.tacticShortnames.join(',')}`).toBeTrue();
      }
    }
  });

  it('enterprise 19.2 ships the stealth / defense-impairment split instead of defense-evasion', () => {
    const shortnames = domainOf('enterprise-attack.json').tactics.map(tactic => tactic.shortname);
    expect(shortnames).toContain('stealth');
    expect(shortnames).toContain('defense-impairment');
    expect(shortnames).not.toContain('defense-evasion');
  });

  it('ics 19.2 ships the Unauthorized Message family and retires T0855 through revoked-by', () => {
    const domain = domainOf('ics-attack.json');
    const ids = new Set(domain.techniques.map(technique => technique.attackId));
    for (const id of ['T1691', 'T1692', 'T1692.001', 'T1693', 'T1694', 'T1695', 'T0843.001', 'T0846.001', 'T0873.001']) {
      expect(ids.has(id)).withContext(id).toBeTrue();
    }
    for (const id of ['T0803', 'T0804', 'T0805', 'T0812', 'T0839', 'T0855', 'T0856', 'T0857', 'T0891']) {
      expect(ids.has(id)).withContext(`${id} should be retired`).toBeFalse();
    }
    expect(domain.supersededBy.get('T0855')).toBe('T1692.001');
  });
});
