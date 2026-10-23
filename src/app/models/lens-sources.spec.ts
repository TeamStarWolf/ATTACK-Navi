// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// SOURCE_DOMAINS (technique page design 4.4, PR 1): the ATT&CK domains each
// source has technique data for, so an ICS or Mobile technique reads "not
// applicable in <domain>" for an Enterprise-only source instead of 0.
import { HEATMAP_MODES } from './heatmap-modes';
import { LENS_SOURCES, type LensSourceId, SOURCE_DOMAINS, notApplicableWords, sourceApplies } from './lens-sources';

describe('SOURCE_DOMAINS', () => {
  it('names the domains of every source in the inventory', () => {
    expect(Object.keys(SOURCE_DOMAINS).sort()).toEqual(Object.keys(LENS_SOURCES).sort());
    for (const [id, domains] of Object.entries(SOURCE_DOMAINS)) {
      expect(domains.length).withContext(id).toBeGreaterThan(0);
    }
  });

  it('no lens claims a domain one of its sources has no data for', () => {
    for (const lens of HEATMAP_MODES) {
      for (const domain of lens.domains) {
        for (const id of lens.sources) {
          expect(sourceApplies(id, domain)).withContext(`${lens.value}: ${id} in ${domain}`).toBeTrue();
        }
      }
    }
  });

  it('SigmaHQ, CAR, Atomic, D3FEND and the CTID mappings are Enterprise only; the ATT&CK bundle and your workspace are everywhere', () => {
    const enterpriseOnly: LensSourceId[] = ['sigmahq', 'car', 'car-seed', 'atomic', 'd3fend-seed', 'ctid-nist-800-53', 'ctid-cri', 'ctid-csa-ccm', 'ctid-m365', 'cisa-kev', 'ctid-attack-to-cve', 'ctid-kev'];
    for (const id of enterpriseOnly) expect(SOURCE_DOMAINS[id]).withContext(id).toEqual(['enterprise']);
    for (const id of ['attack-bundle', 'workspace-local'] as const) {
      expect(['enterprise', 'ics', 'mobile', 'f3'].every(d => sourceApplies(id, d as never))).withContext(id).toBeTrue();
    }
  });

  it('notApplicableWords names the domain, the sources and where they have data; null while any source applies', () => {
    expect(notApplicableWords(['sigmahq', 'car'], 'ics'))
      .toBe('not applicable in ICS ATT&CK: SigmaHQ coverage and MITRE CAR layer have Enterprise ATT&CK data only');
    expect(notApplicableWords(['atomic'], 'mobile')).toBe('not applicable in Mobile ATT&CK: Atomic Red Team has Enterprise ATT&CK data only');
    expect(notApplicableWords(['sigmahq', 'car'], 'enterprise')).toBeNull();
    expect(notApplicableWords(['attack-bundle', 'sigmahq'], 'ics')).withContext('one source applies').toBeNull();
    expect(notApplicableWords([], 'ics')).toBeNull();
  });
});
