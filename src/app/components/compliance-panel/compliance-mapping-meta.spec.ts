// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Plan P1 row E1.6: "compliance-panel shows CIS as 'source withdrawn upstream' and
// stamps every framework tab with 'mapped vs ATT&CK 16.1 / 17.1'". The rendered
// stamps are checked in compliance-panel.component.render.spec.ts; these cases pin
// the metadata, and check each stamp against the URL its loader really fetches.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { COMPLIANCE_TABS, COMPLIANCE_TAB_META, COMPLIANCE_TAB_SOURCE, mappedVsAttack } from './compliance-mapping-meta';
import { BUNDLED_ATTACK_VERSION, SOURCE_DEFINITIONS } from '../../services/source-inventory';
import { CisControlsService } from '../../services/cis-controls.service';
import { CloudControlsService } from '../../services/cloud-controls.service';
import { NistMappingService } from '../../services/nist-mapping.service';
import { CriProfileService } from '../../services/cri-profile.service';
import { CsaCcmService } from '../../services/csa-ccm.service';
import { M365ControlsService } from '../../services/m365-controls.service';

const CTID_TABS = ['aws', 'azure', 'gcp', 'nist', 'cri', 'csa-ccm', 'm365-ctrl'] as const;
const SEED_TABS = ['soc2', 'iso27001', 'pci'] as const;

describe('compliance mapping metadata (E1.6)', () => {
  it('covers every tab with a stamp read from the source inventory', () => {
    expect(Object.keys(COMPLIANCE_TAB_META).sort()).toEqual([...COMPLIANCE_TABS].sort());
    for (const tab of COMPLIANCE_TABS) {
      const meta = COMPLIANCE_TAB_META[tab];
      expect(SOURCE_DEFINITIONS.some(d => d.id === meta.sourceId)).withContext(tab).toBeTrue();
      expect(meta.stamp.trim()).withContext(tab).not.toBe('');
    }
  });

  it("stamps each CTID tab 'mapped vs ATT&CK 16.1' or '17.1', matching the release in its upstream path", () => {
    const seen = new Set<string>();
    for (const tab of CTID_TABS) {
      const meta = COMPLIANCE_TAB_META[tab];
      const def = SOURCE_DEFINITIONS.find(d => d.id === meta.sourceId)!;
      expect(meta.withdrawn).withContext(tab).toBeFalse();
      expect(meta.mappedVs).withContext(tab).toMatch(/^1[67]\.1$/);
      expect(meta.stamp).withContext(tab).toContain(`mapped vs ATT&CK ${meta.mappedVs}`);
      expect(meta.stamp).withContext(tab).toContain(`the matrix shows ATT&CK ${BUNDLED_ATTACK_VERSION}`);
      expect(def.upstream).withContext(tab).toContain(`/attack-${meta.mappedVs}/`);
      seen.add(meta.mappedVs!);
    }
    // CSA CCM is the one mapping made against 17.1; the rest are 16.1.
    expect(COMPLIANCE_TAB_META['csa-ccm'].mappedVs).toBe('17.1');
    expect([...seen].sort()).toEqual(['16.1', '17.1']);
  });

  it("shows CIS as 'source withdrawn upstream', with no mapping version", () => {
    const cis = COMPLIANCE_TAB_META.cis;
    expect(cis.withdrawn).toBeTrue();
    expect(cis.mappedVs).toBeNull();
    expect(cis.stamp).toMatch(/^Source withdrawn upstream: /);
    expect(cis.stamp).toContain('left out of the scores');
  });

  it('says the SOC 2, ISO 27001 and PCI DSS tables are project-authored and name no ATT&CK release', () => {
    for (const tab of SEED_TABS) {
      const meta = COMPLIANCE_TAB_META[tab];
      expect(meta.sourceId).toBe('compliance-mapper-seed');
      expect(meta.mappedVs).withContext(tab).toBeNull();
      expect(meta.withdrawn).withContext(tab).toBeFalse();
      expect(meta.stamp).withContext(tab).toMatch(/^Project-authored mapping, reviewed \d{4}-\d{2}-\d{2}, not mapped against a specific ATT&CK release\.$/);
    }
  });

  it('reads the mapped-vs release out of an inventory version string', () => {
    expect(mappedVsAttack({ version: 'csa_ccm-4.1, mapped vs ATT&CK 17.1' })).toBe('17.1');
    expect(mappedVsAttack({ version: 'none (no upstream file since ATT&CK 16)' })).toBeNull();
    expect(mappedVsAttack({})).toBeNull();
  });

  describe('against what the loaders fetch', () => {
    let fetched: string[];

    beforeEach(() => {
      TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
      for (const svc of [CisControlsService, CloudControlsService, NistMappingService, CriProfileService, CsaCcmService, M365ControlsService]) {
        TestBed.inject(svc as never);
      }
      fetched = TestBed.inject(HttpTestingController).match(() => true).map(r => r.request.url);
    });

    it('every CTID tab stamps the release of the file its loader requests', () => {
      for (const tab of CTID_TABS) {
        const def = SOURCE_DEFINITIONS.find(d => d.id === COMPLIANCE_TAB_SOURCE[tab])!;
        const url = fetched.find(u => u === def.upstream);
        expect(url).withContext(`${tab}: the loader fetches ${def.upstream}`).toBeDefined();
        expect(url).withContext(tab).toContain(`_attack-${COMPLIANCE_TAB_META[tab].mappedVs}-enterprise.json`);
      }
    });

    it('nothing is fetched for CIS', () => {
      expect(fetched.filter(u => /cis/i.test(u))).toEqual([]);
    });
  });
});
