// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { SiemExportComponent } from './siem-export.component';
import { DataService } from '../../services/data.service';
import { CARService, CarAnalytic } from '../../services/car.service';
import { SuricataService } from '../../services/suricata.service';
import { ZeekService } from '../../services/zeek.service';
import { SiemQueryService } from '../../services/siem-query.service';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';

function technique(attackId: string, name: string, tacticShortnames: string[]): Technique {
  return {
    id: `attack-pattern--${attackId}`, attackId, name, description: '', url: '',
    tacticShortnames, isSubtechnique: attackId.includes('.'), parentId: null, subtechniques: [],
    mitigationCount: 0, platforms: ['Windows'], dataSources: [], detectionText: '',
    defenseBypassed: [], permissionsRequired: [], effectivePermissions: [], systemRequirements: [],
    impactType: [], remoteSupport: false, capecIds: [],
  };
}

const analytic = (id: string, attackIds: string[]): CarAnalytic => ({
  id, name: `Analytic ${id}`, description: '', url: '', platforms: ['Windows'], attackIds,
});

describe('SiemExportComponent', () => {
  it('class is exported', () => {
    expect(SiemExportComponent).toBeTruthy();
  });

  describe('exported tactic tags follow the loaded domain (ATT&CK v19)', () => {
    let component: SiemExportComponent;

    beforeEach(() => {
      const domain = {
        techniques: [
          technique('T1055', 'Process Injection', ['stealth', 'privilege-escalation']),
          technique('T1685', 'Disable or Modify Tools', ['defense-impairment']),
          technique('T1685.001', 'Disable or Modify System Firewall', ['defense-impairment']),
          technique('T1197', 'BITS Jobs', ['stealth', 'persistence']),
        ],
        // v19 retired T1562 (-> T1685) and T1562.001 (-> T1685)
        supersededBy: new Map([['T1562', 'T1685'], ['T1562.001', 'T1685']]),
      } as unknown as Domain;

      TestBed.configureTestingModule({
        imports: [SiemExportComponent],
        providers: [
          { provide: DataService, useValue: { getCurrentDomain: () => domain } },
          { provide: CARService, useValue: { getAll: () => [] } },
          { provide: SuricataService, useValue: { getRuleCount: () => 0, generateRulesForTechniques: () => '' } },
          { provide: ZeekService, useValue: { getScriptCount: () => 0, generatePackageForTechniques: () => '' } },
          { provide: SiemQueryService, useValue: { getAllQueriesForTechnique: () => [] } },
        ],
      });
      const fixture = TestBed.createComponent(SiemExportComponent);
      component = fixture.componentInstance;
      fixture.detectChanges();
    });

    it('tacticTagFor returns the technique tactic from the loaded domain, resolving sub-technique and retired ids', () => {
      expect(component.tacticTagFor('T1055', 'defense-evasion')).toBe('stealth');
      expect(component.tacticTagFor('T1685.001', 'defense-evasion')).toBe('defense-impairment');
      // sub-technique not in the domain falls back to its parent
      expect(component.tacticTagFor('T1685.999', 'defense-evasion')).toBe('defense-impairment');
      // retired id resolves through supersededBy
      expect(component.tacticTagFor('T1562.001', 'defense-evasion')).toBe('defense-impairment');
      // unknown technique keeps the caller's fallback
      expect(component.tacticTagFor('T9999', 'defense-evasion')).toBe('defense-evasion');
      expect(component.tacticTagFor('', 'defense-evasion')).toBe('defense-evasion');
    });

    it('Splunk export never emits the retired defense-evasion slug for v19 techniques', () => {
      const spl = component.buildSplunkExport([
        analytic('CAR-A', ['T1055']),
        analytic('CAR-B', ['T1562.001']),
        analytic('CAR-C', ['T1197']),
      ]);
      expect(spl).toContain('tactic="stealth"');
      expect(spl).toContain('tactic="defense-impairment"');
      expect(spl).not.toContain('tactic="defense-evasion"');
    });
  });
});
