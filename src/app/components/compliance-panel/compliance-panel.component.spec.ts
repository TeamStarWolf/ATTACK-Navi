// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';

import { CompliancePanelComponent } from './compliance-panel.component';
import { Technique } from '../../models/technique';
import { DataService } from '../../services/data.service';
import { CisControlsService } from '../../services/cis-controls.service';
import { CloudControlsService } from '../../services/cloud-controls.service';
import { NistMappingService } from '../../services/nist-mapping.service';
import { CriProfileService } from '../../services/cri-profile.service';
import { ComplianceMapperService } from '../../services/compliance-mapper.service';
import { ImplementationService } from '../../services/implementation.service';
import { CsaCcmService } from '../../services/csa-ccm.service';
import { M365ControlsService } from '../../services/m365-controls.service';

function technique(attackId: string, name: string, tactic: string): Technique {
  return {
    id: `attack-pattern--${attackId}`, attackId, name, description: '', url: '',
    tacticShortnames: [tactic], isSubtechnique: attackId.includes('.'), parentId: null,
    subtechniques: [], mitigationCount: 0, platforms: [], dataSources: [], detectionText: '',
    defenseBypassed: [], permissionsRequired: [], effectivePermissions: [], systemRequirements: [],
    impactType: [], remoteSupport: false, capecIds: [],
  };
}

const DOMAIN = {
  name: 'Enterprise ATT&CK',
  techniques: [
    technique('T1003', 'OS Credential Dumping', 'credential-access'),
    technique('T1059', 'Command and Scripting Interpreter', 'execution'),
    technique('T1059.001', 'PowerShell', 'execution'),
    technique('T1190', 'Exploit Public-Facing Application', 'initial-access'),
    technique('T1566', 'Phishing', 'initial-access'),
  ],
};

/** Controls per technique for one framework: NIST maps 3 of 4 parents, CIS maps 1. */
const NIST: Record<string, string[]> = { T1003: ['IA-02', 'AC-06', 'CM-06'], T1059: ['CM-07'], T1190: ['SI-02', 'RA-05'] };
const CIS: Record<string, string[]> = { T1566: ['9.7'] };

const nistControl = (id: string) => ({ id, description: id, family: id.slice(0, 2), mappingType: 'mitigates' });
const cisControl = (id: string) => ({ id: `CIS ${id}`, description: id, group: 'IG1', mappingType: 'mitigates' });

describe('CompliancePanelComponent', () => {
  let fixture: ComponentFixture<CompliancePanelComponent>;
  let component: CompliancePanelComponent;
  let nistLoaded$: BehaviorSubject<boolean>;
  let nistMap: Record<string, string[]>;

  beforeEach(() => {
    nistLoaded$ = new BehaviorSubject<boolean>(false);
    nistMap = {};
    const empty = () => [];
    // The template's "N controls" badges read total$/loaded$ synchronously.
    const framework = (total: number) => ({
      loaded$: new BehaviorSubject<boolean>(true),
      total$: new BehaviorSubject<number>(total),
      getControlsForTechnique: empty as () => never[],
    });
    TestBed.configureTestingModule({
      imports: [CompliancePanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(DOMAIN) } },
        { provide: CisControlsService, useValue: { ...framework(153), getControlsForTechnique: (id: string) => (CIS[id] ?? []).map(cisControl) } },
        { provide: CloudControlsService, useValue: {
            loaded$: new BehaviorSubject<boolean>(true),
            getControlsForTechnique: empty,
            isProviderLoaded: () => true,
            getProviderTotal: () => 0,
        } },
        // NIST data "arrives" when nistLoaded$ flips to true.
        { provide: NistMappingService, useValue: {
            loaded$: nistLoaded$,
            total$: new BehaviorSubject<number>(6),
            getControlsForTechnique: (id: string) => (nistMap[id] ?? []).map(nistControl),
        } },
        { provide: CriProfileService, useValue: framework(0) },
        { provide: CsaCcmService, useValue: framework(0) },
        { provide: M365ControlsService, useValue: framework(0) },
        { provide: ComplianceMapperService, useValue: { getAllControls: empty, getControlStatus: () => null, getTechniquesForControl: empty } },
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) } },
      ],
    });
    fixture = TestBed.createComponent(CompliancePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('builds one row per parent technique (sub-techniques excluded)', () => {
    expect(component.cachedDomain?.name).toBe('Enterprise ATT&CK');
    expect(component.cisTotal).toBe(153);
    expect(component.nistTotal).toBe(6);
    expect(component.nistLoaded).toBeFalse();
    expect(component.complianceRows.map(r => r.attackId)).toEqual(['T1003', 'T1059', 'T1190', 'T1566']);
    expect(component.complianceRows.find(r => r.attackId === 'T1566')?.cisCount).toBe(1);
    expect(component.complianceRows.find(r => r.attackId === 'T1566')?.tactic).toBe('initial-access');
  });

  it('rebuilds the rows when a framework finishes loading', () => {
    expect(component.complianceRows.every(r => r.nistCount === 0)).toBeTrue();

    nistMap = NIST;
    nistLoaded$.next(true);

    const byId = Object.fromEntries(component.complianceRows.map(r => [r.attackId, r]));
    expect(byId['T1003'].nistCount).toBe(3);
    expect(byId['T1003'].topNistControls.map(c => c.id)).toEqual(['IA-02', 'AC-06']); // top 2 only
    expect(byId['T1566'].nistCount).toBe(0);
  });

  describe('with NIST loaded', () => {
    beforeEach(() => {
      nistMap = NIST;
      nistLoaded$.next(true);
    });

    it('the NIST tab lists only mapped techniques, most controls first', () => {
      expect(component.activeTab).toBe('nist');
      expect(component.sortBy).toBe('coverage');
      expect(component.displayRows.map(r => r.attackId)).toEqual(['T1003', 'T1190', 'T1059']);
      expect(component.activeTabCount).toBe(3);
    });

    it('sorting by technique shows every row alphabetically, unmapped ones included', () => {
      component.sortBy = 'technique';
      expect(component.displayRows.map(r => r.name)).toEqual([
        'Command and Scripting Interpreter',
        'Exploit Public-Facing Application',
        'OS Credential Dumping',
        'Phishing',
      ]);
    });

    it('search narrows on name, id or tactic', () => {
      component.searchText = 'initial-access';
      expect(component.displayRows.map(r => r.attackId)).toEqual(['T1190']);
      component.searchText = 't1003';
      expect(component.displayRows.map(r => r.attackId)).toEqual(['T1003']);
    });

    it('frameworkScores reports technique coverage per framework with a traffic-light status', () => {
      const nist = component.frameworkScores.find(f => f.key === 'nist')!;
      expect(nist).toEqual(jasmine.objectContaining({ total: 4, covered: 3, pct: 75, status: 'amber' }));
      const cis = component.frameworkScores.find(f => f.key === 'cis')!;
      expect(cis).toEqual(jasmine.objectContaining({ total: 4, covered: 1, pct: 25, status: 'red' }));
      // Mapper-based frameworks with no controls score 0 rather than dividing by zero.
      const soc2 = component.frameworkScores.find(f => f.key === 'soc2')!;
      expect(soc2).toEqual(jasmine.objectContaining({ total: 0, covered: 0, pct: 0, status: 'red' }));
    });

    it('switching tabs clears the search and changes the row set', () => {
      component.searchText = 'phish';
      component.setTab('cis');
      expect(component.searchText).toBe('');
      expect(component.displayRows.map(r => r.attackId)).toEqual(['T1566']);
      expect(component.activeTabCount).toBe(1);
      component.setTab('soc2');
      expect(component.displayRows).toEqual([]);
    });
  });
});
