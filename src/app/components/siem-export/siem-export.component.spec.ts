// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';

import { SiemExportComponent } from './siem-export.component';
import { Technique } from '../../models/technique';
import { DataService } from '../../services/data.service';
import { CARService, CarAnalytic } from '../../services/car.service';
import { SuricataService } from '../../services/suricata.service';
import { ZeekService } from '../../services/zeek.service';
import { SiemQueryService } from '../../services/siem-query.service';

function technique(attackId: string, name: string, tactics: string[]): Technique {
  return {
    id: `attack-pattern--${attackId}`, attackId, name, description: '', url: '',
    tacticShortnames: tactics, isSubtechnique: attackId.includes('.'), parentId: null,
    subtechniques: [], mitigationCount: 0, platforms: [], dataSources: [], detectionText: '',
    defenseBypassed: [], permissionsRequired: [], effectivePermissions: [], systemRequirements: [],
    impactType: [], remoteSupport: false, capecIds: [],
  };
}

const TECHNIQUES = [
  technique('T1059', 'Command and Scripting Interpreter', ['execution']),
  technique('T1059.001', 'PowerShell', ['execution']),
  technique('T1003', 'OS Credential Dumping', ['credential-access']),
  technique('T1110', 'Brute Force', ['credential-access']),
];

const ANALYTICS: CarAnalytic[] = [
  { id: 'CAR-2014-04-003', name: 'PowerShell Execution', description: 'd1', url: 'u1', platforms: ['Windows'], attackIds: ['T1059.001'] },
  { id: 'CAR-2019-08-001', name: 'Credential Dumping via Mimikatz', description: 'd2', url: 'u2', platforms: ['Windows'], attackIds: ['T1003'] },
  { id: 'CAR-2013-05-004', name: 'Execution with AT', description: 'd3', url: 'u3', platforms: ['Windows'], attackIds: ['T1053.002'] },
];

describe('SiemExportComponent', () => {
  let fixture: ComponentFixture<SiemExportComponent>;
  let component: SiemExportComponent;
  let suricata: jasmine.SpyObj<SuricataService>;
  let zeek: jasmine.SpyObj<ZeekService>;

  beforeEach(() => {
    suricata = jasmine.createSpyObj<SuricataService>('SuricataService', ['generateRulesForTechniques', 'getRuleCount']);
    suricata.generateRulesForTechniques.and.returnValue('# suricata rules');
    suricata.getRuleCount.and.returnValue(7);
    zeek = jasmine.createSpyObj<ZeekService>('ZeekService', ['generatePackageForTechniques', 'getScriptCount']);
    zeek.generatePackageForTechniques.and.returnValue('# zeek package');
    zeek.getScriptCount.and.returnValue(3);

    TestBed.configureTestingModule({
      imports: [SiemExportComponent],
      providers: [
        // The component reads the domain synchronously through DataService's subject.
        { provide: DataService, useValue: { domainSubject: new BehaviorSubject({ techniques: TECHNIQUES }) } },
        { provide: CARService, useValue: { getAll: () => ANALYTICS } },
        { provide: SuricataService, useValue: suricata },
        { provide: ZeekService, useValue: zeek },
        { provide: SiemQueryService, useValue: { getAllQueriesForTechnique: () => [] } },
      ],
    });
    fixture = TestBed.createComponent(SiemExportComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('loads every CAR analytic as included and the domain tactics for the tactic filter', () => {
    expect(component.analyticsEntries.map(e => e.analytic.id)).toEqual(ANALYTICS.map(a => a.id));
    expect(component.analyticsEntries.every(e => e.included)).toBeTrue();
    expect(component.tacticOptions).toEqual(['credential-access', 'execution']);
    expect(component.techniqueOptions.map(t => t.attackId)).toEqual(['T1059', 'T1003', 'T1110']);
  });

  it('builds Splunk SPL for every included analytic with its technique tag', () => {
    expect(component.activePlatform).toBe('splunk');
    expect(component.fileExtension).toBe('spl');
    for (const a of ANALYTICS) {
      expect(component.generatedContent).toContain(`| ===== ${a.id}: ${a.name} =====`);
    }
    expect(component.generatedContent).toContain('technique="T1059.001"');
    expect(component.analyticsCount).toBe(3);
    expect(component.lineCount).toBeGreaterThan(ANALYTICS.length * 5);
  });

  it('by-technique mode keeps the technique and its sub-techniques only', () => {
    component.exportMode = 'by-technique';
    component.selectedTechniqueId = 'T1059';
    component.onModeChange();

    expect(component.filteredAnalytics.map(a => a.id)).toEqual(['CAR-2014-04-003']);
    expect(component.generatedContent).toContain('CAR-2014-04-003');
    expect(component.generatedContent).not.toContain('CAR-2019-08-001');

    // A sub-technique selection also matches analytics on the parent.
    component.selectedTechniqueId = 'T1003.001';
    expect(component.filteredAnalytics.map(a => a.id)).toEqual(['CAR-2019-08-001']);
  });

  it('by-tactic mode resolves membership through the loaded domain', () => {
    component.exportMode = 'by-tactic';
    component.selectedTactic = 'credential-access';
    component.onModeChange();

    expect(component.filteredAnalytics.map(a => a.id)).toEqual(['CAR-2019-08-001']);
    expect(component.techniqueCount).toBe(1);
  });

  it('excluding an analytic drops it from the export, and an empty set says so', () => {
    component.analyticsEntries[0].included = false;
    component.onEntryToggle();
    expect(component.generatedContent).not.toContain('CAR-2014-04-003');
    expect(component.generatedContent).toContain('CAR-2019-08-001');

    component.analyticsEntries.forEach(e => (e.included = false));
    component.onEntryToggle();
    expect(component.generatedContent).toBe('| * No CAR analytics matched the current filter *');

    component.onPlatformChange('sentinel');
    expect(component.generatedContent).toBe('// No CAR analytics matched the current filter');
    expect(component.fileExtension).toBe('kql');
  });

  it('text filter matches on id, name or technique id', () => {
    component.filterText = 'mimikatz';
    expect(component.filteredAnalytics.map(a => a.id)).toEqual(['CAR-2019-08-001']);
    component.filterText = 't1053';
    expect(component.filteredAnalytics.map(a => a.id)).toEqual(['CAR-2013-05-004']);
  });

  it('Suricata and Zeek exports are technique-driven and delegate to their services', () => {
    component.exportMode = 'by-tactic';
    component.selectedTactic = 'execution';
    component.onPlatformChange('suricata');

    expect(component.isSuricataOrZeek).toBeTrue();
    expect(component.generatedContent).toBe('# suricata rules');
    expect(component.suricataRuleCount).toBe(7);
    expect(component.fileExtension).toBe('rules');
    const passed = suricata.generateRulesForTechniques.calls.mostRecent().args[0];
    expect(passed.map(t => t.attackId)).toEqual(['T1059', 'T1059.001']);

    component.onPlatformChange('zeek');
    expect(component.generatedContent).toBe('# zeek package');
    expect(component.zeekScriptCount).toBe(3);
    expect(component.fileExtension).toBe('zeek');
  });

  it('library search needs two characters and matches id or name', () => {
    component.librarySearchText = 'p';
    component.onLibrarySearchChange();
    expect(component.libraryFilteredTechniques).toEqual([]);

    component.librarySearchText = 'brute';
    component.onLibrarySearchChange();
    expect(component.libraryFilteredTechniques.map(t => t.attackId)).toEqual(['T1110']);
  });
});
