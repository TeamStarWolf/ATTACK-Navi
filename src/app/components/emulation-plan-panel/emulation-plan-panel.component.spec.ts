// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture, fakeAsync, tick } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { BehaviorSubject, of } from 'rxjs';
import { EmulationPlanPanelComponent } from './emulation-plan-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { EmulationPlanService } from '../../services/emulation-plan.service';
import { LibraryService } from '../../services/library.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { AtomicService } from '../../services/atomic.service';
import { SigmaService } from '../../services/sigma.service';
import { ElasticService } from '../../services/elastic.service';
import { SplunkContentService } from '../../services/splunk-content.service';
import { Domain } from '../../models/domain';
import { Technique } from '../../models/technique';
import { Tactic } from '../../models/tactic';

const STORAGE_KEY = 'mitre-nav-emulation-plans';

function technique(attackId: string, name: string, tacticShortnames: string[]): Technique {
  return {
    id: `attack-pattern--${attackId}`, attackId, name, description: '', url: '',
    tacticShortnames, isSubtechnique: attackId.includes('.'), parentId: null, subtechniques: [],
  } as unknown as Technique;
}
function tactic(shortname: string, name: string, order: number): Tactic {
  return { id: `x-mitre-tactic--${shortname}`, attackId: 'TA0000', name, shortname, description: '', url: '', order } as unknown as Tactic;
}
// One group with two techniques across two tactics, so a real generatePlan yields steps.
function domainFixture(): Domain {
  const techs = [technique('T1566', 'Phishing', ['initial-access']), technique('T1003', 'OS Credential Dumping', ['credential-access'])];
  const tactics = [tactic('initial-access', 'Initial Access', 0), tactic('credential-access', 'Credential Access', 1)];
  const group = { id: 'intrusion-set--g1', attackId: 'G0001', name: 'Test Group', aliases: [], description: '' };
  return {
    name: 'Enterprise ATT&CK', tactics, techniques: techs, groups: [group], campaigns: [],
    techniquesByGroup: new Map([[group.id, techs]]),
  } as unknown as Domain;
}

describe('EmulationPlanPanelComponent', () => {
  let component: EmulationPlanPanelComponent;
  let fixture: ComponentFixture<EmulationPlanPanelComponent>;
  let domain: Domain;

  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);
    domain = domainFixture();
    TestBed.configureTestingModule({
      imports: [EmulationPlanPanelComponent],
      providers: [
        provideRouter([]),
        { provide: FilterService, useValue: { toggleThreatGroup: () => {} } },
        { provide: DataService, useValue: {
            domain$: new BehaviorSubject(domain),
            getCurrentDomain: () => domain,
            getCurrentAttackDomain: () => 'enterprise',
        }},
        // The real EmulationPlanService (no stub) so selecting a group runs a real plan.
        EmulationPlanService,
        { provide: AtomicService, useValue: { getTestsForTechnique: () => [], getTests: () => [], generateInvokeCommand: (id: string) => `Invoke-AtomicTest ${id}` } },
        { provide: SigmaService, useValue: { getRulesForTechnique: () => [], getRuleCount: () => 0 } },
        { provide: ElasticService, useValue: { getRulesForTechnique: () => [], getRuleCount: () => 0 } },
        { provide: SplunkContentService, useValue: { getContentForTechnique: () => [], getRuleCount: () => 0 } },
        { provide: LibraryService, useValue: { getAssetsForTactic: () => [] } },
        // The embedded shared picker (single mode) needs these.
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]), layerTechniqueIds: () => of([]) } },
        { provide: ThreatProfileService, useValue: {
            current: { source: { kind: 'top-groups', n: 20 } },
            profile$: new BehaviorSubject({ source: { kind: 'top-groups', n: 20 } }),
            setSource: () => {},
        }},
      ],
    });
    fixture = TestBed.createComponent(EmulationPlanPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  afterEach(() => localStorage.removeItem(STORAGE_KEY));

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('exposes 6 quick picks by ATT&CK id (no name/alias matching)', () => {
    expect(component.quickPicks.length).toBe(6);
    expect(component.quickPicks.map(q => q.label)).toContain('APT29');
    expect(component.quickPicks.find(q => q.label === 'APT29')?.attackId).toBe('G0016');
  });

  it('starts with no selectedGroup or plan', () => {
    expect(component.selectedGroup).toBeNull();
    expect(component.plan).toBeNull();
  });

  it('resolves the picker\'s STIX id to the group (never the attackId)', () => {
    component.onGroupPicked('intrusion-set--g1');
    expect(component.selectedGroup?.id).toBe('intrusion-set--g1');
  });

  // Mode guard: drive the selection through a rendered picker item, so dropping mode="single"
  // would break this test. generatePlan must receive the STIX id and the plan must have steps.
  it('clicking a rendered picker item (single mode) drives generatePlan with the STIX id and yields steps', fakeAsync(() => {
    const spy = spyOn(TestBed.inject(EmulationPlanService), 'generatePlan').and.callThrough();
    const item = (fixture.nativeElement as HTMLElement).querySelector('.tpp-item') as HTMLButtonElement | null;
    expect(item).withContext('picker rendered a .tpp-item in single mode').toBeTruthy();
    item!.click();
    fixture.detectChanges();
    expect(component.selectedGroup?.id).toBe('intrusion-set--g1');
    component.generatePlan();
    tick(0);   // flush the spinner setTimeout
    expect(spy).toHaveBeenCalledWith('intrusion-set--g1', jasmine.anything());
    expect(component.plan!.steps.length).toBeGreaterThan(0);
  }));

  it('resolves quick picks to STIX groups by attackId on domain load', () => {
    const data = TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<Domain | null> };
    const apt29 = { id: 'intrusion-set--apt29', attackId: 'G0016', name: 'APT29', aliases: ['Cozy Bear'], description: '' };
    data.domain$.next({ name: 'Enterprise ATT&CK', tactics: [], techniques: [], groups: [apt29], campaigns: [], techniquesByGroup: new Map() } as unknown as Domain);
    fixture.detectChanges();
    expect(component.quickPickGroups.find(q => q.label === 'APT29')?.group.id).toBe('intrusion-set--apt29');
  });

  it('re-resolves on a domain switch so a later pick targets the new domain (no take(1))', fakeAsync(() => {
    const data = TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<Domain | null> };
    const g2 = { id: 'intrusion-set--g2', attackId: 'G0002', name: 'New Group', aliases: [], description: '' };
    const t2 = technique('T1059', 'Command and Scripting Interpreter', ['execution']);
    data.domain$.next({ name: 'Enterprise ATT&CK', tactics: [tactic('execution', 'Execution', 0)], techniques: [t2], groups: [g2], campaigns: [], techniquesByGroup: new Map([[g2.id, [t2]]]) } as unknown as Domain);
    fixture.detectChanges();
    const spy = spyOn(TestBed.inject(EmulationPlanService), 'generatePlan').and.callThrough();
    component.onGroupPicked('intrusion-set--g2');
    component.generatePlan();
    tick(0);
    expect(spy).toHaveBeenCalledWith('intrusion-set--g2', jasmine.anything());
    expect(component.plan!.steps.length).toBeGreaterThan(0);
  }));
});
