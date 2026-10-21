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
    name: 'Enterprise ATT&CK', tactics, techniques: techs, groups: [group],
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

  it('exposes 6 quick-pick threat actors', () => {
    expect(component.quickPicks.length).toBe(6);
    expect(component.quickPicks).toContain('APT29');
  });

  it('starts with no selectedGroup or plan', () => {
    expect(component.selectedGroup).toBeNull();
    expect(component.plan).toBeNull();
  });

  it('resolves the picker\'s STIX id to the group (never the attackId)', () => {
    component.onGroupPicked('intrusion-set--g1');
    expect(component.selectedGroup?.id).toBe('intrusion-set--g1');
  });

  it('generates a real plan with steps when a group is picked via the shared picker (P2-11 STIX fix)', fakeAsync(() => {
    component.onGroupPicked('intrusion-set--g1');
    component.generatePlan();
    tick(0);   // flush the spinner setTimeout
    expect(component.plan).toBeTruthy();
    expect(component.plan!.name).not.toBe('Unknown Actor Plan');
    expect(component.plan!.steps.length).toBeGreaterThan(0);
  }));
});
