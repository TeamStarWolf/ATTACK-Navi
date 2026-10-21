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
import { ThreatGroup } from '../../models/group';
import { By } from '@angular/platform-browser';
import { ThreatProfilePickerComponent } from '../threat-profile-picker/threat-profile-picker.component';

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

  it('resolves quick picks to STIX groups by attackId on domain load (inside the shared picker)', () => {
    const data = TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<Domain | null> };
    const apt29 = { id: 'intrusion-set--apt29', attackId: 'G0016', name: 'APT29', aliases: ['Cozy Bear'], description: '' };
    data.domain$.next({ name: 'Enterprise ATT&CK', tactics: [], techniques: [], groups: [apt29], campaigns: [], techniquesByGroup: new Map() } as unknown as Domain);
    fixture.detectChanges();
    const picker = fixture.debugElement.query(By.directive(ThreatProfilePickerComponent)).componentInstance as ThreatProfilePickerComponent;
    expect(picker.quickPickGroups.find(q => q.label === 'APT29')?.group.id).toBe('intrusion-set--apt29');
  });

  // RP-F item 3: the six Common picks called the panel's own selectGroup(), so the page read
  // "Selected: APT28 (G0007)" while the shared picker on the same page showed nothing. They are
  // now the picker's quick-select presets: one selection, shown by the list and the Selected line.
  describe('Common picks drive the shared picker (RP-F item 3)', () => {
    const apt28 = { id: 'intrusion-set--apt28', attackId: 'G0007', name: 'APT28', aliases: ['Fancy Bear'], description: '' };
    const apt29 = { id: 'intrusion-set--apt29', attackId: 'G0016', name: 'APT29', aliases: ['Cozy Bear'], description: '' };
    const el = () => fixture.nativeElement as HTMLElement;
    const norm = (n: Element | null) => (n?.textContent ?? '').replace(/\s+/g, ' ').trim();
    /** A list item as 'Name G####' (its name and id spans). */
    const item = (b: Element) => Array.from(b.querySelectorAll('span')).map(n => n.textContent!.trim()).join(' ');
    const selectedItems = () => Array.from(el().querySelectorAll('.tpp-item.selected')).map(item);

    beforeEach(() => {
      const data = TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<Domain | null> };
      data.domain$.next({ name: 'Enterprise ATT&CK', tactics: [], techniques: [], groups: [apt28, apt29], campaigns: [], techniquesByGroup: new Map() } as unknown as Domain);
      fixture.detectChanges();
    });

    it('the presets render inside the picker, and the panel has no buttons of its own', () => {
      expect(el().querySelector('app-threat-profile-picker .tpp-quick')).not.toBeNull();
      expect(Array.from(el().querySelectorAll('app-threat-profile-picker .tpp-quick-btn')).map(norm)).toEqual(['APT28', 'APT29']);
      expect(el().querySelector('.emu-quick-picks, .emu-qp-btn')).toBeNull();
    });

    it('clicking a preset selects it in the rendered picker and the Selected line matches', () => {
      const preset = Array.from(el().querySelectorAll<HTMLButtonElement>('.tpp-quick-btn')).find(b => norm(b) === 'APT29')!;
      preset.click();
      fixture.detectChanges();
      expect(selectedItems()).toEqual(['APT29 G0016']);
      expect(el().querySelector('.tpp-item.selected')!.getAttribute('aria-pressed')).toBe('true');
      expect(preset.getAttribute('aria-pressed')).toBe('true');
      expect(norm(el().querySelector('.emu-selected-actor'))).toContain('Selected: APT29 (G0016)');
      expect(component.selectedGroup?.id).toBe('intrusion-set--apt29');

      // A later click on a list item moves both together.
      Array.from(el().querySelectorAll<HTMLButtonElement>('.tpp-item')).find(b => item(b) === 'APT28 G0007')!.click();
      fixture.detectChanges();
      expect(selectedItems()).toEqual(['APT28 G0007']);
      expect(norm(el().querySelector('.emu-selected-actor'))).toContain('Selected: APT28 (G0007)');
      expect(preset.getAttribute('aria-pressed')).toBe('false');
    });

    it('clearing the selection clears the picker too', () => {
      el().querySelector<HTMLButtonElement>('.tpp-quick-btn')!.click();
      fixture.detectChanges();
      expect(selectedItems()).toEqual(['APT28 G0007']);
      component.clearGroup();
      fixture.detectChanges();
      expect(selectedItems()).toEqual([]);
      expect(el().querySelector('.emu-selected-actor')).toBeNull();
    });
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

  it('clears a stale selection and its plan when the domain switches to one without it (1a)', fakeAsync(() => {
    const data = TestBed.inject(DataService) as unknown as { domain$: BehaviorSubject<Domain | null> };
    component.onGroupPicked('intrusion-set--g1');
    component.generatePlan();
    tick(0);
    expect(component.plan).toBeTruthy();
    data.domain$.next({ name: 'ICS ATT&CK', tactics: [], techniques: [], groups: [], campaigns: [], techniquesByGroup: new Map() } as unknown as Domain);
    fixture.detectChanges();
    expect(component.selectedGroup).toBeNull();
    expect(component.plan).toBeNull();
  }));

  it('generatePlan on a stale group resets generating and surfaces an error instead of hanging (1b)', fakeAsync(() => {
    // Force a selection the loaded domain does not contain, bypassing the 1a guard.
    component.selectedGroup = { id: 'intrusion-set--gone', attackId: 'G9999', name: 'Gone', aliases: [], description: '' } as unknown as ThreatGroup;
    expect(() => { component.generatePlan(); tick(0); }).not.toThrow();
    expect(component.generating).toBeFalse();
    expect(component.plan).toBeNull();
    expect(component.planError).toBeTruthy();
  }));
});
