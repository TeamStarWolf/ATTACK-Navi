// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { BehaviorSubject, of } from 'rxjs';
import { ComparisonPanelComponent } from './comparison-panel.component';
import { FilterService } from '../../services/filter.service';
import { PanelNavService } from '../../services/panel-nav.service';
import { DataService } from '../../services/data.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { Domain } from '../../models/domain';
import { ThreatGroup } from '../../models/group';
import { Technique } from '../../models/technique';

function tech(id: string, attackId: string): Technique {
  return {
    id, attackId, name: attackId, description: '', url: '', tacticShortnames: ['recon'],
    isSubtechnique: false, parentId: null, subtechniques: [], mitigationCount: 0, platforms: [],
    dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [], effectivePermissions: [],
    systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
  };
}
function group(id: string, attackId: string, name: string): ThreatGroup {
  return { id, attackId, name, description: 'd', url: '', aliases: [] };
}

const GA = group('intrusion-set--a', 'G0001', 'Alpha');
const GB = group('intrusion-set--b', 'G0002', 'Bravo');
const T1 = tech('t1', 'T1001');
const T2 = tech('t2', 'T1002');

function domainFixture(): Domain {
  return {
    name: 'Enterprise ATT&CK', groups: [GA, GB], techniques: [T1, T2], campaigns: [], tacticColumns: [],
    groupsByTechnique: new Map([['t1', [GA, GB]], ['t2', [GA]]]),
    techniquesByGroup: new Map([['intrusion-set--a', [T1, T2]], ['intrusion-set--b', [T1]]]),
  } as unknown as Domain;
}

describe('ComparisonPanelComponent', () => {
  let component: ComparisonPanelComponent;
  let fixture: ComponentFixture<ComparisonPanelComponent>;
  let domain$: BehaviorSubject<Domain | null>;

  beforeEach(() => {
    domain$ = new BehaviorSubject<Domain | null>(domainFixture());
    TestBed.configureTestingModule({
      imports: [ComparisonPanelComponent],
      providers: [
        { provide: FilterService, useValue: { selectTechnique: jasmine.createSpy(), toggleThreatGroup: jasmine.createSpy() }},
        { provide: PanelNavService, useValue: { open: jasmine.createSpy() }},
        { provide: DataService, useValue: {
            domain$,
            getCurrentDomain: () => domain$.value,
            getCurrentAttackDomain: () => 'enterprise',
        }},
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]), manifest: [], layerTechniqueIds: () => of([]) }},
      ],
    });
    fixture = TestBed.createComponent(ComparisonPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and renders two single-mode pickers', () => {
    expect(component).toBeTruthy();
    expect(fixture.debugElement.queryAll(By.css('app-threat-profile-picker')).length).toBe(2);
  });

  it('clicking a picker item in each selects groups by STIX id and computes the overlap', () => {
    const pickers = fixture.debugElement.queryAll(By.css('app-threat-profile-picker'));
    pickers[0].queryAll(By.css('.tpp-item'))[0].nativeElement.click();   // Alpha
    fixture.detectChanges();
    expect(component.groupA?.id).toBe('intrusion-set--a');   // STIX id, not G####

    const pickerB = fixture.debugElement.queryAll(By.css('app-threat-profile-picker'))[0];
    const itemsB = pickerB.queryAll(By.css('.tpp-item'));
    itemsB[itemsB.length - 1].nativeElement.click();         // Bravo
    fixture.detectChanges();
    expect(component.groupB?.id).toBe('intrusion-set--b');

    expect(component.both.map(t => t.attackId)).toEqual(['T1001']);
    expect(component.aOnly.map(t => t.attackId)).toEqual(['T1002']);
    expect(component.bOnly).toEqual([]);
  });

  it('resolves a group with no technique uses (not dropped) and shows the no-uses state', () => {
    const GNT = group('intrusion-set--nt', 'G0003', 'NoTech');
    domain$.next({
      name: 'Enterprise ATT&CK', groups: [GA, GNT], techniques: [T1, T2], campaigns: [], tacticColumns: [],
      groupsByTechnique: new Map([['t1', [GA]], ['t2', [GA]]]),      // GNT maps nothing
      techniquesByGroup: new Map([['intrusion-set--a', [T1, T2]]]),  // GNT absent -> no techniques
    } as unknown as Domain);
    fixture.detectChanges();
    // Groups sort by name: Alpha, NoTech. Pick NoTech in A — it must resolve, not drop.
    fixture.debugElement.queryAll(By.css('app-threat-profile-picker'))[0]
      .queryAll(By.css('.tpp-item'))[1].nativeElement.click();
    fixture.detectChanges();
    expect(component.groupA?.id).toBe('intrusion-set--nt');
    // Pick Alpha in B (the remaining picker), so a different group is selected.
    fixture.debugElement.queryAll(By.css('app-threat-profile-picker'))[0]
      .queryAll(By.css('.tpp-item'))[0].nativeElement.click();
    fixture.detectChanges();
    expect(component.groupB?.id).toBe('intrusion-set--a');
    expect(fixture.debugElement.query(By.css('[data-testid="no-uses"]'))).toBeTruthy();
  });

  it('shows the no-uses note after picking a techniques-less group in A alone (before B)', () => {
    const GNT = group('intrusion-set--nt', 'G0003', 'NoTech');
    domain$.next({
      name: 'Enterprise ATT&CK', groups: [GA, GNT], techniques: [T1, T2], campaigns: [], tacticColumns: [],
      groupsByTechnique: new Map([['t1', [GA]], ['t2', [GA]]]),      // GNT maps nothing
      techniquesByGroup: new Map([['intrusion-set--a', [T1, T2]]]),  // GNT absent -> no techniques
    } as unknown as Domain);
    fixture.detectChanges();
    // Groups sort by name: Alpha, NoTech. Pick NoTech in A ONLY; do not pick B.
    fixture.debugElement.queryAll(By.css('app-threat-profile-picker'))[0]
      .queryAll(By.css('.tpp-item'))[1].nativeElement.click();
    fixture.detectChanges();
    expect(component.groupA?.id).toBe('intrusion-set--nt');
    expect(component.groupB).toBeNull();
    // The note must appear before the second pick, so the user knows the comparison will be empty.
    expect(fixture.debugElement.query(By.css('[data-testid="no-uses"]'))).toBeTruthy();
  });

  it('drops a selection the new domain lacks on a domain switch', () => {
    fixture.debugElement.queryAll(By.css('app-threat-profile-picker'))[0]
      .queryAll(By.css('.tpp-item'))[0].nativeElement.click();   // Alpha, via the rendered picker
    fixture.detectChanges();
    expect(component.groupA?.id).toBe('intrusion-set--a');
    domain$.next({
      name: 'ICS ATT&CK', groups: [group('intrusion-set--c', 'G9001', 'Gamma')], techniques: [], campaigns: [], tacticColumns: [],
      groupsByTechnique: new Map([['t9', [group('intrusion-set--c', 'G9001', 'Gamma')]]]),
      techniquesByGroup: new Map(),
    } as unknown as Domain);
    fixture.detectChanges();
    expect(component.groupA).toBeNull();
  });
});
