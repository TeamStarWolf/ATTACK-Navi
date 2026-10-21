// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { BehaviorSubject, of } from 'rxjs';
import { ActorComparePanelComponent } from './actor-compare-panel.component';
import { FilterService } from '../../services/filter.service';
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
// GA uses T1+T2, GB uses T1 → overlap {T1}, unique-A {T2}.
const GROUPS_FOR_TECH = new Map<string, ThreatGroup[]>([['t1', [GA, GB]], ['t2', [GA]]]);

function domainFixture(): Domain {
  return {
    name: 'Enterprise ATT&CK', groups: [GA, GB], techniques: [T1, T2], campaigns: [],
    tacticColumns: [{ tactic: { name: 'Reconnaissance' }, techniques: [T1, T2] }],
    groupsByTechnique: new Map([['t1', [GA, GB]], ['t2', [GA]]]),
    techniquesByGroup: new Map([['intrusion-set--a', [T1, T2]], ['intrusion-set--b', [T1]]]),
  } as unknown as Domain;
}

describe('ActorComparePanelComponent', () => {
  let component: ActorComparePanelComponent;
  let fixture: ComponentFixture<ActorComparePanelComponent>;
  let domain$: BehaviorSubject<Domain | null>;

  beforeEach(() => {
    domain$ = new BehaviorSubject<Domain | null>(domainFixture());
    TestBed.configureTestingModule({
      imports: [ActorComparePanelComponent],
      providers: [
        { provide: DataService, useValue: {
            domain$,
            getCurrentDomain: () => domain$.value,
            getCurrentAttackDomain: () => 'enterprise',
            getGroupsForTechnique: (techId: string) => GROUPS_FOR_TECH.get(techId) ?? [],
        }},
        { provide: FilterService, useValue: { toggleThreatGroup: jasmine.createSpy('toggleThreatGroup') }},
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]), manifest: [], layerTechniqueIds: () => of([]) }},
      ],
    });
    fixture = TestBed.createComponent(ActorComparePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and renders two single-mode pickers', () => {
    expect(component).toBeTruthy();
    const pickers = fixture.debugElement.queryAll(By.css('app-threat-profile-picker'));
    expect(pickers.length).toBe(2);
  });

  it('clicking a picker item in each selects actors by STIX id and runs the compare', () => {
    const pickers = fixture.debugElement.queryAll(By.css('app-threat-profile-picker'));
    // Picker A: click the first group item (Alpha, G0001 → intrusion-set--a).
    const itemsA = pickers[0].queryAll(By.css('.tpp-item'));
    expect(itemsA.length).toBeGreaterThan(0);
    itemsA[0].nativeElement.click();
    fixture.detectChanges();
    expect(component.actorA?.id).toBe('intrusion-set--a');   // STIX id, not the G#### attackId

    // Picker A is now replaced by the selected-actor display; picker B remains.
    const pickerB = fixture.debugElement.queryAll(By.css('app-threat-profile-picker'))[0];
    const itemsB = pickerB.queryAll(By.css('.tpp-item'));
    // Click Bravo (the second group; order is by name — Alpha, Bravo).
    itemsB[itemsB.length - 1].nativeElement.click();
    fixture.detectChanges();
    expect(component.actorB?.id).toBe('intrusion-set--b');

    expect(component.overlapIds).toEqual(['T1001']);     // shared
    expect(component.uniqueToAIds).toEqual(['T1002']);   // Alpha-only
    expect(component.uniqueToBIds).toEqual([]);
  });

  it('drops a selection the new domain lacks on a domain switch', () => {
    component.onPickA('intrusion-set--a');
    expect(component.actorA?.id).toBe('intrusion-set--a');
    domain$.next({
      name: 'ICS ATT&CK', groups: [group('intrusion-set--c', 'G9001', 'Gamma')], techniques: [], campaigns: [],
      tacticColumns: [], groupsByTechnique: new Map(), techniquesByGroup: new Map(),
    } as unknown as Domain);
    fixture.detectChanges();
    expect(component.actorA).toBeNull();   // intrusion-set--a is not in the ICS domain
  });
});
