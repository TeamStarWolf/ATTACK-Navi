// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ThreatProfilePickerComponent } from './threat-profile-picker.component';
import { DataService } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { Domain } from '../../models/domain';
import { ThreatGroup } from '../../models/group';

function grp(id: string, attackId: string, description: string): ThreatGroup {
  return { id, attackId, name: `grp-${attackId}`, description, url: '', aliases: [] };
}

function domainWithGroups(groups: ThreatGroup[]): Domain {
  return { name: 'Enterprise ATT&CK', groups, campaigns: [] } as unknown as Domain;
}

describe('ThreatProfilePickerComponent', () => {
  let fixture: ComponentFixture<ThreatProfilePickerComponent>;
  let component: ThreatProfilePickerComponent;
  let domain$: BehaviorSubject<Domain | null>;
  let setSource: jasmine.Spy;
  let toggleThreatGroup: jasmine.Spy;

  beforeEach(() => {
    domain$ = new BehaviorSubject<Domain | null>(domainWithGroups([
      grp('intrusion-set--aaa', 'G0001', 'A financial banking crime group'),
      grp('intrusion-set--bbb', 'G0002', 'A healthcare and medical espionage group'),
    ]));
    setSource = jasmine.createSpy('setSource');
    toggleThreatGroup = jasmine.createSpy('toggleThreatGroup');
    TestBed.configureTestingModule({
      imports: [ThreatProfilePickerComponent],
      providers: [
        { provide: DataService, useValue: { domain$, getCurrentDomain: () => domain$.value } },
        { provide: FilterService, useValue: { toggleThreatGroup } },
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]) } },
        { provide: ThreatProfileService, useValue: { setSource } },
      ],
    });
    fixture = TestBed.createComponent(ThreatProfilePickerComponent);
    component = fixture.componentInstance;
  });

  it('is created and loads groups from the domain', () => {
    fixture.detectChanges();
    expect(component.groups.length).toBe(2);
  });

  it('single mode emits the STIX id, never the G#### attackId', () => {
    component.mode = 'single';
    fixture.detectChanges();
    const emitted: string[] = [];
    component.groupSelected.subscribe((id) => emitted.push(id));
    component.selectGroup(component.groups[0]);
    expect(emitted).toEqual(['intrusion-set--aaa']);
    expect(emitted[0]).not.toMatch(/^G\d+$/);
    expect(setSource).not.toHaveBeenCalled();
  });

  it('multi-local mode emits a set and never mutates the service', () => {
    component.mode = 'multi-local';
    fixture.detectChanges();
    let last: ReadonlySet<string> | undefined;
    component.selectionChange.subscribe((s) => (last = s));
    component.selectGroup(component.groups[0]);
    component.selectGroup(component.groups[1]);
    expect(last && [...last].sort()).toEqual(['intrusion-set--aaa', 'intrusion-set--bbb']);
    expect(setSource).not.toHaveBeenCalled();
  });

  it('profile mode writes the source through the service', () => {
    component.mode = 'profile';
    fixture.detectChanges();
    component.selectGroup(component.groups[0]);
    expect(setSource).toHaveBeenCalledWith({ kind: 'groups', ids: ['intrusion-set--aaa'] });
  });

  it('the sector aid filters groups by their description keywords', () => {
    fixture.detectChanges();
    component.toggleSector('Financial');
    expect(component.filteredGroups().map((g) => g.attackId)).toEqual(['G0001']);
    component.toggleSector('Financial');   // toggle off
    expect(component.filteredGroups().length).toBe(2);
  });

  it('"Use as matrix filter" toggles the FilterService group filter, separate from the profile', () => {
    component.mode = 'profile';
    fixture.detectChanges();
    component.selectGroup(component.groups[0]);
    component.useAsMatrixFilter();
    expect(toggleThreatGroup).toHaveBeenCalledWith('intrusion-set--aaa');
  });
});
