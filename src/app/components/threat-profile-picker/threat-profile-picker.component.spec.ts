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
import { Campaign } from '../../models/campaign';
import { ThreatProfileSource } from '../../models/threat-profile';

function grp(id: string, attackId: string, description: string): ThreatGroup {
  return { id, attackId, name: `grp-${attackId}`, description, url: '', aliases: [] };
}
function camp(id: string, attackId: string): Campaign {
  return { id, attackId, name: `camp-${attackId}`, description: '', url: '', aliases: [], firstSeen: '', lastSeen: '', attributedGroupIds: [] };
}
function domainWith(groups: ThreatGroup[], campaigns: Campaign[] = []): Domain {
  return { name: 'Enterprise ATT&CK', groups, campaigns } as unknown as Domain;
}

// The wizard's keyword table (assessment-wizard.component.ts:46-52); the picker must match it verbatim.
const WIZARD_SECTORS = [
  { label: 'Financial', keywords: ['financial', 'banking', 'payment', 'fin'] },
  { label: 'Government', keywords: ['government', 'military', 'defense', 'intelligence', 'political', 'embassy'] },
  { label: 'Healthcare', keywords: ['health', 'hospital', 'medical', 'pharma'] },
  { label: 'Technology', keywords: ['technology', 'software', 'tech', 'telecom', 'it '] },
  { label: 'Energy', keywords: ['energy', 'oil', 'gas', 'nuclear', 'power', 'utility'] },
  { label: 'Education', keywords: ['education', 'university', 'academic', 'research'] },
];

describe('ThreatProfilePickerComponent', () => {
  let fixture: ComponentFixture<ThreatProfilePickerComponent>;
  let component: ThreatProfilePickerComponent;
  let domain$: BehaviorSubject<Domain | null>;
  let setSource: jasmine.Spy;
  let toggleThreatGroup: jasmine.Spy;
  let currentSource: ThreatProfileSource;

  function configure(): void {
    domain$ = new BehaviorSubject<Domain | null>(domainWith(
      [grp('intrusion-set--aaa', 'G0001', 'A financial banking crime group'),
       grp('intrusion-set--bbb', 'G0002', 'A healthcare and medical espionage group')],
      [camp('campaign--ccc', 'C0001')],
    ));
    setSource = jasmine.createSpy('setSource');
    toggleThreatGroup = jasmine.createSpy('toggleThreatGroup');
    TestBed.configureTestingModule({
      imports: [ThreatProfilePickerComponent],
      providers: [
        { provide: DataService, useValue: { domain$, getCurrentDomain: () => domain$.value } },
        { provide: FilterService, useValue: { toggleThreatGroup } },
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]) } },
        { provide: ThreatProfileService, useValue: {
            get current() { return { source: currentSource }; },
            profile$: new BehaviorSubject({ source: currentSource }),
            setSource,
        } },
      ],
    });
    fixture = TestBed.createComponent(ThreatProfilePickerComponent);
    component = fixture.componentInstance;
  }

  beforeEach(() => { currentSource = { kind: 'top-groups', n: 20 }; configure(); });

  it('is created and loads groups and campaigns from the domain', () => {
    fixture.detectChanges();
    expect(component.groups.length).toBe(2);
    expect(component.campaigns.length).toBe(1);
  });

  it('single mode emits the STIX id, never the G#### attackId, and never a campaign', () => {
    component.mode = 'single';
    fixture.detectChanges();
    const emitted: string[] = [];
    component.groupSelected.subscribe((id) => emitted.push(id));
    component.selectGroup(component.groups[0]);
    component.selectCampaign(component.campaigns[0]);   // must NOT emit in single mode
    expect(emitted).toEqual(['intrusion-set--aaa']);
    expect(emitted[0]).not.toMatch(/^G\d+$/);
    expect(setSource).not.toHaveBeenCalled();
    expect(component.showPresetTabs).toBeFalse();
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

  it('keeps group and campaign selections apart; a preset switch clears the other', () => {
    component.mode = 'multi-local';
    fixture.detectChanges();
    component.selectGroup(component.groups[0]);
    component.selectCampaign(component.campaigns[0]);
    expect([...component.selectedGroupIds]).toEqual(['intrusion-set--aaa']);
    expect([...component.selectedCampaignIds]).toEqual(['campaign--ccc']);
    component.setPreset('campaigns');
    expect(component.selectedGroupIds.size).toBe(0);   // switching away from groups clears them
    expect([...component.selectedCampaignIds]).toEqual(['campaign--ccc']);
  });

  it('profile mode writes a groups source through the service', () => {
    component.mode = 'profile';
    fixture.detectChanges();
    component.selectGroup(component.groups[0]);
    expect(setSource).toHaveBeenCalledWith({ kind: 'groups', ids: ['intrusion-set--aaa'] });
  });

  it('profile mode initialises its selection from the stored profile (no silent replace)', () => {
    TestBed.resetTestingModule();   // beforeEach already instantiated with the default source
    currentSource = { kind: 'groups', ids: ['intrusion-set--bbb'] };
    configure();
    component.mode = 'profile';
    fixture.detectChanges();
    expect(component.preset).toBe('groups');
    expect([...component.selectedGroupIds]).toEqual(['intrusion-set--bbb']);
  });

  it('clamps the Top-N field to [1, number of groups]', () => {
    component.mode = 'profile';
    fixture.detectChanges();
    component.topN = 999;
    component.onTopNChange();
    expect(component.topN).toBe(2);   // only two groups in the fixture
    expect(setSource).toHaveBeenCalledWith({ kind: 'top-groups', n: 2 });
  });

  it('"Use as matrix filter" toggles only group ids on the FilterService', () => {
    component.mode = 'profile';
    fixture.detectChanges();
    component.selectGroup(component.groups[0]);
    component.useAsMatrixFilter();
    expect(toggleThreatGroup).toHaveBeenCalledWith('intrusion-set--aaa');
    expect(toggleThreatGroup).toHaveBeenCalledTimes(1);
  });

  it('the sector aid table matches the wizard verbatim', () => {
    fixture.detectChanges();
    expect(component.sectors).toEqual(WIZARD_SECTORS);
  });

  it('the sector aid filters groups by their description keywords', () => {
    fixture.detectChanges();
    component.toggleSector('Financial');
    expect(component.filteredGroups().map((g) => g.attackId)).toEqual(['G0001']);
    component.toggleSector('Financial');   // toggle off
    expect(component.filteredGroups().length).toBe(2);
  });
});
