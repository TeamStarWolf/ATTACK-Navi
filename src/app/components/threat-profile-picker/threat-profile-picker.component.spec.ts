// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { WritableSignal, signal } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { ThreatProfilePickerComponent } from './threat-profile-picker.component';
import { DataService } from '../../services/data.service';
import { FilterService } from '../../services/filter.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { Domain } from '../../models/domain';
import { ThreatGroup } from '../../models/group';
import { Campaign } from '../../models/campaign';
import { ProfileGroupRef, ThreatProfileSource } from '../../models/threat-profile';
import { THREAT_WEIGHT_PROVIDER } from '../../models/posture/threat-weight';

// The picker is the single source of the sector aid table (P2-10). This fixture mirrors the
// expected content; the test compares the picker's runtime `component.sectors` against it, so
// a drift in the picker's table fails the spec.
const EXPECTED_SECTORS = [
  { label: 'Financial', keywords: ['financial', 'banking', 'payment', 'fin'] },
  { label: 'Government', keywords: ['government', 'military', 'defense', 'intelligence', 'political', 'embassy'] },
  { label: 'Healthcare', keywords: ['health', 'hospital', 'medical', 'pharma'] },
  { label: 'Technology', keywords: ['technology', 'software', 'tech', 'telecom', 'it '] },
  { label: 'Energy', keywords: ['energy', 'oil', 'gas', 'nuclear', 'power', 'utility'] },
  { label: 'Education', keywords: ['education', 'university', 'academic', 'research'] },
];

function grp(id: string, attackId: string, description: string): ThreatGroup {
  return { id, attackId, name: `grp-${attackId}`, description, url: '', aliases: [] };
}
function camp(id: string, attackId: string): Campaign {
  return { id, attackId, name: `camp-${attackId}`, description: '', url: '', aliases: [], firstSeen: '', lastSeen: '', attributedGroupIds: [] };
}
/** A list item as 'Name G####' (its name and id spans). */
function itemText(b: Element): string {
  return Array.from(b.querySelectorAll('span')).map((n) => n.textContent!.trim()).join(' ');
}
function domainWith(groups: ThreatGroup[], campaigns: Campaign[] = []): Domain {
  return { name: 'Enterprise ATT&CK', groups, campaigns } as unknown as Domain;
}

describe('ThreatProfilePickerComponent', () => {
  let fixture: ComponentFixture<ThreatProfilePickerComponent>;
  let component: ThreatProfilePickerComponent;
  let domain$: BehaviorSubject<Domain | null>;
  let setSource: jasmine.Spy;
  let toggleThreatGroup: jasmine.Spy;
  let currentSource: ThreatProfileSource;
  let profileSubject: BehaviorSubject<{ source: ThreatProfileSource }>;
  // RP-F decision 6: what the service reports as absent from the loaded domain, and its sentence.
  let absent: ProfileGroupRef[];
  let domainNotice: WritableSignal<string | null>;

  function configure(): void {
    domain$ = new BehaviorSubject<Domain | null>(domainWith(
      [grp('intrusion-set--aaa', 'G0001', 'A financial banking crime group'),
       grp('intrusion-set--bbb', 'G0002', 'A healthcare and medical espionage group')],
      [camp('campaign--ccc', 'C0001')],
    ));
    setSource = jasmine.createSpy('setSource');
    toggleThreatGroup = jasmine.createSpy('toggleThreatGroup');
    profileSubject = new BehaviorSubject<{ source: ThreatProfileSource }>({ source: currentSource });
    TestBed.configureTestingModule({
      imports: [ThreatProfilePickerComponent],
      providers: [
        { provide: DataService, useValue: { domain$, getCurrentDomain: () => domain$.value } },
        { provide: FilterService, useValue: { toggleThreatGroup } },
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]) } },
        { provide: ThreatProfileService, useValue: {
            get current() { return { source: currentSource }; },
            profile$: profileSubject,
            setSource,
            absentGroups: (d: Domain | null) => (d ? absent : []),
        } },
        { provide: THREAT_WEIGHT_PROVIDER, useValue: {
            weight: () => 0, revision: signal(0), parents: signal(new Set<string>()), domainNotice,
        } },
      ],
    });
    fixture = TestBed.createComponent(ThreatProfilePickerComponent);
    component = fixture.componentInstance;
  }

  beforeEach(() => {
    currentSource = { kind: 'top-groups', n: 20 };
    absent = [];
    domainNotice = signal<string | null>(null);
    configure();
  });

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

  // RP-F item 3: single mode holds the chosen group, so the list shows what was emitted
  // (for a caller that binds selectedGroupId, as the emulation and scenario panels do).
  it('single mode marks the chosen list item selected, and a second pick replaces it', () => {
    component.mode = 'single';
    fixture.componentRef.setInput('selectedGroupId', null);
    fixture.detectChanges();
    component.selectGroup(component.groups[0]);
    fixture.detectChanges();
    const items = () => Array.from((fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('.tpp-item'));
    expect(items().filter((b) => b.classList.contains('selected')).map(itemText)).toEqual(['grp-G0001 G0001']);
    items()[1].click();
    fixture.detectChanges();
    expect([...component.selectedGroupIds]).toEqual(['intrusion-set--bbb']);
    expect(items().map((b) => b.getAttribute('aria-pressed'))).toEqual(['false', 'true']);
  });

  // RP-F round 1: a caller that does not bind selectedGroupId cannot clear the picker,
  // so a pressed item could outlive the caller's selection (the scenario panel drops its
  // actor on a domain switch). Without the binding no item is pressed; the emit still fires.
  it('single mode without a bound selectedGroupId emits the pick but presses no item', () => {
    component.mode = 'single';
    fixture.detectChanges();
    const emitted: string[] = [];
    component.groupSelected.subscribe((id) => emitted.push(id));
    const items = () => Array.from((fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('.tpp-item'));
    items()[1].click();
    fixture.detectChanges();
    expect(emitted).toEqual(['intrusion-set--bbb']);
    expect(component.selectedGroupIds.size).toBe(0);
    expect(items().map((b) => b.getAttribute('aria-pressed'))).toEqual(['false', 'false']);
  });

  it('single mode quick picks: presets resolve by ATT&CK id, drive the picker selection and emit the STIX id', () => {
    component.mode = 'single';
    fixture.componentRef.setInput('selectedGroupId', null);
    fixture.componentRef.setInput('quickPicks', [
      { label: 'Bee', attackId: 'G0002' },
      { label: 'Missing', attackId: 'G9999' },   // not in the domain: not shown
    ]);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const presets = Array.from(el.querySelectorAll<HTMLButtonElement>('.tpp-quick-btn'));
    expect(presets.map((b) => b.textContent!.replace(/\s+/g, ' ').trim())).toEqual(['Bee']);
    const emitted: string[] = [];
    component.groupSelected.subscribe((id) => emitted.push(id));
    component.searchText = 'grp-G0001';            // a search that hides the preset's group
    component.toggleSector('Financial');
    presets[0].click();
    fixture.detectChanges();
    expect(emitted).toEqual(['intrusion-set--bbb']);
    expect(component.searchText).toBe('');         // cleared so the selected item is on screen
    expect(component.activeSector).toBeNull();
    const selected = Array.from(el.querySelectorAll<HTMLButtonElement>('.tpp-item.selected'));
    expect(selected.map(itemText)).toEqual(['grp-G0002 G0002']);
    expect(selected[0].getAttribute('aria-pressed')).toBe('true');
    expect(el.querySelector('.tpp-quick-btn')!.getAttribute('aria-pressed')).toBe('true');
    expect(setSource).not.toHaveBeenCalled();
  });

  it('single mode quick picks re-resolve on a domain switch and are absent outside single mode', () => {
    component.mode = 'single';
    fixture.componentRef.setInput('quickPicks', [{ label: 'New', attackId: 'G0003' }]);
    fixture.detectChanges();
    expect(component.quickPickGroups.length).toBe(0);
    domain$.next(domainWith([grp('intrusion-set--ddd', 'G0003', 'new group')]));
    fixture.detectChanges();
    expect(component.quickPickGroups.map((q) => q.group.id)).toEqual(['intrusion-set--ddd']);

    TestBed.resetTestingModule(); configure();
    component.mode = 'profile';
    fixture.componentRef.setInput('quickPicks', [{ label: 'Bee', attackId: 'G0002' }]);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('.tpp-quick')).toBeNull();
  });

  it('single mode reflects the caller selection (selectedGroupId) without emitting', () => {
    component.mode = 'single';
    const emitted: string[] = [];
    component.groupSelected.subscribe((id) => emitted.push(id));
    fixture.componentRef.setInput('selectedGroupId', 'intrusion-set--bbb');
    fixture.detectChanges();
    expect([...component.selectedGroupIds]).toEqual(['intrusion-set--bbb']);
    fixture.componentRef.setInput('selectedGroupId', null);   // the caller cleared it (New Plan)
    fixture.detectChanges();
    expect(component.selectedGroupIds.size).toBe(0);
    expect((fixture.nativeElement as HTMLElement).querySelectorAll('.tpp-item.selected').length).toBe(0);
    expect(emitted).toEqual([]);
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

  it('profile mode keeps following profile$ after init (not just the first seed, item C)', () => {
    component.mode = 'profile';
    fixture.detectChanges();
    expect(component.preset).toBe('top-groups');           // the beforeEach seed
    profileSubject.next({ source: { kind: 'campaigns', ids: ['campaign--ccc'] } });
    fixture.detectChanges();
    expect(component.preset).toBe('campaigns');             // a later push is reflected
    expect([...component.selectedCampaignIds]).toEqual(['campaign--ccc']);
    expect(component.selectedGroupIds.size).toBe(0);        // the other kind is cleared
  });

  it('a profile$ re-emission of the SAME source keeps the user\'s open tab (regression, item 2)', () => {
    component.mode = 'profile';
    fixture.detectChanges();                 // seeded top-groups/20 from the beforeEach
    component.setPreset('groups');           // user opens the Groups tab; nothing picked yet (groups does not persist)
    expect(component.preset).toBe('groups');
    profileSubject.next({ source: { kind: 'top-groups', n: 20 } });   // a domain switch / layer-load re-emit of the same stored source
    fixture.detectChanges();
    expect(component.preset).toBe('groups');                          // tab preserved, not snapped back to Top N
    profileSubject.next({ source: { kind: 'campaigns', ids: ['campaign--ccc'] } });   // a genuine change elsewhere
    fixture.detectChanges();
    expect(component.preset).toBe('campaigns');                       // re-seeds on a different source
    expect([...component.selectedCampaignIds]).toEqual(['campaign--ccc']);
  });

  it('profile mode seeds preset, n, ids and layer from every stored source kind (item C)', () => {
    currentSource = { kind: 'top-groups', n: 7 };
    TestBed.resetTestingModule(); configure();
    component.mode = 'profile'; fixture.detectChanges();
    expect(component.preset).toBe('top-groups');
    expect(component.topN).toBe(7);

    currentSource = { kind: 'campaigns', ids: ['campaign--ccc'] };
    TestBed.resetTestingModule(); configure();
    component.mode = 'profile'; fixture.detectChanges();
    expect(component.preset).toBe('campaigns');
    expect([...component.selectedCampaignIds]).toEqual(['campaign--ccc']);

    currentSource = { kind: 'library-layer', file: 'ransomware.json' };
    TestBed.resetTestingModule(); configure();
    component.mode = 'profile'; fixture.detectChanges();
    expect(component.preset).toBe('library-layer');
    expect(component.selectedLayerFile).toBe('ransomware.json');
  });

  it('clamps the Top-N field to an integer in [1, 1000], NOT to the current group count', () => {
    component.mode = 'profile';
    fixture.detectChanges();
    component.topN = 999;
    component.onTopNChange();
    expect(component.topN).toBe(999);   // kept though the fixture has two groups; resolveProfile clamps at resolve time
    expect(setSource).toHaveBeenCalledWith({ kind: 'top-groups', n: 999 });
    component.topN = 99999;
    component.onTopNChange();
    expect(component.topN).toBe(1000);  // the stored-source guard's upper bound
    component.topN = 0;
    component.onTopNChange();
    expect(component.topN).toBe(1);
  });

  it('does not collapse Top-N to the group count while domain$ is null (regression, item A)', () => {
    component.mode = 'profile';
    fixture.detectChanges();
    domain$.next(null);                 // mid domain switch: component.groups becomes []
    expect(component.groups.length).toBe(0);
    component.topN = 20;
    component.onTopNChange();
    expect(setSource).toHaveBeenCalledWith({ kind: 'top-groups', n: 20 });   // never n:1 or n:groups.length
    setSource.calls.reset();
    component.setPreset('top-groups');
    expect(setSource).toHaveBeenCalledWith({ kind: 'top-groups', n: 20 });
  });

  it('"Use as matrix filter" toggles only group ids on the FilterService', () => {
    component.mode = 'profile';
    fixture.detectChanges();
    component.selectGroup(component.groups[0]);
    component.useAsMatrixFilter();
    expect(toggleThreatGroup).toHaveBeenCalledWith('intrusion-set--aaa');
    expect(toggleThreatGroup).toHaveBeenCalledTimes(1);
  });

  it('the sector aid table matches the expected sector fixture', () => {
    fixture.detectChanges();
    expect(component.sectors).toEqual(EXPECTED_SECTORS);
  });

  it('the sector aid filters groups by their description keywords', () => {
    fixture.detectChanges();
    component.toggleSector('Financial');
    expect(component.filteredGroups().map((g) => g.attackId)).toEqual(['G0001']);
    component.toggleSector('Financial');   // toggle off
    expect(component.filteredGroups().length).toBe(2);
  });
  describe('stored groups the loaded domain lacks (RP-F decision 6)', () => {
    const APT29: ProfileGroupRef = { id: 'intrusion-set--apt29', name: 'APT29' };
    const NOTICE = '1 of 2 groups present in Enterprise: grp-G0001; APT29 has no Enterprise use';
    const host = () => fixture.nativeElement as HTMLElement;
    const absentButtons = () => Array.from(host().querySelectorAll('[data-testid="profile-absent-groups"] button'));

    beforeEach(() => {
      TestBed.resetTestingModule();
      currentSource = { kind: 'groups', ids: ['intrusion-set--aaa', APT29.id] };
      absent = [APT29];
      configure();
      domainNotice.set(NOTICE);
      component.mode = 'profile';
      fixture.detectChanges();
    });

    it('the header shows the shared sentence and lists the absent group pressed, marked, "has no <Domain> use"', () => {
      expect(host().querySelector('[data-testid="profile-domain-notice"]')!.textContent!.trim()).toBe(NOTICE);
      const rows = absentButtons();
      expect(rows.length).toBe(1);
      expect(itemText(rows[0])).toBe('APT29 has no Enterprise use');
      expect(rows[0].classList).toContain('tpp-item--absent');
      expect(rows[0].getAttribute('aria-pressed')).toBe('true');
    });

    // WCAG 2 relative luminance / contrast of an rgb()/rgba() colour composited over an opaque background.
    const rgba = (c: string): number[] => {
      const m = c.match(/rgba?\(([^)]+)\)/);
      if (!m) throw new Error(`unparsed colour ${c}`);
      const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
      return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
    };
    const lum = ([r, g, b]: number[]) => {
      const ch = (v: number) => { const x = v / 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; };
      return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b);
    };
    const over = (fg: number[], bg: number[], alpha: number) => fg.slice(0, 3).map((v, i) => v * alpha + bg[i] * (1 - alpha));
    const ratio = (a: number[], b: number[]) => { const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x); return (hi + 0.05) / (lo + 0.05); };
    /** Contrast of `el`'s text against the row background, counting opacity on every ancestor up to the component host. */
    const textContrast = (el: Element, row: Element): number => {
      let alpha = 1;
      for (let n: Element | null = el; n && n !== host(); n = n.parentElement) alpha *= Number(getComputedStyle(n).opacity);
      const page = rgba(getComputedStyle(document.body).getPropertyValue('--bg-base').trim().replace(/^#(..)(..)(..)$/,
        (_x, r, g, b) => `rgb(${parseInt(r, 16)}, ${parseInt(g, 16)}, ${parseInt(b, 16)})`));
      const rowBg = rgba(getComputedStyle(row).backgroundColor);
      const bg = over(rowBg, page, rowBg[3]);
      const fg = rgba(getComputedStyle(el).color);
      return ratio(over(fg, bg, fg[3] * alpha), bg);
    };

    for (const theme of ['dark', 'light'] as const) {
      it(`every label on an absent row keeps >= 4.5:1 contrast, pressed and unpressed (${theme} theme, WCAG AA)`, () => {
        document.body.classList.toggle('light-mode', theme === 'light');
        try {
          for (const pressed of [true, false]) {
            if (!pressed) { (absentButtons()[0] as HTMLButtonElement).click(); fixture.detectChanges(); }
            const row = absentButtons()[0];
            expect(row.getAttribute('aria-pressed')).toBe(String(pressed));
            expect(Number(getComputedStyle(row).opacity)).withContext('no whole-row opacity').toBe(1);
            for (const sel of ['.tpp-item-name', '.tpp-item-id']) {
              const c = textContrast(row.querySelector(sel)!, row);
              expect(c).withContext(`${sel} ${theme} pressed=${pressed}: ${c.toFixed(2)}:1`).toBeGreaterThanOrEqual(4.5);
            }
          }
        } finally {
          document.body.classList.remove('light-mode');
        }
      });
    }

    it('toggling a present group keeps the absent one in the stored selection (never dropped)', () => {
      component.selectGroup(component.groups.find((g) => g.id === 'intrusion-set--bbb')!);
      expect(setSource).toHaveBeenCalledWith({ kind: 'groups', ids: ['intrusion-set--aaa', APT29.id, 'intrusion-set--bbb'] });
      component.selectGroup(component.groups.find((g) => g.id === 'intrusion-set--aaa')!);
      expect(setSource.calls.mostRecent().args[0]).toEqual({ kind: 'groups', ids: [APT29.id, 'intrusion-set--bbb'] });
    });

    it('an absent group is selectable: deselecting keeps it listed (unpressed) so it can be picked again', () => {
      component.toggleAbsent(APT29);
      expect(setSource).toHaveBeenCalledWith({ kind: 'groups', ids: ['intrusion-set--aaa'] });
      absent = [];                       // the service no longer stores it
      profileSubject.next({ source: { kind: 'groups', ids: ['intrusion-set--aaa'] } });
      fixture.detectChanges();
      expect(absentButtons().length).toBe(1);
      expect(absentButtons()[0].getAttribute('aria-pressed')).toBe('false');
      (absentButtons()[0] as HTMLButtonElement).click();
      expect(setSource.calls.mostRecent().args[0]).toEqual({ kind: 'groups', ids: ['intrusion-set--aaa', APT29.id] });
    });

    it('nothing is shown when every stored group is present, and the next domain load re-lists from the service', () => {
      absent = [];
      domainNotice.set(null);
      domain$.next(domain$.value);       // a domain (re)load re-reads the absent list
      fixture.detectChanges();
      expect(host().querySelector('[data-testid="profile-domain-notice"]')).toBeNull();
      expect(absentButtons().length).toBe(0);
    });

    it('single mode shows neither the notice nor the absent list', () => {
      TestBed.resetTestingModule();
      configure();
      domainNotice.set(NOTICE);
      component.mode = 'single';
      fixture.detectChanges();
      expect(host().querySelector('[data-testid="profile-domain-notice"]')).toBeNull();
      expect(absentButtons().length).toBe(0);
    });
  });
});
