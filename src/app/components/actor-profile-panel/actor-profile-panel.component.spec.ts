// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { provideRouter } from '@angular/router';
import { ActorProfilePanelComponent } from './actor-profile-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { Domain } from '../../models/domain';
import { ThreatGroup } from '../../models/group';
import { Technique } from '../../models/technique';
import { makeSplitDomain } from '../../testing/report-split-fixture';
import { PostureStub, makePostureStub, postureStubProvider } from '../../testing/posture-stub';
import type { PostureBucket } from '../../models/posture/posture.types';
import { postureBadge } from '../../models/posture/posture-vocabulary';

describe('ActorProfilePanelComponent', () => {
  let component: ActorProfilePanelComponent;
  let fixture: ComponentFixture<ActorProfilePanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ActorProfilePanelComponent],
      providers: [
        provideRouter([]),
        { provide: FilterService, useValue: {
            toggleThreatGroup: jasmine.createSpy(),
            selectTechnique: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        postureStubProvider(makePostureStub(() => null)),
      ],
    });
    fixture = TestBed.createComponent(ActorProfilePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  it('searchText starts empty', () => {
    expect(component.searchText).toBe('');
  });
});

// S6 (P2-07): the actor profile shows counts from PostureService.tallyFor over
// the group's techniques, never a percentage; each row dot is the technique's
// posture bucket.
describe('ActorProfilePanelComponent posture counts (S6, P2-07)', () => {
  let fixture: ComponentFixture<ActorProfilePanelComponent>;
  let posture: PostureStub;
  let techniques: Technique[];
  const group = { id: 'intrusion-set--g1', attackId: 'G0001', name: 'Group One', aliases: [], description: '' } as unknown as ThreatGroup;

  function open(buckets: Record<string, PostureBucket>): HTMLElement {
    const domain = { ...makeSplitDomain(), groups: [group] } as unknown as Domain;
    techniques = domain.techniques;
    posture = makePostureStub(() => domain, buckets);
    TestBed.configureTestingModule({
      imports: [ActorProfilePanelComponent],
      providers: [
        provideRouter([]),
        { provide: FilterService, useValue: { toggleThreatGroup: jasmine.createSpy(), selectTechnique: jasmine.createSpy() } },
        { provide: DataService, useValue: {
            domain$: new BehaviorSubject(domain),
            getTechniquesForGroup: () => techniques,
            getSoftwareForGroup: () => [],
            getCampaignsForGroup: () => [],
        }},
        postureStubProvider(posture),
      ],
    });
    fixture = TestBed.createComponent(ActorProfilePanelComponent);
    fixture.detectChanges();
    fixture.componentInstance.selectGroup(group);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim();
  const ring = (el: HTMLElement) => Array.from(el.querySelectorAll('[data-testid="actor-ring"] span')).map(sp => text(sp)).join(' ');

  it("reads 'M techniques; no data of yours recorded' on a fresh profile, with no Covered words and no '%'", () => {
    const el = open({});
    expect(text(el.querySelector('[data-testid="actor-posture-summary"]'))).toBe('6 techniques; no data of yours recorded');
    expect(el.querySelector('[data-testid="actor-posture-proven"]')).toBeNull();
    expect(ring(el)).toBe('6 techniques');
    expect(text(el)).not.toContain('%');
    expect(text(el)).not.toMatch(/\bcovered\b|\bproven\b|\bdefended\b|mitigated/i);
  });

  it('shows the covered and partial counts of tallyFor(group techniques) and a Proven line', () => {
    const el = open({ T1: 'covered', T2: 'partial', 'T1.001': 'covered', T4: 'proven', T5: 'stale' });
    const tally = posture.tallyFor(techniques);
    const summary = text(el.querySelector('[data-testid="actor-posture-summary"]'));
    expect(summary).toMatch(/^\d+ of \d+ techniques covered \(self-attested\), \d+ partial$/);
    expect(summary).toBe(`${tally.covered} of 6 techniques covered (self-attested), ${tally.partial} partial`);
    expect([tally.covered, tally.partial]).toEqual([2, 1]);
    expect(text(el.querySelector('[data-testid="actor-posture-proven"]'))).toBe('Proven: 1 · Proven (stale): 1');
    expect(ring(el)).toBe('2 of 6');
    expect(text(el)).not.toContain('%');
  });

  it('sets each row dot from the posture bucket: covered, proven and stale a tick, partial a half mark with its badge', () => {
    const el = open({ T1: 'covered', T2: 'partial', T4: 'proven', T5: 'stale' });
    (Array.from(el.querySelectorAll<HTMLButtonElement>('.ptab')).find(b => b.textContent!.includes('Techniques')))!.click();
    fixture.detectChanges();
    const rows = Array.from(el.querySelectorAll('.tech-row')).map(r => {
      const status = r.querySelector('.tech-row-status')!;
      return [text(r.querySelector('.tech-row-id')), status.getAttribute('data-mark'), text(status), status.getAttribute('title')];
    });
    expect(rows).toEqual([
      ['T1', 'yes', '✅', null],
      ['T2', 'partial', '◐', postureBadge(posture.stateFor(techniques[1]))],
      ['T3', 'no', '🔴', null],
      ['T4', 'yes', '✅', null],
      ['T5', 'yes', '✅', null],
      ['T1.001', 'no', '🔴', null],
    ]);
    expect(rows[1][3]).toBe('Covered (self-attested, partial via M1)');
  });

  it('lists techniques without a full mark as exposed, and refreshes when the posture states change', () => {
    open({ T1: 'covered' });
    const panel = fixture.componentInstance;
    const profile = panel.selectedProfile!;
    expect(panel.topExposed(profile).map(t => t.attackId)).not.toContain('T1');
    posture.set({ T1: 'covered', T2: 'covered' });
    fixture.detectChanges();
    expect(panel.topExposed(profile).map(t => t.attackId)).not.toContain('T2');
    expect(text(fixture.nativeElement.querySelector('[data-testid="actor-posture-summary"]'))).toBe('2 of 6 techniques covered (self-attested), 0 partial');
  });
});
