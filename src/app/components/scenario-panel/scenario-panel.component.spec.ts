// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture, fakeAsync, tick } from '@angular/core/testing';
import { signal, WritableSignal } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { ScenarioPanelComponent } from './scenario-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { PostureService } from '../../services/posture.service';
import { EmulationPlanService } from '../../services/emulation-plan.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { ThreatProfileService } from '../../services/threat-profile.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { ExploitdbService } from '../../services/exploitdb.service';
import { EpssService } from '../../services/epss.service';
import { THREAT_WEIGHT_PROVIDER } from '../../models/posture/threat-weight';
import { Technique } from '../../models/technique';
import { ThreatGroup } from '../../models/group';
import { PostureBucket, PostureSubState } from '../../models/posture/posture.types';

function tech(id: string, attackId: string): Technique {
  return {
    id, attackId, name: attackId, description: '', url: '', tacticShortnames: ['execution'],
    isSubtechnique: false, parentId: null, subtechniques: [], mitigationCount: 0, platforms: [],
    dataSources: [], detectionText: '', defenseBypassed: [], permissionsRequired: [], effectivePermissions: [],
    systemRequirements: [], impactType: [], remoteSupport: false, capecIds: [],
  };
}

const GROUP = { id: 'intrusion-set--g1', attackId: 'G0001', name: 'TestAPT', aliases: [] } as unknown as ThreatGroup;
const T1 = tech('t1', 'T1001');
const T2 = tech('t2', 'T1002');
const DOMAIN = { groups: [GROUP], techniques: [T1, T2], campaigns: [], mitigationsByTechnique: new Map() } as any;

describe('ScenarioPanelComponent (posture outcomes)', () => {
  let component: ScenarioPanelComponent;
  let fixture: ComponentFixture<ScenarioPanelComponent>;
  let domain$: BehaviorSubject<any>;
  let buckets: Map<string, PostureBucket>;
  let subStates: Map<string, PostureSubState[]>;
  let knownSignals: Map<string, number>;   // reference mappings per technique (ctem "Known: mapped" source)
  let ownerWords: boolean;
  let parentsSig: WritableSignal<ReadonlySet<string>>;
  let revisionSig: WritableSignal<number>;

  function configure(parentIds: string[] = ['t1', 't2']): void {
    domain$ = new BehaviorSubject<any>(DOMAIN);
    parentsSig = signal<ReadonlySet<string>>(new Set(parentIds));
    revisionSig = signal(0);
    TestBed.configureTestingModule({
      imports: [ScenarioPanelComponent],
      providers: [
        // scenario-panel deps
        { provide: FilterService, useValue: { selectTechnique: jasmine.createSpy('selectTechnique'), toggleThreatGroup: jasmine.createSpy() } },
        { provide: DataService, useValue: {
            domain$,
            getCurrentDomain: () => domain$.value,
            getCurrentAttackDomain: () => 'enterprise',
            getTechniquesForGroup: (id: string) => (id === GROUP.id ? [T1, T2] : []),
        } },
        { provide: PostureService, useValue: {
            stateFor: (t: Technique) => ({ bucket: buckets.get(t.id) ?? 'none', subStates: subStates.get(t.id) ?? [], excluded: false, knownSignals: knownSignals.get(t.id) ?? 0 }),
            ownerWords: () => ownerWords,
        } },
        // The REAL profile-scoped ThreatSimulationService over a fixture, so the overlay
        // exercises simulate() (item 5). Its gap/priority inputs are stubbed empty.
        { provide: THREAT_WEIGHT_PROVIDER, useValue: { weight: () => 0, revision: revisionSig, parents: parentsSig } },
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [], getKevCvesForTechnique: () => [] } },
        { provide: ExploitdbService, useValue: { hasExploits: () => false } },
        { provide: EpssService, useValue: { getScore: () => null } },
        { provide: EmulationPlanService, useValue: { generatePlan: () => ({ steps: [] }), exportCalderaProfile: () => {} } },
        // embedded picker deps
        { provide: LibraryLayerService, useValue: { manifest$: new BehaviorSubject([]), layerTechniqueIds: () => new BehaviorSubject([]), manifest: [] } },
        { provide: ThreatProfileService, useValue: {
            get current() { return { source: { kind: 'top-groups', n: 20 } }; },
            profile$: new BehaviorSubject({ source: { kind: 'top-groups', n: 20 } }),
            setSource: jasmine.createSpy('setSource'),
        } },
      ],
    });
    fixture = TestBed.createComponent(ScenarioPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  }

  beforeEach(() => { buckets = new Map(); subStates = new Map(); knownSignals = new Map(); ownerWords = false; });

  it('is created', () => {
    configure();
    expect(component).toBeTruthy();
  });

  it('a fresh profile shows only Known + None, renders no Covered/Proven card, and no "covered"/"proven" text', fakeAsync(() => {
    ownerWords = false;                 // no owner words → fresh profile
    buckets = new Map([['t1', 'known'], ['t2', 'none']]);
    configure();

    component.onGroupPicked(GROUP.id);
    tick(200);                          // flush the single-sim setTimeout
    fixture.detectChanges();
    // Also run the profile simulation so the overlay renders and is scanned too (item 5).
    component.runProfileSimulation();
    tick(200);                          // flush the runProfileSimulation setTimeout
    fixture.detectChanges();

    expect(component.result!.hasOwnerWords).toBeFalse();
    expect(component.result!.covered).toBe(0);
    expect(component.result!.proven).toBe(0);
    expect(component.profileSimResult).not.toBeNull();   // the overlay is mounted

    const host = fixture.nativeElement as HTMLElement;
    // No Covered or Proven card is rendered (single-sim); no owner rows in the overlay.
    expect(host.querySelector('.outcome-covered')).toBeNull();
    expect(host.querySelector('.outcome-proven')).toBeNull();
    expect(host.querySelector('[data-sim="covered"]')).toBeNull();
    expect(host.querySelector('[data-sim="proven"]')).toBeNull();
    // Item 1: the owner-posture overlay surfaces are all absent on a fresh profile.
    expect(host.querySelector('[data-sim="partial"]')).toBeNull();
    expect(host.querySelector('[data-sim="stale"]')).toBeNull();
    expect(host.querySelector('.sim-tactic-section')).toBeNull();      // "Recorded posture by tactic" bars
    expect(host.querySelector('.sim-gaps-section')).toBeNull();        // Prioritized Gaps list
    expect(host.querySelector('.sim-no-gaps')).toBeNull();            // nor the "No gaps" else
    expect(host.querySelector('[title="Export gaps as CSV"]')).toBeNull();   // nor the gaps CSV export (the Caldera plan export is not a posture surface)
    expect(host.textContent).not.toContain('Threat-weighted gap');    // nor the risk/Gaps summary cards
    // Item 1: what the fresh overlay SHOWS — total, the share %, Known (mapped of total), None, the prompt.
    expect(host.querySelector('[data-sim="total"]')).not.toBeNull();
    expect(host.querySelector('[data-sim="mapped"]')).not.toBeNull();
    expect(host.querySelector('[data-sim="none"]')).not.toBeNull();
    // The fresh-profile prompt is shown (both the single-sim and the overlay carry it).
    expect(host.textContent).toContain('Record a run or mark a mitigation implemented');
    // No 'covered'/'proven' anywhere in visible text or in title/aria-label/placeholder/alt.
    expect(host.textContent!.toLowerCase()).not.toContain('covered');
    expect(host.textContent!.toLowerCase()).not.toContain('proven');
    for (const attr of ['title', 'aria-label', 'placeholder', 'alt']) {
      for (const el of Array.from(host.querySelectorAll(`[${attr}]`))) {
        const v = (el.getAttribute(attr) ?? '').toLowerCase();
        expect(v).not.toContain('covered');
        expect(v).not.toContain('proven');
      }
    }
  }));

  it('with owner words, the Covered and Proven cards render with the vocabulary labels', fakeAsync(() => {
    ownerWords = true;
    buckets = new Map([['t1', 'covered'], ['t2', 'proven']]);
    configure();

    component.onGroupPicked(GROUP.id);
    tick(200);
    fixture.detectChanges();

    expect(component.result!.covered).toBe(1);
    expect(component.result!.proven).toBe(1);
    const host = fixture.nativeElement as HTMLElement;
    expect(host.querySelector('.outcome-covered')).not.toBeNull();
    expect(host.querySelector('.outcome-proven')).not.toBeNull();
    // Labels come from scenarioOutcomeLabel() — 'Covered (self-attested or range)'.
    expect(host.textContent).toContain('Covered (self-attested or range)');
  }));

  it('the overlay Known row shows mapped-of-total (knownSignals>0), mirroring ctem, not bucket-known', fakeAsync(() => {
    ownerWords = true;
    buckets = new Map([['t1', 'covered'], ['t2', 'none']]);   // bucket-'known' count is 0 here
    knownSignals = new Map([['t1', 2], ['t2', 0]]);           // one parent has a reference mapping
    configure(['t1', 't2']);

    component.runProfileSimulation();
    tick(200);
    fixture.detectChanges();

    const host = fixture.nativeElement as HTMLElement;
    // mapped = 1 (t1 has knownSignals>0), total = 2 — NOT the bucket-known count (0).
    expect(host.querySelector('[data-sim="mapped"]')!.textContent!.trim()).toBe('1');
    expect(host.querySelector('[data-sim="total-known"]')!.textContent!.trim()).toBe('2');
    expect(component.profileSimResult!.mappedCount).toBe(1);
    expect(component.profileSimResult!.knownCount).toBe(0);   // bucket-known differs from mapped
  }));

  // RP-F round 1: the single-actor picker keeps a picked group pressed, so it must follow
  // the panel's actor. A domain switch emits null first and the panel drops its actor;
  // the picker used to keep the old STIX id (shared across domains) pressed regardless.
  it('the single-actor picker shows the panel actor pressed, and none after a domain switch drops it', fakeAsync(() => {
    configure();
    const el = fixture.nativeElement as HTMLElement;
    const singlePicker = (): HTMLElement => el.querySelector('app-threat-profile-picker')!;   // the first one is mode="single"
    const pressed = (): string[] => Array.from(singlePicker().querySelectorAll('.tpp-item[aria-pressed="true"]'))
      .map((b) => b.querySelector('.tpp-item-id')!.textContent!.trim());
    expect(pressed()).toEqual([]);

    singlePicker().querySelector<HTMLButtonElement>('.tpp-item')!.click();
    tick(200);
    fixture.detectChanges();
    expect(component.selectedGroup).toBe(GROUP);
    expect(pressed()).toEqual(['G0001']);

    domain$.next(null);          // a domain switch: null first, the panel drops its actor
    fixture.detectChanges();
    domain$.next(DOMAIN);        // and back: the same STIX id exists again
    fixture.detectChanges();
    expect(component.selectedGroup).toBeNull();
    expect(pressed()).withContext('the picker agrees with the panel: no actor').toEqual([]);
  }));

  it('the open overlay recomputes when the profile changes (reactive, not a stale snapshot)', fakeAsync(() => {
    ownerWords = true;
    buckets = new Map([['t1', 'covered'], ['t2', 'covered']]);
    configure(['t1', 't2']);                        // profile = both parents

    component.runProfileSimulation();
    tick(200);
    fixture.detectChanges();
    expect(component.profileSimResult!.techniquesTotal).toBe(2);

    // The shared profile narrows to one parent: parents() changes and revision() bumps.
    parentsSig.set(new Set(['t1']));
    revisionSig.set(revisionSig() + 1);
    fixture.detectChanges();                        // flushes the effect

    expect(component.profileSimResult!.techniquesTotal).toBe(1);   // overlay followed the profile, no re-click
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-sim="total"]')!.textContent!.trim()).toBe('1');
  }));
});
