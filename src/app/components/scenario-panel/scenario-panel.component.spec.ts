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
  let ownerWords: boolean;
  let parentsSig: WritableSignal<ReadonlySet<string>>;

  function configure(parentIds: string[] = ['t1', 't2']): void {
    domain$ = new BehaviorSubject<any>(DOMAIN);
    parentsSig = signal<ReadonlySet<string>>(new Set(parentIds));
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
            stateFor: (t: Technique) => ({ bucket: buckets.get(t.id) ?? 'none', subStates: subStates.get(t.id) ?? [], excluded: false }),
            ownerWords: () => ownerWords,
        } },
        // The REAL profile-scoped ThreatSimulationService over a fixture, so the overlay
        // exercises simulate() (item 5). Its gap/priority inputs are stubbed empty.
        { provide: THREAT_WEIGHT_PROVIDER, useValue: { weight: () => 0, revision: signal(0), parents: parentsSig } },
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

  beforeEach(() => { buckets = new Map(); subStates = new Map(); ownerWords = false; });

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
});
