// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture, fakeAsync, tick } from '@angular/core/testing';
import { BehaviorSubject, filter, take } from 'rxjs';
import { RoadmapPanelComponent } from './roadmap-panel.component';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { makePostureStub, postureStubProvider } from '../../testing/posture-stub';
import type { Domain } from '../../models/domain';
import type { Technique } from '../../models/technique';

describe('RoadmapPanelComponent', () => {
  let component: RoadmapPanelComponent;
  let fixture: ComponentFixture<RoadmapPanelComponent>;

  // The CTID mapping stub: outcome$ drives settled$() as the real service does, and
  // getCvesForTechnique answers from `mapped` (empty until the mapping "arrives").
  let outcome: BehaviorSubject<'pending' | 'loaded' | 'failed'>;
  let loaded: BehaviorSubject<boolean>;
  let mapped: Set<string>;
  let cve: Record<string, unknown>;

  beforeEach(() => {
    outcome = new BehaviorSubject<'pending' | 'loaded' | 'failed'>('pending');
    loaded = new BehaviorSubject(false);
    mapped = new Set();
    cve = {
      loadOnDemand: () => undefined,
      loaded$: loaded,
      settled$: () => outcome.pipe(filter(o => o !== 'pending'), take(1)),
      getCvesForTechnique: (id: string) => (mapped.has(id) ? [{ cveId: 'CVE-2024-0001' }] : []),
    };
    TestBed.configureTestingModule({
      imports: [RoadmapPanelComponent],
      providers: [
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()), getStatusMap: () => new Map() }},
        { provide: AttackCveService, useValue: cve },
        // P2-08: the Known count and the posture line read PostureService.rollup.
        postureStubProvider(makePostureStub(() => null)),
      ],
    });
    fixture = TestBed.createComponent(RoadmapPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  describe('Auto-Generate and the on-demand CTID mapping', () => {
    const tech = (id: string, attackId: string) => ({ id, attackId }) as Technique;
    const domain = {
      mitigations: [
        { id: 'm-a', attackId: 'M1001', name: 'A' },
        { id: 'm-b', attackId: 'M1002', name: 'B' },
      ],
      // A covers two techniques without CVEs; B covers one technique with CVEs. By technique
      // count alone A ranks first (6 vs 3); with the CVE weighting B does (3 + 5 = 8).
      techniquesByMitigation: new Map([
        ['m-a', [tech('t-1', 'T1001'), tech('t-2', 'T1002')]],
        ['m-b', [tech('t-3', 'T1003')]],
      ]),
      groupsByTechnique: new Map(),
    } as unknown as Domain;
    const button = () => fixture.nativeElement.querySelector('.generate-btn') as HTMLButtonElement;

    beforeEach(() => {
      mapped.add('T1003');
      component.domain = domain;
    });

    it('waits for the mapping, says so, then scores with the CVE weighting', fakeAsync(() => {
      component.generateAutoRoadmap();
      fixture.detectChanges();
      expect(component.waitingForCves).toBeTrue();
      expect(button().textContent).toContain('Loading the CVE mappings...');
      tick(1000);
      expect(component.autoRoadmap).toBeNull();

      outcome.next('loaded');
      fixture.detectChanges();
      expect(button().textContent).toContain('Analyzing...');
      tick(500);
      const q1 = component.autoRoadmap![0].mitigations;
      expect(q1[0].mitigation.attackId).toBe('M1002');
      expect(q1[0].cveCount).toBe(1);
      expect(component.generatingRoadmap).toBeFalse();
    }));

    it('with the mapping already in, scores at once as before', fakeAsync(() => {
      outcome.next('loaded');
      component.generateAutoRoadmap();
      fixture.detectChanges();
      expect(component.waitingForCves).toBeFalse();
      expect(button().textContent).toContain('Analyzing...');
      tick(500);
      expect(component.autoRoadmap![0].mitigations[0].cveCount).toBe(1);
    }));

    it('a roadmap scored after the mapping failed is scored again when a retry brings it in', fakeAsync(() => {
      mapped.clear();
      outcome.next('failed');
      component.generateAutoRoadmap();
      tick(500);
      expect(component.autoRoadmap![0].mitigations[0].mitigation.attackId).toBe('M1001');

      mapped.add('T1003');
      loaded.next(true);
      tick(500);
      expect(component.autoRoadmap![0].mitigations[0].mitigation.attackId).toBe('M1002');
    }));
  });
});
