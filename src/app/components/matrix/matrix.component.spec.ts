// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';

import { MatrixComponent } from './matrix.component';
import { Domain, TacticColumn } from '../../models/domain';
import { Tactic } from '../../models/tactic';
import { Technique } from '../../models/technique';
import { AttackNaviLayer } from '../../models/user-layer';
import { FilterService } from '../../services/filter.service';
import { LibraryLayerService, LibraryLayerMeta } from '../../services/library-layer.service';
import { UserLayerService } from '../../services/user-layer.service';

// ── fixtures ────────────────────────────────────────────────────────────────

function technique(attackId: string, name: string, tactics: string[], mitigationCount = 0): Technique {
  return {
    id: `attack-pattern--${attackId}`,
    attackId,
    name,
    description: '',
    url: '',
    tacticShortnames: tactics,
    isSubtechnique: attackId.includes('.'),
    parentId: null,
    subtechniques: [],
    mitigationCount,
    platforms: [],
    dataSources: [],
    detectionText: '',
    defenseBypassed: [],
    permissionsRequired: [],
    effectivePermissions: [],
    systemRequirements: [],
    impactType: [],
    remoteSupport: false,
    capecIds: [],
  };
}

function tactic(shortname: string, name: string, order: number): Tactic {
  return { id: `x-mitre-tactic--${shortname}`, attackId: `TA${order}`, name, shortname, description: '', url: '', order };
}

/** A tiny Domain: every technique that names a tactic lands in that column. */
function domain(name: string, tactics: Tactic[], techniques: Technique[]): Domain {
  const tacticColumns: TacticColumn[] = tactics.map(t => ({
    tactic: t,
    techniques: techniques.filter(x => !x.isSubtechnique && x.tacticShortnames.includes(t.shortname)),
  }));
  return {
    name,
    attackVersion: '19.2',
    attackModified: '',
    tactics,
    techniques,
    mitigations: [],
    tacticColumns,
    mitigationsByTechnique: new Map(),
    techniquesByMitigation: new Map(),
    maxMitigationCount: 4,
    groups: [],
    groupsByTechnique: new Map(),
    techniquesByGroup: new Map(),
    software: [],
    softwareByTechnique: new Map(),
    techniquesBySoftware: new Map(),
    proceduresByTechnique: new Map(),
    dataSources: [],
    dataComponents: [],
    techniquesByDataComponent: new Map(),
    dataComponentsByTechnique: new Map(),
    campaigns: [],
    campaignsByTechnique: new Map(),
    techniquesByCampaign: new Map(),
    softwareByGroup: new Map(),
    groupsBySoftware: new Map(),
    softwareByCampaign: new Map(),
    campaignsByGroup: new Map(),
    detectionNotesByTechnique: new Map(),
    supersededBy: new Map(),
    retiredNames: new Map(),
  };
}

function userLayer(scores: Record<string, { score: number | null; color?: string }>): AttackNaviLayer {
  return {
    id: 'layer-test',
    name: 'Uploaded',
    description: '',
    domain: 'enterprise',
    navigatorDomain: 'enterprise-attack',
    attackVersion: '19',
    navigatorVersion: '5.1.0',
    layerVersion: '4.5',
    filters: { platforms: [] },
    gradient: { colors: ['#ff6666', '#ffe766', '#8ec843'], minValue: 0, maxValue: 100 },
    legendItems: [],
    metadata: [],
    links: [],
    techniques: Object.entries(scores).map(([techniqueID, v]) => ({
      techniqueID,
      tactic: '',
      score: v.score,
      color: v.color ?? '',
      comment: '',
      enabled: true,
      metadata: [],
      links: [],
      showSubtechniques: false,
    })),
    importedAt: '2026-01-01T00:00:00.000Z',
    sourceFormat: 'navigator-4.5',
  };
}

// Fake attack ids keep every bundled enrichment seed (Sigma, CAR, Atomic, ...) at
// zero, so the only signal that differs between techniques is the one each spec sets.
const T_WELL_MITIGATED = technique('T9001', 'Well mitigated', ['stealth'], 4);
const T_UNMITIGATED = technique('T9002', 'Unmitigated', ['stealth'], 0);
const T_IMPACT = technique('T9003', 'Impact only', ['impact'], 0);

const ENTERPRISE = domain(
  'Enterprise ATT&CK',
  [tactic('stealth', 'Stealth', 1), tactic('impact', 'Impact', 2)],
  [T_WELL_MITIGATED, T_UNMITIGATED, T_IMPACT],
);
const ICS = domain(
  'ICS ATT&CK',
  [tactic('inhibit-response-function', 'Inhibit Response Function', 1), tactic('impair-process-control', 'Impair Process Control', 2)],
  [technique('T9801', 'ICS one', ['inhibit-response-function']), technique('T9802', 'ICS two', ['impair-process-control'])],
);

// ── stubs for the two layer services the library mode branches on ───────────

class LibraryLayerStub {
  manifest: LibraryLayerMeta[] = [
    { file: 'first.json', name: 'First curated layer', description: '' },
    { file: 'second.json', name: 'Second curated layer', description: '' },
  ];
  activeFile: string | null = null;
  readonly manifest$ = new BehaviorSubject<LibraryLayerMeta[]>(this.manifest);
  readonly activeFile$ = new BehaviorSubject<string | null>(null);
  readonly changed$ = new BehaviorSubject<boolean>(false);
  private scores = new Map<string, number>([['T9001', 40], ['T9002', 10]]);

  setActive = jasmine.createSpy('setActive').and.callFake((file: string) => {
    this.activeFile = file;
    this.activeFile$.next(file);
    this.changed$.next(true);
  });
  getScore(attackId: string): number { return this.scores.get(attackId) ?? 0; }
  maxScore(): number { return 40; }
  activeMeta(): LibraryLayerMeta | undefined { return this.manifest.find(m => m.file === this.activeFile); }
}

class UserLayerStub {
  activeLayer: AttackNaviLayer | null = null;
  readonly activeLayer$ = new BehaviorSubject<AttackNaviLayer | null>(null);
  readonly layers$ = new BehaviorSubject<unknown[]>([]);
  readonly changed$ = new BehaviorSubject<boolean>(false);

  apply(layer: AttackNaviLayer | null): void {
    this.activeLayer = layer;
    this.activeLayer$.next(layer);
    this.changed$.next(true);
  }
  getScore(attackId: string): number {
    return this.activeLayer?.techniques.find(t => t.techniqueID === attackId)?.score ?? 0;
  }
  maxScore(): number {
    const scores = (this.activeLayer?.techniques ?? []).map(t => t.score ?? 0);
    return scores.length ? Math.max(1, ...scores) : 1;
  }
  getGradientColor(attackId: string): string | null {
    const entry = this.activeLayer?.techniques.find(t => t.techniqueID === attackId);
    return entry?.color || null;
  }
  getEntry(attackId: string) {
    return this.activeLayer?.techniques.find(t => t.techniqueID === attackId) ?? null;
  }
}

describe('MatrixComponent', () => {
  let fixture: ComponentFixture<MatrixComponent>;
  let component: MatrixComponent;
  let filterService: FilterService;
  let library: LibraryLayerStub;
  let user: UserLayerStub;

  beforeEach(() => {
    library = new LibraryLayerStub();
    user = new UserLayerStub();
    TestBed.configureTestingModule({
      imports: [MatrixComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: LibraryLayerService, useValue: library },
        { provide: UserLayerService, useValue: user },
      ],
    });
    filterService = TestBed.inject(FilterService);
    fixture = TestBed.createComponent(MatrixComponent);
    component = fixture.componentInstance;
    fixture.componentRef.setInput('domain', ENTERPRISE);
    fixture.detectChanges();
  });

  afterEach(() => {
    // FilterService is a root singleton inside this TestBed; put the mode back so
    // the next spec starts from the real default.
    filterService.setHeatmapMode('unified');
  });

  it('starts in the unified heatmap mode and renders one column per tactic', () => {
    expect(component.heatmapMode).toBe('unified');
    expect(component.sortedColumns.map(c => c.tactic.shortname)).toEqual(['stealth', 'impact']);
    expect(component.sortedColumns[0].techniques.map(t => t.attackId)).toEqual(['T9001', 'T9002']);
    expect(fixture.nativeElement.querySelectorAll('.tactic-header').length).toBe(2);
  });

  it('unified score rewards a technique with more defensive signals', () => {
    const strong = component.getUnifiedScore(T_WELL_MITIGATED);
    const weak = component.getUnifiedScore(T_UNMITIGATED);
    expect(strong).toBeGreaterThan(weak);
    // Nothing is mapped to T9003 and it has no mitigations: it must not score
    // above the equally-bare T9002.
    expect(component.getUnifiedScore(T_IMPACT)).toBe(weak);
  });

  describe('library heatmap mode', () => {
    it('with no user layer, auto-selects the first curated layer and reads its scores', () => {
      filterService.setHeatmapMode('library');

      expect(component.heatmapMode).toBe('library');
      expect(library.setActive).toHaveBeenCalledWith('first.json');
      expect(component.getLibraryScore(T_WELL_MITIGATED)).toBe(40);
      expect(component.getLibraryScore(T_UNMITIGATED)).toBe(10);
      expect(component.getLibraryScore(T_IMPACT)).toBe(0);
      expect(component.getLibraryColorOverride(T_WELL_MITIGATED)).toBeNull();
      expect(component.maxLibraryScore).toBe(40);
    });

    it('keeps a layer the user already picked instead of resetting to the first one', () => {
      library.activeFile = 'second.json';
      filterService.setHeatmapMode('library');

      expect(library.setActive).not.toHaveBeenCalled();
      expect(library.activeFile).toBe('second.json');
    });

    it('prefers an active user layer: its scores, its colours and its own maximum', () => {
      user.apply(userLayer({ T9001: { score: 75 }, T9002: { score: 5, color: '#abcdef' } }));
      filterService.setHeatmapMode('library');

      expect(library.setActive).not.toHaveBeenCalled();
      expect(component.getLibraryScore(T_WELL_MITIGATED)).toBe(75);
      expect(component.getLibraryScore(T_UNMITIGATED)).toBe(5);
      expect(component.getLibraryColorOverride(T_UNMITIGATED)).toBe('#abcdef');
      expect(component.getLibraryColorOverride(T_WELL_MITIGATED)).toBeNull();
      expect(component.maxLibraryScore).toBe(75);
    });

    it('falls back to the curated layer once the user layer is cleared', () => {
      user.apply(userLayer({ T9001: { score: 75 } }));
      filterService.setHeatmapMode('library');
      expect(component.getLibraryScore(T_WELL_MITIGATED)).toBe(75);

      // clearActive() in the real service: activeLayer -> null, then changed$ fires.
      user.apply(null);

      expect(library.setActive).toHaveBeenCalledWith('first.json');
      expect(component.getLibraryScore(T_WELL_MITIGATED)).toBe(40);
      expect(component.getLibraryColorOverride(T_WELL_MITIGATED)).toBeNull();
      expect(component.maxLibraryScore).toBe(40);
    });

    it('re-applies the layer mode when the curated layer finishes loading', () => {
      filterService.setHeatmapMode('library');
      const spy = spyOn(filterService, 'setHeatmapMode').and.callThrough();

      library.changed$.next(true);
      expect(spy).toHaveBeenCalledWith('library');

      // ...but a layer change while another mode is active must not hijack it.
      filterService.setHeatmapMode('coverage');
      spy.calls.reset();
      library.changed$.next(true);
      expect(spy).not.toHaveBeenCalled();
    });
  });

  it('switching domains rebuilds the tactic columns from the new domain', () => {
    fixture.componentRef.setInput('domain', ICS);
    fixture.detectChanges();

    expect(component.sortedColumns.map(c => c.tactic.name)).toEqual([
      'Inhibit Response Function',
      'Impair Process Control',
    ]);
    expect(component.sortedColumns.flatMap(c => c.techniques.map(t => t.attackId))).toEqual(['T9801', 'T9802']);
    const headers = Array.from(
      fixture.nativeElement.querySelectorAll('.tactic-header') as NodeListOf<HTMLElement>,
    ).map(h => h.textContent ?? '');
    expect(headers.some(h => h.includes('Inhibit Response Function'))).toBeTrue();
    expect(headers.some(h => h.includes('Stealth'))).toBeFalse();
  });
});
