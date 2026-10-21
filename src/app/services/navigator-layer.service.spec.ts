// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BrowserFileService } from './browser-file.service';
import { ImplementationService } from './implementation.service';
import { NavigatorLayerService, detectStatusKeyword } from './navigator-layer.service';
import { type ImplView, implView } from './posture-adapters';
import { TECHNIQUE_MARKS_KEY, TechniqueMarksService } from './technique-marks.service';
import type { ImplStatus } from './implementation.service';
import type { Technique } from '../models/technique';

describe('NavigatorLayerService', () => {
  let service: NavigatorLayerService;
  let implService: jasmine.SpyObj<ImplementationService>;
  let marks: TechniqueMarksService;

  beforeEach(() => {
    localStorage.removeItem(TECHNIQUE_MARKS_KEY);
    implService = jasmine.createSpyObj<ImplementationService>('ImplementationService', ['setStatus']);
    TestBed.configureTestingModule({
      providers: [
        NavigatorLayerService,
        BrowserFileService,
        { provide: ImplementationService, useValue: implService },
      ],
    });
    service = TestBed.inject(NavigatorLayerService);
    marks = TestBed.inject(TechniqueMarksService);
  });

  afterEach(() => localStorage.removeItem(TECHNIQUE_MARKS_KEY));

  it('builds navigator layers with domain-specific metadata', () => {
    const layer = service.buildLayer({
      name: 'ICS ATT&CK',
      attackVersion: '18',
      techniques: [{
        id: 'tech-1',
        attackId: 'T0801',
        tacticShortnames: ['inhibit-response-function'],
      }],
      mitigationsByTechnique: new Map([['tech-1', []]]),
    } as any, 'ics', new Map());

    expect(layer.domain).toBe('ics-attack');
    expect(layer.versions.attack).toBe('18');
    expect(layer.name).toContain('ICS ATT&CK');
  });

  const foreignDomain = () => ({
    attackVersion: '18',
    techniques: [{ id: 'tech-1', attackId: 'T0801' }],
    mitigationsByTechnique: new Map([['tech-1', [{ mitigation: { id: 'mit-1', attackId: 'M0801' } }]]]),
  } as any);

  const foreignLayer = (comment: string, enabled = true) => JSON.stringify({
    name: 'Imported Layer',
    techniques: [{ techniqueID: 'T0801', comment, enabled }],
  });

  it('derives a technique mark from a navigator comment only when the caller opts in, never a mitigation status (P2-16)', async () => {
    // Default: the guess is reported, not written.
    const preview = await service.importLayer(foreignLayer('Status: implemented'), foreignDomain(), implService, undefined, { attackDomain: 'ics' });
    expect(preview.layerName).toBe('Imported Layer');
    expect(preview.resolvedCount).toBe(1);
    expect(preview.derivedStatuses).toEqual([{ techniqueId: 'T0801', status: 'implemented', comment: 'Status: implemented' }]);
    expect([preview.statusesApplied, preview.marksApplied]).toEqual([0, 0]);
    expect(implService.setStatus).not.toHaveBeenCalled();
    expect(marks.all).toEqual([]);

    // Opted in: the same guess becomes one technique mark under layer:<name>; no mitigation status.
    const applied = await service.importLayer(
      foreignLayer('Status: implemented'), foreignDomain(), implService, undefined,
      { deriveStatusesFromComments: true, attackDomain: 'ics' },
    );
    expect([applied.statusesApplied, applied.marksApplied]).toEqual([0, 1]);
    expect(implService.setStatus).not.toHaveBeenCalled();
    expect(marks.all.map(m => [m.ref, m.status, m.source])).toEqual([['attack/ics/T0801@18', 'implemented', 'layer:Imported Layer']]);
  });

  it('never reads a negated or unrelated keyword as a status', async () => {
    for (const comment of [
      'Not implemented - no rule yet',
      'not yet implemented',
      'unimplemented',
      "isn't implemented",
      'unplanned',
      'no progress',
      'never planned',
      'partially implemented',
    ]) {
      const result = await service.importLayer(
        foreignLayer(comment), foreignDomain(), implService, undefined, { deriveStatusesFromComments: true },
      );
      expect(result.derivedStatuses).withContext(comment).toEqual([]);
      expect(result.statusesApplied).withContext(comment).toBe(0);
    }
    expect(implService.setStatus).not.toHaveBeenCalled();
  });

  it('reads anchored status keywords regardless of case and separators', () => {
    expect(detectStatusKeyword('Status: implemented')).toBe('implemented');
    expect(detectStatusKeyword('IMPLEMENTED via EDR policy')).toBe('implemented');
    expect(detectStatusKeyword('rollout in progress')).toBe('in-progress');
    expect(detectStatusKeyword('in-progress')).toBe('in-progress');
    expect(detectStatusKeyword('planned for Q3')).toBe('planned');
    expect(detectStatusKeyword('planned but not implemented')).toBe('planned');
    expect(detectStatusKeyword('detection coverage: none')).toBeNull();
    expect(detectStatusKeyword('')).toBeNull();
  });

  it('ignores disabled entries when deriving statuses', async () => {
    const result = await service.importLayer(
      foreignLayer('implemented', false), foreignDomain(), implService, undefined, { deriveStatusesFromComments: true },
    );
    expect(result.derivedStatuses).toEqual([]);
    expect(implService.setStatus).not.toHaveBeenCalled();
  });

  it('dryRun reports what would be applied without writing statuses or notes', async () => {
    const annotationService = jasmine.createSpyObj('AnnotationService', ['setAnnotation', 'getAnnotation']);
    annotationService.getAnnotation.and.returnValue(undefined);
    const result = await service.importLayer(
      foreignLayer('implemented'), foreignDomain(), implService, annotationService,
      { dryRun: true, deriveStatusesFromComments: true },
    );
    expect([result.statusesApplied, result.marksApplied]).toEqual([0, 1]);
    expect(result.notesApplied).toBe(1);
    expect(implService.setStatus).not.toHaveBeenCalled();
    expect(annotationService.setAnnotation).not.toHaveBeenCalled();
    expect(marks.all).toEqual([]);
  });

  // ── Technique-id resolution against the loaded release ────────────────

  const v19Domain = () => ({
    techniques: [
      { id: 'tech-1685-005', attackId: 'T1685.005' },
      { id: 'tech-1059', attackId: 'T1059' },
    ],
    mitigations: [],
    mitigationsByTechnique: new Map(),
    supersededBy: new Map([['T1070.001', 'T1685.005']]),
  } as any);

  it('resolves retired ids through supersededBy and reports what did not resolve', async () => {
    const annotationService = jasmine.createSpyObj('AnnotationService', ['setAnnotation', 'getAnnotation']);
    annotationService.getAnnotation.and.returnValue(undefined);

    const result = await service.importLayer(JSON.stringify({
      name: 'Pre-v19 layer',
      techniques: [
        { techniqueID: 'T1070.001', comment: 'cleared logs note' },
        { techniqueID: 'T9999', comment: 'typo' },
        { techniqueID: 'T1059', comment: 'shell' },
      ],
    }), v19Domain(), implService, annotationService);

    expect(result.techniqueIdCount).toBe(3);
    expect(result.resolvedCount).toBe(2);
    expect(result.remapped).toEqual([{ from: 'T1070.001', to: 'T1685.005' }]);
    expect(result.unresolvedIds).toEqual(['T9999']);
    // The retired entry's data lands on the replacement technique.
    expect(annotationService.setAnnotation).toHaveBeenCalledWith('T1685.005', 'cleared logs note');
    expect(annotationService.setAnnotation).toHaveBeenCalledWith('T1059', 'shell');
    expect(annotationService.setAnnotation).not.toHaveBeenCalledWith('T9999', jasmine.anything());
    expect(result.notesApplied).toBe(2);
  });

  it('lets a direct entry win over its retired alias, and still counts the alias as resolved', async () => {
    const annotationService = jasmine.createSpyObj('AnnotationService', ['setAnnotation', 'getAnnotation']);
    annotationService.getAnnotation.and.returnValue(undefined);

    const result = await service.importLayer(JSON.stringify({
      techniques: [
        { techniqueID: 'T1685.005', comment: 'current' },
        { techniqueID: 'T1070.001', comment: 'legacy' },
      ],
    }), v19Domain(), implService, annotationService);

    expect(annotationService.setAnnotation).toHaveBeenCalledWith('T1685.005', 'current');
    expect(annotationService.setAnnotation).not.toHaveBeenCalledWith('T1685.005', 'legacy');
    expect(result.remapped).toEqual([]);
    expect(result.unresolvedIds).toEqual([]);
    expect(result.resolvedCount).toBe(2);
  });

  // ── Round-trip fidelity ────────────────────────────────────────────────

  const roundTripDomain = () => ({
    name: 'Enterprise ATT&CK',
    attackVersion: '19',
    techniques: [{ id: 'tech-1', attackId: 'T1059', tacticShortnames: ['execution'] }],
    mitigations: [
      { id: 'mit-1', attackId: 'M1038' },
      { id: 'mit-2', attackId: 'M1049' },
    ],
    mitigationsByTechnique: new Map([['tech-1', [
      { mitigation: { id: 'mit-1', attackId: 'M1038' } },
      { mitigation: { id: 'mit-2', attackId: 'M1049' } },
    ]]]),
  } as any);

  it('exports exact per-mitigation statuses and notes in metadata', () => {
    const statuses = new Map<string, any>([['mit-1', 'implemented'], ['mit-2', 'planned']]);
    const annotations = new Map<string, any>([['T1059', { note: 'Reviewed in Q3 tabletop' }]]);
    const layer = service.buildLayer(roundTripDomain(), 'enterprise', statuses, annotations);
    const entry = layer.techniques.find(t => t.techniqueID === 'T1059')!;
    expect(entry.metadata).toContain(jasmine.objectContaining({
      name: 'attack-navi:mitStatuses', value: 'M1038=implemented;M1049=planned',
    }));
    expect(entry.metadata).toContain(jasmine.objectContaining({
      name: 'attack-navi:note', value: 'Reviewed in Q3 tabletop',
    }));
    expect(entry.comment).toContain('Reviewed in Q3 tabletop');
  });

  it('round-trips: import restores the exact statuses and notes it exported', async () => {
    const domain = roundTripDomain();
    const statuses = new Map<string, any>([['mit-1', 'implemented'], ['mit-2', 'planned']]);
    const annotations = new Map<string, any>([['T1059', { note: 'Reviewed in Q3 tabletop' }]]);
    const layer = service.buildLayer(domain, 'enterprise', statuses, annotations);

    const annotationService = jasmine.createSpyObj('AnnotationService', ['setAnnotation', 'getAnnotation']);
    annotationService.getAnnotation.and.returnValue(undefined);

    const result = await service.importLayer(JSON.stringify(layer), domain, implService, annotationService);
    expect(implService.setStatus).toHaveBeenCalledWith('mit-1', 'implemented');
    expect(implService.setStatus).toHaveBeenCalledWith('mit-2', 'planned');
    expect(annotationService.setAnnotation).toHaveBeenCalledWith('T1059', 'Reviewed in Q3 tabletop');
    expect(result.statusesApplied).toBe(2);
    expect(result.notesApplied).toBe(1);
  });

  it('does not turn its own exported display comments into notes or guessed statuses', async () => {
    const annotationService = jasmine.createSpyObj('AnnotationService', ['setAnnotation', 'getAnnotation']);
    annotationService.getAnnotation.and.returnValue(undefined);
    // Our export with one status and no analyst note: comment is "Status: implemented".
    const layer = service.buildLayer(roundTripDomain(), 'enterprise', new Map([['mit-1', 'implemented']]));
    expect(layer.techniques[0].comment).toBe('Status: implemented');

    const result = await service.importLayer(
      JSON.stringify(layer), roundTripDomain(), implService, annotationService, { deriveStatusesFromComments: true },
    );

    expect(implService.setStatus).toHaveBeenCalledOnceWith('mit-1', 'implemented'); // exact restore only
    expect(result.derivedStatuses).toEqual([]);
    expect(annotationService.setAnnotation).not.toHaveBeenCalled();
    expect(result.notesApplied).toBe(0);
  });

  it('never overwrites an existing analyst note with a foreign comment', async () => {
    const annotationService = jasmine.createSpyObj('AnnotationService', ['setAnnotation', 'getAnnotation']);
    annotationService.getAnnotation.and.returnValue({ note: 'My precious analysis' });

    await service.importLayer(JSON.stringify({
      name: 'Foreign Layer',
      techniques: [{ techniqueID: 'T1059', comment: 'vendor says patch this' }],
    }), roundTripDomain(), implService, annotationService);

    expect(annotationService.setAnnotation).not.toHaveBeenCalled();
  });
  // ── Breadth guard (P2-14, Addendum note 4) ─────────────────────────────

  describe('the guarded view (D16): a technique implemented only through a broad mitigation', () => {
    /** M1038 mapped to 79 techniques (threshold 15 by default); T1078 is also reached by the narrow M1032. */
    const broadDomain = () => {
      const tech = (attackId: string) => ({ id: `tech-${attackId}`, attackId, tacticShortnames: ['execution'] });
      const m1038 = { id: 'mit-1038', attackId: 'M1038' };
      const m1032 = { id: 'mit-1032', attackId: 'M1032' };
      const t1059 = tech('T1059');
      const t1078 = tech('T1078');
      const all = [t1059, t1078, ...Array.from({ length: 77 }, (_, i) => tech(`T9${String(i + 1).padStart(3, '0')}`))];
      return {
        name: 'Enterprise ATT&CK', attackVersion: '19', techniques: all, mitigations: [m1038, m1032],
        mitigationsByTechnique: new Map(all.map(t => [t.id, t === t1078
          ? [{ mitigation: m1038 }, { mitigation: m1032 }] : [{ mitigation: m1038 }]])),
        techniquesByMitigation: new Map([[m1038.id, all], [m1032.id, [t1078]]]),
      } as any;
    };
    const statuses = new Map<string, ImplStatus>([['mit-1038', 'implemented'], ['mit-1032', 'implemented']]);
    const entry = (layer: { techniques: Array<{ techniqueID: string; comment?: string; color?: string }> }, id: string) =>
      layer.techniques.find(t => t.techniqueID === id)!;
    const viewFor = (d: any, threshold: number, marks: Record<string, ImplStatus[]> = {}) =>
      (t: Technique): ImplView => implView(t, statuses, d, threshold, marks[t.attackId] ?? []);

    it("M1038 implemented, threshold 15: T1059 'Status: implemented, partial via M1038' in #64b5f6; T1078 'Status: implemented'", () => {
      const d = broadDomain();
      expect(d.techniquesByMitigation.get('mit-1038').length).toBe(79);
      for (const layer of [service.buildLayer(d, 'enterprise', statuses), service.buildLayer(d, 'enterprise', statuses, undefined, viewFor(d, 15))]) {
        expect(entry(layer, 'T1059').comment).toBe('Status: implemented, partial via M1038');
        expect(entry(layer, 'T1059').color).toBe('#64b5f6');
        expect(entry(layer, 'T1078').comment).toBe('Status: implemented');
        expect(entry(layer, 'T1078').color).toBe('#00c853');
        expect(layer.legendItems).toContain(jasmine.objectContaining({ color: '#64b5f6' }));
      }
    });

    it("threshold 100 (Settings > Posture rules) or a technique mark: T1059 'Status: implemented' in #00c853", () => {
      const d = broadDomain();
      const raised = service.buildLayer(d, 'enterprise', statuses, undefined, viewFor(d, 100));
      expect(entry(raised, 'T1059').comment).toBe('Status: implemented');
      expect(entry(raised, 'T1059').color).toBe('#00c853');
      const marked = service.buildLayer(d, 'enterprise', statuses, undefined, viewFor(d, 15, { T1059: ['implemented'] }));
      expect(entry(marked, 'T1059').comment).toBe('Status: implemented');
      expect(entry(marked, 'T1059').color).toBe('#00c853');
      expect(entry(marked, 'T9001').comment).toBe('Status: implemented, partial via M1038');
    });

    it('round-trips the exact statuses and never reads the partial comment as a note or a guessed status', async () => {
      const d = broadDomain();
      const annotationService = jasmine.createSpyObj('AnnotationService', ['setAnnotation', 'getAnnotation']);
      annotationService.getAnnotation.and.returnValue(undefined);
      const layer = service.buildLayer(d, 'enterprise', statuses);
      const result = await service.importLayer(JSON.stringify(layer), d, implService, annotationService, { deriveStatusesFromComments: true });
      expect(implService.setStatus).toHaveBeenCalledWith('mit-1038', 'implemented');
      expect(result.derivedStatuses).toEqual([]);
      expect(annotationService.setAnnotation).not.toHaveBeenCalled();
    });
  });
});
