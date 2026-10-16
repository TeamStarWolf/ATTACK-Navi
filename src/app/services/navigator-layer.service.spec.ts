// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BrowserFileService } from './browser-file.service';
import { ImplementationService } from './implementation.service';
import { NavigatorLayerService, detectStatusKeyword } from './navigator-layer.service';

describe('NavigatorLayerService', () => {
  let service: NavigatorLayerService;
  let implService: jasmine.SpyObj<ImplementationService>;

  beforeEach(() => {
    implService = jasmine.createSpyObj<ImplementationService>('ImplementationService', ['setStatus']);
    TestBed.configureTestingModule({
      providers: [
        NavigatorLayerService,
        BrowserFileService,
        { provide: ImplementationService, useValue: implService },
      ],
    });
    service = TestBed.inject(NavigatorLayerService);
  });

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
    techniques: [{ id: 'tech-1', attackId: 'T0801' }],
    mitigationsByTechnique: new Map([['tech-1', [{ mitigation: { id: 'mit-1', attackId: 'M0801' } }]]]),
  } as any);

  const foreignLayer = (comment: string, enabled = true) => JSON.stringify({
    name: 'Imported Layer',
    techniques: [{ techniqueID: 'T0801', comment, enabled }],
  });

  it('derives implementation statuses from navigator comments only when the caller opts in', async () => {
    // Default: the guess is reported, not written.
    const preview = await service.importLayer(foreignLayer('Status: implemented'), foreignDomain(), implService);
    expect(preview.layerName).toBe('Imported Layer');
    expect(preview.resolvedCount).toBe(1);
    expect(preview.derivedStatuses).toEqual([jasmine.objectContaining({
      techniqueId: 'T0801', mitigationId: 'mit-1', mitigationAttackId: 'M0801', status: 'implemented',
    })]);
    expect(preview.statusesApplied).toBe(0);
    expect(implService.setStatus).not.toHaveBeenCalled();

    // Opted in: the same guess is written.
    const applied = await service.importLayer(
      foreignLayer('Status: implemented'), foreignDomain(), implService, undefined,
      { deriveStatusesFromComments: true },
    );
    expect(applied.statusesApplied).toBe(1);
    expect(implService.setStatus).toHaveBeenCalledWith('mit-1', 'implemented');
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
    expect(result.statusesApplied).toBe(1);
    expect(result.notesApplied).toBe(1);
    expect(implService.setStatus).not.toHaveBeenCalled();
    expect(annotationService.setAnnotation).not.toHaveBeenCalled();
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
});
