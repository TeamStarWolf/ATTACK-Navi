// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BrowserFileService } from './browser-file.service';
import { ImplementationService } from './implementation.service';
import { NavigatorLayerService } from './navigator-layer.service';

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

  it('imports navigator comments into implementation statuses', async () => {
    const result = await service.importLayer(JSON.stringify({
      name: 'Imported Layer',
      techniques: [{
        techniqueID: 'T0801',
        comment: 'Status: implemented',
      }],
    }), {
      techniques: [{ id: 'tech-1', attackId: 'T0801' }],
      mitigationsByTechnique: new Map([['tech-1', [{ mitigation: { id: 'mit-1' } }]]]),
    } as any, implService);

    expect(result.layerName).toBe('Imported Layer');
    expect(result.appliedCount).toBe(1);
    expect(implService.setStatus).toHaveBeenCalledWith('mit-1', 'implemented');
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
