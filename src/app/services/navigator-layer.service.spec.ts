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
});
