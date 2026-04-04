import { TestBed } from '@angular/core/testing';
import { LayersService } from './layers.service';

describe('LayersService', () => {
  let service: LayersService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [LayersService],
    });
    service = TestBed.inject(LayersService);
  });

  it('should throw for invalid JSON imports', () => {
    expect(() => service.importLayer('not-json')).toThrowError('Invalid JSON');
  });

  it('should throw for malformed layer payloads', () => {
    expect(() => service.importLayer(JSON.stringify({ nope: true }))).toThrowError('Invalid layer payload');
  });

  it('should throw for malformed layer state payloads', () => {
    const invalidLayer = {
      id: 'layer-1',
      name: 'Layer One',
      description: 'desc',
      createdAt: new Date().toISOString(),
      state: {
        heatmapMode: 'coverage',
        activeThreatGroupIds: ['g-1'],
        activeSoftwareIds: ['s-1'],
        activeCampaignIds: ['c-1'],
        activeMitigationFilterIds: ['m-1'],
        whatIfMitigationIds: ['m-2'],
        platformFilter: null,
        sortMode: 'alpha',
        dimUncovered: false,
        searchFilterMode: false,
        hiddenTacticIds: ['ta0001'],
        implStatus: { 'm-1': 'bogus-status' },
        techNotes: {},
        mitDocs: {},
      },
    };

    expect(() => service.importLayer(JSON.stringify(invalidLayer))).toThrowError('Invalid layer payload');
  });

  it('should import valid layers and assign a fresh id', () => {
    const validLayer = {
      id: 'layer-1',
      name: 'Layer One',
      description: 'desc',
      createdAt: new Date().toISOString(),
      state: {
        heatmapMode: 'coverage',
        activeThreatGroupIds: ['g-1'],
        activeSoftwareIds: ['s-1'],
        activeCampaignIds: ['c-1'],
        activeMitigationFilterIds: ['m-1'],
        whatIfMitigationIds: ['m-2'],
        platformFilter: null,
        sortMode: 'alpha',
        dimUncovered: false,
        searchFilterMode: false,
        hiddenTacticIds: ['ta0001'],
        implStatus: { 'm-1': 'planned' },
        techNotes: { 't-1': 'note' },
        mitDocs: {
          'm-1': {
            notes: 'doc',
            owner: 'owner',
            dueDate: '2026-01-01',
            controlRefs: 'CIS 1',
            evidenceUrl: 'https://example.com',
          },
        },
      },
    };

    service.importLayer(JSON.stringify(validLayer));

    const stored = JSON.parse(localStorage.getItem('mitre-nav-layers-v1') ?? '[]');
    expect(stored).toHaveSize(1);
    expect(stored[0].name).toBe('Layer One');
    expect(stored[0].id).not.toBe('layer-1');
  });
});
