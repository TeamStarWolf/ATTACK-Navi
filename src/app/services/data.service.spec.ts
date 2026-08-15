// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { DataService } from './data.service';

describe('DataService', () => {
  let service: DataService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        {
          provide: HttpClient,
          useValue: { get: () => of({}) },
        },
      ],
    });
    service = TestBed.inject(DataService);
  });

  it('should ignore stale load results when a newer request wins', fakeAsync(() => {
    const enterpriseDomain = { name: 'Enterprise ATT&CK' } as any;
    const icsDomain = { name: 'ICS ATT&CK' } as any;
    const pending: Array<() => void> = [];

    spyOn<any>(service, 'loadLive').and.callFake((config: { name: string }) =>
      new Observable((subscriber) => {
        pending.push(() => subscriber.next(config.name === 'Enterprise ATT&CK' ? enterpriseDomain : icsDomain));
      })
    );

    service.loadDomain();
    service.switchDomain('ics');

    pending[1]();
    pending[0]();
    tick();

    expect(service.getCurrentDomain()).toBe(icsDomain);
  }));

  it('should load bundled data for mobile when bundled mode is selected', fakeAsync(() => {
    const mobileDomain = { name: 'Mobile ATT&CK' } as any;

    spyOn<any>(service, 'loadBundled').and.returnValue(of(mobileDomain));

    service.setDataSourceMode('bundled');
    service.switchDomain('mobile');
    tick();

    expect((service as any).loadBundled).toHaveBeenCalled();
    expect(service.getCurrentDomain()).toBe(mobileDomain);
  }));

  describe('parseBundle relationship indexes', () => {
    const ref = (id: string, source = 'mitre-attack') => [{ source_name: source, external_id: id, url: `https://attack.mitre.org/x/${id}` }];

    const bundle = {
      objects: [
        { type: 'x-mitre-collection', x_mitre_version: '17.1', modified: '2026-01-01' },
        { type: 'attack-pattern', id: 'attack-pattern--t1', name: 'Tech One', external_references: ref('T1001'), kill_chain_phases: [{ phase_name: 'execution' }] },
        { type: 'intrusion-set', id: 'intrusion-set--g2', name: 'Group Two', external_references: ref('G0002') },
        { type: 'intrusion-set', id: 'intrusion-set--g1', name: 'Group One', external_references: ref('G0001') },
        { type: 'tool', id: 'tool--s1', name: 'Tool One', external_references: ref('S0001') },
        { type: 'campaign', id: 'campaign--c1', name: 'Camp One', external_references: ref('C0001') },
        { type: 'course-of-action', id: 'course-of-action--m1', name: 'Mit One', external_references: ref('M1001') },
        { type: 'x-mitre-data-component', id: 'x-mitre-data-component--dc1', name: 'Process Creation' },
        // group→technique twice (duplicate pair, two procedure descriptions), out of attackId order
        { type: 'relationship', relationship_type: 'uses', source_ref: 'intrusion-set--g2', target_ref: 'attack-pattern--t1', description: 'G2 procedure' },
        { type: 'relationship', relationship_type: 'uses', source_ref: 'intrusion-set--g1', target_ref: 'attack-pattern--t1', description: 'G1 procedure A' },
        { type: 'relationship', relationship_type: 'uses', source_ref: 'intrusion-set--g1', target_ref: 'attack-pattern--t1', description: 'G1 procedure B' },
        // toolkit + campaign relationships (previously dropped)
        { type: 'relationship', relationship_type: 'uses', source_ref: 'intrusion-set--g1', target_ref: 'tool--s1' },
        { type: 'relationship', relationship_type: 'uses', source_ref: 'campaign--c1', target_ref: 'tool--s1' },
        { type: 'relationship', relationship_type: 'uses', source_ref: 'campaign--c1', target_ref: 'attack-pattern--t1', description: 'C1 procedure' },
        { type: 'relationship', relationship_type: 'attributed-to', source_ref: 'campaign--c1', target_ref: 'intrusion-set--g1' },
        { type: 'relationship', relationship_type: 'uses', source_ref: 'tool--s1', target_ref: 'attack-pattern--t1', description: 'S1 procedure' },
        { type: 'relationship', relationship_type: 'mitigates', source_ref: 'course-of-action--m1', target_ref: 'attack-pattern--t1', description: 'mitigation note' },
        { type: 'relationship', relationship_type: 'detects', source_ref: 'x-mitre-data-component--dc1', target_ref: 'attack-pattern--t1', description: 'Watch for odd child processes' },
      ],
    };

    it('indexes group and campaign toolkits (uses → software)', () => {
      const domain = (service as any).parseBundle(bundle);
      expect(domain.softwareByGroup.get('intrusion-set--g1')?.map((s: any) => s.attackId)).toEqual(['S0001']);
      expect(domain.groupsBySoftware.get('tool--s1')?.map((g: any) => g.attackId)).toEqual(['G0001']);
      expect(domain.softwareByCampaign.get('campaign--c1')?.map((s: any) => s.attackId)).toEqual(['S0001']);
    });

    it('builds the campaign attribution reverse index', () => {
      const domain = (service as any).parseBundle(bundle);
      expect(domain.campaignsByGroup.get('intrusion-set--g1')?.map((c: any) => c.attackId)).toEqual(['C0001']);
    });

    it('captures campaign procedure examples', () => {
      const domain = (service as any).parseBundle(bundle);
      const procs = domain.proceduresByTechnique.get('attack-pattern--t1') ?? [];
      const campaignProc = procs.find((p: any) => p.sourceType === 'campaign');
      expect(campaignProc?.attackId).toBe('C0001');
      expect(campaignProc?.description).toBe('C1 procedure');
    });

    it('captures detection notes from detects relationships', () => {
      const domain = (service as any).parseBundle(bundle);
      const notes = domain.detectionNotesByTechnique.get('attack-pattern--t1') ?? [];
      expect(notes.length).toBe(1);
      expect(notes[0].dataComponentName).toBe('Process Creation');
      expect(notes[0].description).toBe('Watch for odd child processes');
    });

    it('dedupes duplicate relationship pairs and sorts indexes by attackId', () => {
      const domain = (service as any).parseBundle(bundle);
      // g1 appears in two uses rels but must index once; g1 sorts before g2
      expect(domain.groupsByTechnique.get('attack-pattern--t1')?.map((g: any) => g.attackId)).toEqual(['G0001', 'G0002']);
      // both procedure descriptions survive the dedupe
      const g1Procs = (domain.proceduresByTechnique.get('attack-pattern--t1') ?? [])
        .filter((p: any) => p.attackId === 'G0001');
      expect(g1Procs.length).toBe(2);
    });
  });
});
