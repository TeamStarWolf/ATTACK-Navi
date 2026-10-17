// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { D3FEND_MAPPING, D3fendService, d3fendTechniqueApiUrl } from './d3fend.service';
import D3FEND_ALL from '../testing/__snapshots__/d3fend-all-techniques.json';

describe('D3fendService', () => {
  let service: D3fendService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(D3fendService);
  });

  describe('getAllTechniques', () => {
    it('returns the bundled D3FEND mapping list', () => {
      const all = service.getAllTechniques();
      expect(all.length).toBeGreaterThan(0);
      expect(all[0].id).toMatch(/^D3-/);
      expect(all[0].url).toContain('d3fend');
    });
  });

  describe('getCountermeasures', () => {
    it('returns countermeasures for a known mapped technique', () => {
      const cms = service.getCountermeasures('T1059');
      expect(cms.length).toBeGreaterThanOrEqual(1);
      expect(cms[0].attackIds).toContain('T1059');
    });

    it('returns empty array for unknown technique', () => {
      expect(service.getCountermeasures('T9999')).toEqual([]);
    });
  });

  describe('getAllByCategory', () => {
    it('groups countermeasures by category', () => {
      const grouped = service.getAllByCategory();
      expect(grouped.size).toBeGreaterThanOrEqual(1);
      const categoryNames = [...grouped.keys()];
      // Should contain at least one of the known D3FEND tactic categories
      expect(categoryNames.some(c => ['Harden', 'Detect', 'Isolate', 'Deceive', 'Evict'].includes(c))).toBe(true);
    });
  });

  // Plan E1.5: d3fend.mitre.org keys a sub-technique by its dotted ATT&CK id.
  // https://d3fend.mitre.org/api/offensive-technique/attack/T1059.001.json is
  // 200 and .../T1059/001.json is 404 (both checked on 2026-10-17), so the
  // slash form put a D3FEND 404 in the console for every sub-technique drawer.
  describe('per-technique API URL (E1.5)', () => {
    const API = 'https://d3fend.mitre.org/api/offensive-technique/attack/';

    it('keeps the dot in a sub-technique id', () => {
      expect(d3fendTechniqueApiUrl('T1059.001')).toBe(`${API}T1059.001.json`);
      expect(d3fendTechniqueApiUrl('T1003.006')).toBe(`${API}T1003.006.json`);
    });

    it('leaves a parent technique id as it is', () => {
      expect(d3fendTechniqueApiUrl('T1059')).toBe(`${API}T1059.json`);
    });

    it('requests the dotted sub-technique URL and its parent, never the slash form', () => {
      const http = TestBed.inject(HttpTestingController);
      service.getCountermeasures('T1059.001', true);
      const urls = http
        .match(req => req.url.startsWith(API))
        .map(req => req.request.url)
        .sort();
      expect(urls).toEqual([`${API}T1059.001.json`, `${API}T1059.json`]);
      expect(urls.some(u => u.includes('T1059/001'))).toBe(false);
    });

    it('serves the live sub-technique countermeasures with a d3fend.mitre.org technique link', () => {
      const http = TestBed.inject(HttpTestingController);
      service.getCountermeasures('T1059.001', true);
      http.expectOne(`${API}T1059.001.json`).flush({
        off_to_def: {
          results: {
            bindings: [
              {
                def_tech_id: { value: 'D3-FIM' },
                def_tech_label: { value: 'File Integrity Monitoring' },
                def_tactic_label: { value: 'Detect' },
                def_tech: { value: 'http://d3fend.mitre.org/ontologies/d3fend.owl#FileIntegrityMonitoring' },
              },
            ],
          },
        },
      });
      const live = service.getCountermeasures('T1059.001').find(c => c.id === 'D3-FIM');
      expect(live?.url).toBe('https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring');
    });
  });

  // Seed currency: every seed entry must be a current D3FEND technique, so the
  // offline fallback never links to a removed or renamed d3fend.mitre.org page.
  // The snapshot is https://d3fend.mitre.org/api/technique/all.json as fetched
  // on 2026-10-17, the same list loadOntologyIndex fetches at startup.
  describe('seed currency against the D3FEND technique list', () => {
    type OntologyNode = { '@id': string; 'd3f:d3fend-id'?: string; 'rdfs:label'?: string };
    const graph = (D3FEND_ALL as { '@graph': OntologyNode[] })['@graph'];
    const byD3fendId = new Map<string, OntologyNode>();
    for (const n of graph) if (n['d3f:d3fend-id']) byD3fendId.set(n['d3f:d3fend-id'], n);
    const ontologyIds = new Set(graph.map(n => n['@id']));
    const norm = (s: string) => s.toLowerCase().replace(/[\s\-/]/g, '');
    const PAGE = 'https://d3fend.mitre.org/technique/';
    const ALL_URL = 'https://d3fend.mitre.org/api/technique/all.json';
    const seedIds = () => D3FEND_MAPPING.map(d => d.id).sort();

    it('reads a non-empty snapshot and seed', () => {
      expect(graph.length).toBeGreaterThan(0);
      expect(D3FEND_MAPPING.length).toBeGreaterThan(0);
    });

    it('links every seed entry to a technique page whose fragment is an @id in all.json', () => {
      const missing = D3FEND_MAPPING
        .filter(d => !d.url.startsWith(PAGE) || !ontologyIds.has(d.url.slice(PAGE.length)))
        .map(d => `${d.id} ${d.url}`);
      expect(missing).toEqual([]);
    });

    it('links every seed entry to the page of its own D3FEND id', () => {
      const wrong = D3FEND_MAPPING
        .filter(d => `${PAGE}${byD3fendId.get(d.id)?.['@id']}` !== d.url)
        .map(d => `${d.id} ${d.url} (expected ${byD3fendId.get(d.id)?.['@id']})`);
      expect(wrong).toEqual([]);
    });

    it('names every seed entry with its current D3FEND label, so the startup reconcile keeps it', () => {
      const renamed = D3FEND_MAPPING
        .filter(d => norm(byD3fendId.get(d.id)?.['rdfs:label'] ?? '') !== norm(d.name))
        .map(d => `${d.id} ${d.name} (current: ${byD3fendId.get(d.id)?.['rdfs:label']})`);
      expect(renamed).toEqual([]);
    });

    it('renders every seed entry offline, before the ontology index responds', () => {
      expect(service.getAllTechniques().map(d => d.id).sort()).toEqual(seedIds());
    });

    it('keeps every seed entry once the ontology index answers with the snapshot', () => {
      const http = TestBed.inject(HttpTestingController);
      http.expectOne(ALL_URL).flush(D3FEND_ALL);
      expect(service.getAllTechniques().map(d => d.id).sort()).toEqual(seedIds());
    });
  });
});
