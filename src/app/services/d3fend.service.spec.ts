// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { D3fendService, d3fendTechniqueApiUrl } from './d3fend.service';

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
});
