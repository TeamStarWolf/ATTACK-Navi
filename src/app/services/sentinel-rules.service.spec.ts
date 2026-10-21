// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SentinelRulesService } from './sentinel-rules.service';
import { SourceRegistryService, TRUNCATED_LISTING } from './source-registry.service';
import TREES from '../../testing/fixtures/github-tree-listings.json';

describe('SentinelRulesService', () => {
  let service: SentinelRulesService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(SentinelRulesService);
  });

  describe('getRuleCount', () => {
    it('returns 0 for unknown technique before any load', () => {
      expect(service.getRuleCount('T9999')).toBe(0);
    });
  });

  describe('getRulesForTechnique', () => {
    it('returns empty array before any load', () => {
      expect(service.getRulesForTechnique('T9999')).toEqual([]);
    });
  });

  describe('loadOnDemand', () => {
    it('does not throw when called', () => {
      expect(() => service.loadOnDemand()).not.toThrow();
    });
  });
  describe('tree listing (edoardogerosa/sentinel-attack)', () => {
    const TREE_URL = 'https://api.github.com/repos/edoardogerosa/sentinel-attack/git/trees/master?recursive=1';
    let httpMock: HttpTestingController;
    let registry: SourceRegistryService;

    beforeEach(() => {
      httpMock = TestBed.inject(HttpTestingController);
      registry = TestBed.inject(SourceRegistryService);
      service.loadOnDemand();
    });

    afterEach(() => httpMock.verify());

    it('reads no rule from the real listing (the upstream removed its rules on 2024-11-28): empty, rows 0', () => {
      const listing = TREES.sentinel.listing;
      expect(listing.tree.length).toBe(8);
      httpMock.expectOne(TREE_URL).flush(listing);
      const record = registry.get('sentinel-attack-tree');
      expect(record.status).toBe('empty');
      expect(record.rows).toBe(0);
      expect(service.getRuleCount('T1059')).toBe(0);
    });

    it('synthetic: counts a rule file whose path carries a technique id (keeps the path regex covered)', () => {
      httpMock.expectOne(TREE_URL).flush({
        truncated: false,
        tree: [{ path: 'detections/Execution/T1059.001-synthetic.json', type: 'blob' }],
      });
      expect(service.getRuleCount('T1059.001')).toBe(1);
      expect(service.getRulesForTechnique('T1059.001')[0].filename).toBe('T1059.001-synthetic.json');
      expect(registry.get('sentinel-attack-tree').status).toBe('loaded');
      expect(registry.get('sentinel-attack-tree').rows).toBe(1);
    });

    it('records a GitHub rate limit (403, X-RateLimit-Remaining 0) as failed, with the reset time', () => {
      const reset = Math.floor(new Date(2026, 9, 21, 9, 30).getTime() / 1000);
      httpMock.expectOne(TREE_URL).flush(
        { message: 'API rate limit exceeded for 203.0.113.7.' },
        { status: 403, statusText: 'Forbidden', headers: { 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': String(reset) } },
      );
      expect(registry.get('sentinel-attack-tree').status).toBe('failed');
      expect(registry.get('sentinel-attack-tree').lastError).toContain('resets at 09:30');
    });

    it('records a 404 as not found (branch or path moved), with the URL', () => {
      httpMock.expectOne(TREE_URL).flush({ message: 'Not Found' }, { status: 404, statusText: 'Not Found' });
      expect(registry.get('sentinel-attack-tree').lastError).toBe(`not found (branch or path moved): ${TREE_URL}`);
    });

    it('records status 0 as a network error, with the URL', () => {
      httpMock.expectOne(TREE_URL).error(new ProgressEvent('error'));
      expect(registry.get('sentinel-attack-tree').status).toBe('failed');
      expect(registry.get('sentinel-attack-tree').lastError).toBe(`network error: ${TREE_URL}`);
    });

    it('does not parse a truncated listing: failed, with the truncated wording, and no ids recorded', () => {
      httpMock.expectOne(TREE_URL).flush({
        truncated: true,
        tree: [{ path: 'detections/Execution/T1059.001-synthetic.json', type: 'blob' }],
      });
      expect(registry.get('sentinel-attack-tree').status).toBe('failed');
      expect(registry.get('sentinel-attack-tree').lastError).toBe(TRUNCATED_LISTING);
      expect(service.getRuleCount('T1059.001')).toBe(0);
      expect(service.getRulesForTechnique('T1059.001')).toEqual([]);
    });

    it('records a parse error thrown inside the response handler as failed, not loading', () => {
      // A path that is not a string makes the parser throw.
      httpMock.expectOne(TREE_URL).flush({ truncated: false, tree: [{ path: 5, type: 'blob' }] });
      expect(registry.get('sentinel-attack-tree').status).toBe('failed');
    });
  });
});
