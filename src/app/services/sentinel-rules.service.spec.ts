// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SentinelRulesService } from './sentinel-rules.service';
import { SourceRegistryService } from './source-registry.service';

// The upstream removed every rule on 2024-11-28: the service is the withdrawn stub the
// CIS Controls pattern uses, kept only so the technique drawer needs no change.
describe('SentinelRulesService (withdrawn upstream)', () => {
  let service: SentinelRulesService;
  let http: HttpTestingController;
  let registry: SourceRegistryService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(SentinelRulesService);
    http = TestBed.inject(HttpTestingController);
    registry = TestBed.inject(SourceRegistryService);
  });

  it('makes no request, even when the drawer asks it to load', () => {
    service.loadOnDemand();
    service.loadOnDemand();
    expect(http.match(() => true).length).toBe(0);
    http.verify();
  });

  it('holds no rules and never reports loaded', () => {
    service.loadOnDemand();
    expect(service.getRuleCount('T1059')).toBe(0);
    expect(service.getRulesForTechnique('T1059')).toEqual([]);
    let loaded = true;
    service.loaded$.subscribe(v => (loaded = v)).unsubscribe();
    expect(loaded).toBeFalse();
  });

  it('leaves the registry saying withdrawn upstream on 2024-11-28, with no data', () => {
    service.loadOnDemand();
    const r = registry.get('sentinel-attack-tree');
    expect(r.status).toBe('archived-upstream');
    expect(r.archivedUpstream).toBe('2024-11-28');
    expect(r.rows).toBeNull();
    expect(registry.hasData('sentinel-attack-tree')).toBeFalse();
  });
});
