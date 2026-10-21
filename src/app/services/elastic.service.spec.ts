// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ElasticService } from './elastic.service';
import { SourceRegistryService } from './source-registry.service';
import { RULE_COVERAGE_SNAPSHOT_URL } from './rule-coverage-snapshot.service';
import { RULE_COVERAGE_FIXTURE } from '../testing/rule-coverage-fixture';

describe('ElasticService (bundled rule-coverage snapshot)', () => {
  let service: ElasticService;
  let http: HttpTestingController;
  let registry: SourceRegistryService;
  const SECTION = RULE_COVERAGE_FIXTURE.sources.elastic;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
    service = TestBed.inject(ElasticService);
    http = TestBed.inject(HttpTestingController);
    registry = TestBed.inject(SourceRegistryService);
  });

  // Only the bundled asset is requested: no api.github.com tree listing any more.
  afterEach(() => http.verify());

  const current = <T>(obs: { subscribe(fn: (v: T) => void): { unsubscribe(): void } }): T => {
    let v!: T;
    obs.subscribe(x => (v = x)).unsubscribe();
    return v;
  };

  it('asks for the bundled asset at start-up and counts nothing before it arrives', () => {
    expect(registry.get('elastic-tree').status).toBe('loading');
    expect(service.getRuleCount('T1059')).toBe(0);
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
  });

  it('builds the technique-to-count map from its section; the count is the full number, not the listed rules', () => {
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
    for (const [id, t] of Object.entries(SECTION.techniques)) {
      expect(service.getRuleCount(id)).withContext(id).toBe(t.count);
      expect(service.getHeatScore(id)).withContext(id).toBe(t.count);
      expect(t.rules.length).toBeLessThan(t.count);
    }
    expect(service.getRuleCount('T9999')).toBe(0);
    expect(service.getCounts().size).toBe(3);
    expect(current<boolean>(service.loaded$)).toBeTrue();
    expect(current<number>(service.total$)).toBe(SECTION.ruleCount);
    expect(current<number>(service.covered$)).toBe(3);
  });

  it('does not add sub-technique counts to the parent again (the snapshot already rolled them up)', () => {
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
    expect(service.getRuleCount('T1059')).toBe(SECTION.techniques['T1059'].count);
  });

  it('records the source loaded with rows = techniques and the pinned commit in its version', () => {
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
    const r = registry.get('elastic-tree');
    expect(r.status).toBe('loaded');
    expect(r.rows).toBe(3);
    expect(r.version).toBe(`snapshot of 2026-10-21, ${SECTION.owner}/${SECTION.repo}@${SECTION.sha.slice(0, 7)} (commit ${SECTION.commitDate.slice(0, 10)}, ${SECTION.branch})`);
  });

  it('lists rule names with permalinks at the pinned commit', () => {
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
    let rules: Array<{ name: string; url: string }> = [];
    service.fetchRulesForTechnique('T1059').subscribe(r => (rules = r));
    expect(rules.map(r => r.name)).toEqual(SECTION.techniques['T1059'].rules.map(r => r.name));
    expect(rules[0].url).toBe(`https://github.com/${SECTION.owner}/${SECTION.repo}/blob/${SECTION.sha}/${SECTION.techniques['T1059'].rules[0].path}`);
    let none: unknown[] = [1];
    service.fetchRulesForTechnique('T9999').subscribe(r => (none = r));
    expect(none).toEqual([]);
  });

  it("fetchRulesForTechnique before the asset has arrived waits for it", () => {
    let rules: unknown[] | null = null;
    service.fetchRulesForTechnique('T1059').subscribe(r => (rules = r));
    expect(rules).toBeNull();
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
    expect((rules as unknown as unknown[]).length).toBe(2);
  });

  it("a missing asset (404) is failed with 'bundled snapshot missing', never empty; nothing claims loaded", () => {
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush('Not Found', { status: 404, statusText: 'Not Found' });
    const r = registry.get('elastic-tree');
    expect(r.status).toBe('failed');
    // The app's own file: a 404 means it is not in this build, not GitHub's 'branch or path moved'.
    expect(r.lastError).toBe(`bundled snapshot missing (not in this build (HTTP 404): ${RULE_COVERAGE_SNAPSHOT_URL})`);
    expect(r.lastError).not.toContain('branch or path moved');
    expect(r.rows).toBeNull();
    expect(current<boolean>(service.loaded$)).toBeFalse();
    expect(service.getRuleCount('T1059')).toBe(0);
  });

  it('an unreachable asset (status 0) is failed with the network reason', () => {
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).error(new ProgressEvent('error'));
    expect(registry.get('elastic-tree').status).toBe('failed');
    expect(registry.get('elastic-tree').lastError).toBe(`bundled snapshot missing (network error: ${RULE_COVERAGE_SNAPSHOT_URL})`);
  });

  it("a malformed asset is failed with 'bundled snapshot missing or malformed', never empty", () => {
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush({ generated: '2026-10-21', sources: {} });
    const r = registry.get('elastic-tree');
    expect(r.status).toBe('failed');
    expect(r.lastError).toBe("bundled snapshot missing or malformed: no 'elastic' section");
    expect(current<boolean>(service.loaded$)).toBeFalse();
  });

  it('a section with a wrongly typed field is failed by name, never with a TypeError', () => {
    const broken = { ...RULE_COVERAGE_FIXTURE, sources: { ...RULE_COVERAGE_FIXTURE.sources, elastic: { ...SECTION, commitDate: 42 } } };
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(broken);
    const r = registry.get('elastic-tree');
    expect(r.status).toBe('failed');
    expect(r.lastError).toBe("bundled snapshot missing or malformed: 'elastic' has no commit date");
    expect(current<boolean>(service.loaded$)).toBeFalse();
  });

  it('a null technique entry is failed by name, never with a TypeError', () => {
    const techniques = { ...SECTION.techniques, T1003: null };
    const broken = { ...RULE_COVERAGE_FIXTURE, sources: { ...RULE_COVERAGE_FIXTURE.sources, elastic: { ...SECTION, techniques } } };
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(broken);
    const r = registry.get('elastic-tree');
    expect(r.status).toBe('failed');
    expect(r.lastError).toBe("bundled snapshot missing or malformed: 'elastic' technique T1003 is not an object");
    expect(service.getRuleCount('T1059')).toBe(0);
  });
});
