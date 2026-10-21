// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import {
  RULE_COVERAGE_SNAPSHOT_URL, RuleCoverageSection, RuleCoverageSnapshotService, SNAPSHOT_MISSING,
  ruleLinks, rulePermalink, snapshotError, snapshotVersion,
} from './rule-coverage-snapshot.service';
import { ElasticService } from './elastic.service';
import { SplunkContentService } from './splunk-content.service';
import { SigmaService } from './sigma.service';
import { SourceRegistryService } from './source-registry.service';
import { SourceRetryService } from './source-retry.service';
import { RULE_COVERAGE_NOTE } from './source-inventory';
import { RULE_COVERAGE_FIXTURE } from '../testing/rule-coverage-fixture';

describe('RuleCoverageSnapshotService', () => {
  let service: RuleCoverageSnapshotService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
    service = TestBed.inject(RuleCoverageSnapshotService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('loads the bundled file once, on first use, and serves every section from it', () => {
    const seen: RuleCoverageSection[] = [];
    service.section('elastic').subscribe(s => seen.push(s));
    service.section('mdecrevoisier').subscribe(s => seen.push(s));
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
    service.section('splunk').subscribe(s => seen.push(s));
    http.expectNone(RULE_COVERAGE_SNAPSHOT_URL);
    expect(seen.map(s => s.repo)).toEqual(['detection-rules', 'SIGMA-detection-rules', 'security_content']);
    expect(seen.every(s => s.generated === '2026-10-21')).toBeTrue();
  });

  it("a missing file errors with 'bundled snapshot missing' and the reason, and is asked for again next time", () => {
    let error = '';
    service.section('elastic').subscribe({ error: e => (error = e.message) });
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush('Not Found', { status: 404, statusText: 'Not Found' });
    // The app's own file: a 404 says it is not in this build, not GitHub's 'branch or path moved'.
    expect(error).toBe(`${SNAPSHOT_MISSING} (not in this build (HTTP 404): ${RULE_COVERAGE_SNAPSHOT_URL})`);

    let repo = '';
    service.section('elastic').subscribe(s => (repo = s.repo));
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
    expect(repo).toBe('detection-rules');
  });

  it("a malformed file errors with 'bundled snapshot missing or malformed', never an empty section", () => {
    const errors: string[] = [];
    const cases: unknown[] = [
      'not json at all',
      { sources: RULE_COVERAGE_FIXTURE.sources },
      { generated: '2026-10-21', sources: {} },
      { generated: '2026-10-21', sources: { elastic: { ...RULE_COVERAGE_FIXTURE.sources.elastic, sha: 'main' } } },
      { generated: '2026-10-21', sources: { elastic: { ...RULE_COVERAGE_FIXTURE.sources.elastic, techniques: {} } } },
    ];
    for (const body of cases) {
      const fresh = TestBed.runInInjectionContext(() => new RuleCoverageSnapshotService());
      fresh.section('elastic').subscribe({ next: () => errors.push('loaded'), error: e => errors.push(e.message) });
      http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(body as object);
    }
    expect(errors.length).toBe(cases.length);
    for (const e of errors) expect(e.startsWith(`${SNAPSHOT_MISSING} or malformed: `)).withContext(e).toBeTrue();
  });

  it('every field a reader touches is checked, so a malformed section is named and never reaches a loader', () => {
    const E = RULE_COVERAGE_FIXTURE.sources.elastic;
    const T = E.techniques['T1059'];
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ branch: undefined }, "'elastic' names no branch"],
      [{ branch: 7 }, "'elastic' names no branch"],
      [{ commitDate: 42 }, "'elastic' has no commit date"],
      [{ commitDate: '21 October' }, "'elastic' has no commit date"],
      [{ licence: null }, "'elastic' names no licence"],
      [{ ruleCount: '2131' }, "'elastic' has no rule count"],
      [{ ruleCount: -1 }, "'elastic' has no rule count"],
      [{ techniqueCount: undefined }, "'elastic' has no technique count"],
      [{ techniques: [] }, "'elastic' lists no techniques"],
      [{ techniques: { ...E.techniques, T1003: null } }, "'elastic' technique T1003 is not an object"],
      [{ techniques: { ...E.techniques, T1003: { rules: [] } } }, "'elastic' technique T1003 has no rule count"],
      [{ techniques: { ...E.techniques, T1003: { count: 1 } } }, "'elastic' technique T1003 has no rule list"],
      [{ techniques: { ...E.techniques, T1003: { count: 1, rules: [null] } } }, "'elastic' technique T1003 lists a rule without a name or path"],
      [{ techniques: { ...E.techniques, T1003: { count: 1, rules: [{ name: 'x' }] } } }, "'elastic' technique T1003 lists a rule without a name or path"],
      [{ techniques: { TA0002: T } }, "'elastic' technique key 'TA0002' is not an ATT&CK technique id"],
    ];
    for (const [change, reason] of cases) {
      const fresh = TestBed.runInInjectionContext(() => new RuleCoverageSnapshotService());
      let error = '';
      fresh.section('elastic').subscribe({ next: () => (error = 'loaded'), error: e => (error = e.message) });
      http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush({ generated: '2026-10-21', sources: { elastic: { ...E, ...change } } });
      expect(error).withContext(JSON.stringify(change)).toBe(`${SNAPSHOT_MISSING} or malformed: ${reason}`);
    }
  });

  it('a response that is not JSON is named as such, not as a GitHub path problem', () => {
    let error = '';
    service.section('elastic').subscribe({ error: e => (error = e.message) });
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).error(new ProgressEvent('error'), { status: 200, statusText: 'OK' });
    expect(error).toBe(`${SNAPSHOT_MISSING} (not valid JSON: ${RULE_COVERAGE_SNAPSHOT_URL})`);
  });

  it('snapshotError words any reader error as a missing or malformed snapshot, once', () => {
    expect(snapshotError(new TypeError("Cannot read properties of null (reading 'count')")).message)
      .toBe(`${SNAPSHOT_MISSING} or malformed: Cannot read properties of null (reading 'count')`);
    const already = new Error(`${SNAPSHOT_MISSING} or malformed: 'elastic' lists no techniques`);
    expect(snapshotError(already)).toBe(already);
    expect(snapshotError('odd').message).toBe(`${SNAPSHOT_MISSING} or malformed: odd`);
  });

  it('builds permalinks at the pinned commit, each path segment encoded', () => {
    const src = RULE_COVERAGE_FIXTURE.sources.mdecrevoisier;
    expect(rulePermalink(src, 'windows-os/win-os-payload download (PowerShell).yaml')).toBe(
      'https://github.com/mdecrevoisier/SIGMA-detection-rules/blob/d61408af8769c74c96296b7ccc92d4bc3abb15af/'
      + 'windows-os/win-os-payload%20download%20(PowerShell).yaml');
    expect(ruleLinks(src, 'T9999')).toEqual([]);
  });

  it("states the version in the KEV snapshot's wording: generated date, repository@sha, commit date, branch", () => {
    const section = { ...RULE_COVERAGE_FIXTURE.sources.splunk, generated: '2026-10-21' };
    expect(snapshotVersion(section)).toBe('snapshot of 2026-10-21, splunk/security_content@678e76c (commit 2026-10-20, develop)');
  });
});

describe('rule coverage from the bundled snapshot: lenses, drawer, registry and retry', () => {
  let http: HttpTestingController;
  let registry: SourceRegistryService;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
    registry = TestBed.inject(SourceRegistryService);
  });

  /** Start the three services and answer the one asset request (and SigmaHQ's layer with a 404). */
  function loadAll(): { elastic: ElasticService; splunk: SplunkContentService; sigma: SigmaService } {
    const elastic = TestBed.inject(ElasticService);
    const splunk = TestBed.inject(SplunkContentService);
    const sigma = TestBed.inject(SigmaService);
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
    for (const req of http.match(() => true)) req.flush('', { status: 404, statusText: 'Not Found' });
    return { elastic, splunk, sigma };
  }

  it('the drawer surfaces list rule names with permalinks from all three for a technique in the fixture', () => {
    const { elastic, splunk, sigma } = loadAll();
    const names: Record<string, string[]> = {};
    const urls: string[] = [];
    elastic.fetchRulesForTechnique('T1059').subscribe(r => { names['elastic'] = r.map(x => x.name); urls.push(...r.map(x => x.url)); });
    splunk.fetchRulesForTechnique('T1059').subscribe(r => { names['splunk'] = r.map(x => x.name); urls.push(...r.map(x => x.url)); });
    sigma.fetchRulesForTechnique('T1059').subscribe(r => { names['sigma'] = r.map(x => x.title); urls.push(...r.map(x => x.url)); });
    http.verify();
    expect(names['elastic']).toEqual(['AWS Batch Job Submitted with Container Override by Unusual Identity', 'AWS Bedrock High Risk Filesystem or Execution Tool Invocation']);
    expect(names['splunk']).toEqual(['CMD Carry Out String Command Parameter', 'CMD Echo Pipe - Escalation']);
    expect(names['sigma']).toEqual(['Encoded PowerShell payload deployed (PowerShell)', 'Encoded PowerShell payload deployed via process execution']);
    expect(urls.length).toBe(6);
    expect(urls[0]).toBe('https://github.com/elastic/detection-rules/blob/7115bb0ab06c11c7994486ffe2bc0dc801ad8502/rules/integrations/aws/execution_batch_job_submitted_container_override_unusual_identity.toml');
    expect(urls[2]).toBe('https://github.com/splunk/security_content/blob/678e76c5f36f6fadd93a1eaa0d82c1dbe273c486/detections/endpoint/cmd_carry_out_string_command_parameter.yml');
    expect(urls[4]).toContain('/blob/d61408af8769c74c96296b7ccc92d4bc3abb15af/windows-os/win-os-payload%20encoded%20PowerShell%20deployed%20(PowerShell).yaml');
    expect(sigma.getCachedRules('T1059')!.length).toBe(2);
  });

  it('the lenses read the count map: the full count, not the listed rules', () => {
    const { elastic, splunk, sigma } = loadAll();
    expect(elastic.getRuleCount('T1059')).toBe(323);
    expect(elastic.getHeatScore('T1059.001')).toBe(111);
    expect(splunk.getRuleCount('T1059')).toBe(165);
    expect(sigma.getCommunityRuleCount('T1484.002')).toBe(RULE_COVERAGE_FIXTURE.sources.mdecrevoisier.techniques['T1484.002'].count);
    expect(elastic.getRuleCount('T9999')).toBe(0);
    expect([...elastic.getCounts().keys()]).toEqual(['T1059', 'T1059.001', 'T1114']);
  });

  it('records each source as a loaded pinned snapshot: rows are techniques, the version names the commit and dates, the note says reference data', () => {
    loadAll();
    const expected: Record<string, string> = {
      'elastic-tree': 'snapshot of 2026-10-21, elastic/detection-rules@7115bb0 (commit 2026-10-21, main)',
      'splunk-tree': 'snapshot of 2026-10-21, splunk/security_content@678e76c (commit 2026-10-20, develop)',
      'mdecrevoisier-sigma-tree': 'snapshot of 2026-10-21, mdecrevoisier/SIGMA-detection-rules@d61408a (commit 2026-05-20, main)',
    };
    for (const [id, version] of Object.entries(expected)) {
      const r = registry.get(id);
      expect(r.kind).withContext(id).toBe('bundled');
      expect(r.status).withContext(id).toBe('loaded');
      expect(r.rows).withContext(id).toBe(3);
      expect(r.version).withContext(id).toBe(version);
      expect(r.note).withContext(id).toBe(RULE_COVERAGE_NOTE);
      expect(r.onDemand).withContext(id).toBeFalsy();
      expect(r.name).withContext(id).toContain('(pinned snapshot)');
    }
    expect(RULE_COVERAGE_NOTE).toContain('Reference data about a public rule repository at the pinned commit');
    expect(RULE_COVERAGE_NOTE).not.toMatch(/\b(known|covered|proven|detected)\b/i);
  });

  it("a missing asset fails all three with 'bundled snapshot missing', never 'empty', and no lens claims data", () => {
    const elastic = TestBed.inject(ElasticService);
    TestBed.inject(SplunkContentService);
    const sigma = TestBed.inject(SigmaService);
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush('Not Found', { status: 404, statusText: 'Not Found' });
    for (const req of http.match(() => true)) req.flush('', { status: 404, statusText: 'Not Found' });
    for (const id of ['elastic-tree', 'splunk-tree', 'mdecrevoisier-sigma-tree']) {
      expect(registry.get(id).status).withContext(id).toBe('failed');
      expect(registry.get(id).lastError).withContext(id).toContain('bundled snapshot missing');
    }
    let loaded = true;
    elastic.loaded$.subscribe(v => (loaded = v)).unsubscribe();
    expect(loaded).toBeFalse();
    expect(elastic.getRuleCount('T1059')).toBe(0);
    expect(sigma.getCommunityRuleCount('T1059')).toBe(0);
    // The drawer's rule list asks again (not cached) and records the outcome.
    let rules: unknown[] | null = null;
    sigma.fetchRulesForTechnique('T1059').subscribe(r => (rules = r));
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(RULE_COVERAGE_FIXTURE);
    expect((rules as unknown as unknown[]).length).toBe(2);
    expect(registry.get('mdecrevoisier-sigma-tree').status).toBe('loaded');
  });

  it('a malformed section fails that source, never empty', () => {
    TestBed.inject(ElasticService);
    const broken = { ...RULE_COVERAGE_FIXTURE, sources: { ...RULE_COVERAGE_FIXTURE.sources, elastic: { ...RULE_COVERAGE_FIXTURE.sources.elastic, techniques: {} } } };
    http.expectOne(RULE_COVERAGE_SNAPSHOT_URL).flush(broken);
    expect(registry.get('elastic-tree').status).toBe('failed');
    expect(registry.get('elastic-tree').lastError).toBe("bundled snapshot missing or malformed: 'elastic' lists no techniques");
  });

  it('Retry is not offered for the bundled snapshot or the withdrawn sentinel-attack source', () => {
    const retry = TestBed.inject(SourceRetryService);
    for (const id of ['elastic-tree', 'splunk-tree', 'mdecrevoisier-sigma-tree']) {
      expect(retry.hasLoader(id)).withContext(id).toBeFalse();
      expect(retry.unavailableReason(id)).withContext(id).toContain('bundled snapshot shipped with the app');
      expect(retry.retry(id)).withContext(id).toBeFalse();
    }
    expect(retry.hasLoader('sentinel-attack-tree')).toBeFalse();
    expect(retry.unavailableReason('sentinel-attack-tree')).toBe('withdrawn upstream; nothing to fetch');
  });

  it('records sentinel-attack as withdrawn upstream on 2024-11-28, with no data and no request', () => {
    const r = registry.get('sentinel-attack-tree');
    expect(r.status).toBe('archived-upstream');
    expect(r.archivedUpstream).toBe('2024-11-28');
    expect(r.onDemand).toBeFalsy();
    expect(r.note).toContain('Source withdrawn upstream');
    expect(registry.hasData('sentinel-attack-tree')).toBeFalse();
    http.verify();
  });
});
