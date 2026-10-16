// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Data-currency guard: every ATT&CK id hard-coded in the curated detection
// tables, the D3FEND seed and the generated CVE->technique asset must be a LIVE
// technique in the bundled Enterprise release. A monthly data refresh that
// retires one of them fails here instead of silently turning its content into
// dead weight that no matrix cell can reach.
import { TestBed } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { DataService } from './data.service';
import { AttackIdResolverService } from './attack-id-resolver.service';
import { YaraService } from './yara.service';
import { WazuhService } from './wazuh.service';
import { EventLoggingService, TECHNIQUE_TO_LOGGING } from './event-logging.service';
import { D3FEND_MAPPING } from './d3fend.service';
import { Domain } from '../models/domain';

describe('Hard-coded ATT&CK ids vs the bundled Enterprise release', () => {
  let domain: Domain;
  let live: Set<string>;
  let cveMapKeys: string[];
  let originalTimeout: number;

  beforeAll(async () => {
    originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 120_000;
    const [bundle, cveMap] = await Promise.all([
      fetch('/assets/data/enterprise-attack.json').then((r) => r.json()),
      fetch('/assets/data/cve-technique-map.json').then((r) => r.json()),
    ]);
    TestBed.configureTestingModule({ providers: [{ provide: HttpClient, useValue: { get: () => of({}) } }] });
    domain = (TestBed.inject(DataService) as any).parseBundle(bundle);
    live = new Set(domain.techniques.map((t) => t.attackId));
    cveMapKeys = Object.keys(cveMap).filter((k) => k !== '__meta');
    TestBed.resetTestingModule();
  }, 120_000);

  afterAll(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
  });

  const notLive = (ids: Iterable<string>) => [...new Set(ids)].filter((id) => !live.has(id)).sort();

  it('parses the bundled v19 release', () => {
    expect(domain.attackVersion).toMatch(/^19\./);
    expect(live.has('T1685')).toBe(true);
    expect(domain.supersededBy.get('T1562.001')).toBe('T1685');
    expect(domain.supersededBy.get('T1070.001')).toBe('T1685.005');
  });

  it('YARA patterns are keyed by live techniques', () => {
    TestBed.configureTestingModule({});
    const ids = TestBed.inject(YaraService).getAllPatterns().map((p) => p.attackId);
    expect(notLive(ids)).toEqual([]);
  });

  it('Wazuh rules reference live techniques', () => {
    TestBed.configureTestingModule({});
    const ids = TestBed.inject(WazuhService).getAllRules().flatMap((r) => r.techniqueIds);
    expect(notLive(ids)).toEqual([]);
  });

  it('event-logging configs are keyed by live techniques', () => {
    expect(notLive(Object.keys(TECHNIQUE_TO_LOGGING))).toEqual([]);
  });

  it('the D3FEND seed references live techniques', () => {
    expect(notLive(D3FEND_MAPPING.flatMap((d) => d.attackIds))).toEqual([]);
  });

  it('the CVE->technique asset is keyed by live techniques', () => {
    expect(cveMapKeys.length).toBeGreaterThan(0);
    expect(notLive(cveMapKeys)).toEqual([]);
  });

  describe('with the release loaded', () => {
    beforeEach(() => {
      TestBed.configureTestingModule({});
      TestBed.inject(AttackIdResolverService).setSupersededBy(domain.supersededBy);
    });

    it('T1685.005 Clear Windows Event Logs gets its YARA rule and logging guidance', () => {
      expect(TestBed.inject(YaraService).getPattern('T1685.005')?.meta['description']).toBe('Detects Windows event log clearing');
      expect(TestBed.inject(EventLoggingService).getLoggingConfig('T1685.005').map((c) => c.eventId)).toEqual(['1102']);
    });

    it('T1685 Disable or Modify Tools counts Wazuh rule 61050', () => {
      expect(TestBed.inject(WazuhService).getRulesForTechnique('T1685').map((r) => r.ruleId)).toContain('61050');
    });

    it('a retired id from an older layer resolves to the same content', () => {
      expect(TestBed.inject(WazuhService).getRulesForTechnique('T1562.001').map((r) => r.ruleId)).toContain('61050');
      expect(TestBed.inject(EventLoggingService).getLoggingConfig('T1070.001').length).toBe(1);
    });
  });
});
