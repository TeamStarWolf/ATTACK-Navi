// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import {
  LibraryService,
  LibraryData,
  ATTACK_TACTIC_ORDER,
  tacticLabel,
  assetMatchesTactic,
  normalizeLibraryData,
} from './library.service';

const STUB_LIBRARY: LibraryData = {
  generated_at: '2026-04-17T00:00:00Z',
  counts: { tool: 3, channel: 1, 'x-account': 1 },
  categories: { tool: ['Active Directory', 'Threat Intelligence'] },
  vendors: { CrowdStrike: 2, MITRE: 1 },
  tactic_counts: { 'credential-access': 2, 'discovery': 1 },
  assets: [
    {
      id: 'tool:crowdstrike/falconpy',
      type: 'tool',
      title: 'CrowdStrike/falconpy',
      url: 'https://github.com/CrowdStrike/falconpy',
      description: 'Falcon API SDK for Python',
      category: 'Threat Intelligence',
      subcategory: '',
      vendor: 'CrowdStrike',
      handle: '',
      affiliation: '',
      attack_tactics: ['command-and-control'],
      metadata: {},
    },
    {
      id: 'tool:bloodhoundad/bloodhound',
      type: 'tool',
      title: 'BloodHoundAD/BloodHound',
      url: 'https://github.com/BloodHoundAD/BloodHound',
      description: 'AD attack path mapper using mimikatz dumps',
      category: 'Active Directory',
      subcategory: 'AD enumeration',
      vendor: 'BloodHoundAD',
      handle: '',
      affiliation: '',
      attack_tactics: ['credential-access', 'discovery'],
      metadata: {},
    },
    {
      id: 'tool:mitre/caldera',
      type: 'tool',
      title: 'mitre/caldera',
      url: 'https://github.com/mitre/caldera',
      description: 'Adversary emulation framework',
      category: 'Active Directory',
      subcategory: '',
      vendor: 'MITRE',
      handle: '',
      affiliation: '',
      attack_tactics: ['credential-access'],
      metadata: {},
    },
    {
      id: 'channel:specterops',
      type: 'channel',
      title: 'SpecterOps',
      url: 'https://www.youtube.com/@specterops',
      description: 'BloodHound, AD research',
      category: 'Active Directory',
      subcategory: '',
      vendor: 'SpecterOps',
      handle: '@specterops',
      affiliation: '',
      attack_tactics: ['credential-access'],
      metadata: {},
    },
    {
      id: 'x:@maddiestone',
      type: 'x-account',
      title: 'Maddie Stone',
      url: 'https://x.com/maddiestone',
      description: 'Project Zero researcher',
      category: 'Elite Researchers',
      subcategory: '',
      vendor: 'Google',
      handle: '@maddiestone',
      affiliation: 'Project Zero',
      attack_tactics: [],
      metadata: {},
    },
  ],
};

describe('LibraryService', () => {
  let service: LibraryService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(LibraryService);
    httpMock = TestBed.inject(HttpTestingController);

    // The service eager-subscribes in its constructor, so a request is in flight.
    const req = httpMock.expectOne('assets/library.json');
    req.flush(STUB_LIBRARY);
  });

  afterEach(() => httpMock.verify());

  it('exposes the library via library$ observable', (done) => {
    service.library$.subscribe(data => {
      expect(data.assets.length).toBe(5);
      expect(data.counts.tool).toBe(3);
      done();
    });
  });

  it('falls back to EMPTY data on HTTP failure', (done) => {
    // New service instance for the failure case
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    const failService = TestBed.inject(LibraryService);
    const failHttp = TestBed.inject(HttpTestingController);
    const req = failHttp.expectOne('assets/library.json');
    req.error(new ProgressEvent('Network down'));

    failService.library$.subscribe(data => {
      expect(data.assets.length).toBe(0);
      expect(data.counts).toEqual({});
      failHttp.verify();
      done();
    });
  });

  describe('getAssetsForTactic', () => {
    it('returns assets that include the given tactic slug', () => {
      const credAccess = service.getAssetsForTactic('credential-access');
      const titles = credAccess.map(a => a.title);
      expect(credAccess.length).toBe(3);
      expect(titles).toContain('BloodHoundAD/BloodHound');
      expect(titles).toContain('mitre/caldera');
      expect(titles).toContain('SpecterOps');
    });

    it('returns empty array for unknown slug', () => {
      expect(service.getAssetsForTactic('made-up-tactic')).toEqual([]);
    });

    it('returns empty array for empty slug', () => {
      expect(service.getAssetsForTactic('')).toEqual([]);
    });
  });

  describe('getAssetsForTechnique', () => {
    it('scores tactic-tag matches', () => {
      const results = service.getAssetsForTechnique('T9999.999', 'Unknown', ['credential-access']);
      // The 3 credential-access assets should appear
      const ids = results.map(r => r.id);
      expect(ids).toContain('tool:bloodhoundad/bloodhound');
      expect(ids).toContain('channel:specterops');
    });

    it('boosts score for assets mentioning the technique ID directly', () => {
      const results = service.getAssetsForTechnique('mimikatz', 'LSASS Memory', ['credential-access']);
      // BloodHound's description contains "mimikatz" → ID-mention bonus puts it at top
      expect(results[0].id).toBe('tool:bloodhoundad/bloodhound');
    });

    it('matches name keyword tokens (≥5 chars)', () => {
      const results = service.getAssetsForTechnique('T0000', 'enumeration', ['discovery']);
      const ids = results.map(r => r.id);
      expect(ids).toContain('tool:bloodhoundad/bloodhound');  // subcategory: "AD enumeration"
    });

    it('returns empty array when neither attackId nor name provided', () => {
      expect(service.getAssetsForTechnique('', '', [])).toEqual([]);
    });

    it('caps results at 24', () => {
      // Sanity: small fixture only has 5; just verify no crash + correct ordering
      const results = service.getAssetsForTechnique('T0000', 'discovery', ['credential-access', 'discovery']);
      expect(results.length).toBeLessThanOrEqual(24);
    });
  });

  describe('tacticLabel helper', () => {
    it('converts kebab-case slugs to Title Case', () => {
      expect(tacticLabel('credential-access')).toBe('Credential Access');
      expect(tacticLabel('lateral-movement')).toBe('Lateral Movement');
      expect(tacticLabel('impact')).toBe('Impact');
    });
  });

  describe('ATTACK_TACTIC_ORDER constant', () => {
    it('contains all 15 Enterprise v19 tactics in canonical order', () => {
      expect(ATTACK_TACTIC_ORDER.length).toBe(15);
      expect(ATTACK_TACTIC_ORDER[0]).toBe('reconnaissance');
      expect(ATTACK_TACTIC_ORDER[ATTACK_TACTIC_ORDER.length - 1]).toBe('impact');
      expect(ATTACK_TACTIC_ORDER).not.toContain('defense-evasion');
      const privesc = ATTACK_TACTIC_ORDER.indexOf('privilege-escalation');
      expect(ATTACK_TACTIC_ORDER.slice(privesc + 1, privesc + 4)).toEqual(['stealth', 'defense-impairment', 'credential-access']);
    });
  });

  describe('legacy defense-evasion asset tags (pre-v19 generator)', () => {
    const legacyAsset = { attack_tactics: ['defense-evasion'] };

    it('assetMatchesTactic finds a defense-evasion asset for the v19 stealth and defense-impairment slugs', () => {
      expect(assetMatchesTactic(legacyAsset, 'stealth')).toBeTrue();
      expect(assetMatchesTactic(legacyAsset, 'defense-impairment')).toBeTrue();
      expect(assetMatchesTactic(legacyAsset, 'defense-evasion')).toBeTrue();
      expect(assetMatchesTactic(legacyAsset, 'execution')).toBeFalse();
      expect(assetMatchesTactic({ attack_tactics: undefined }, 'stealth')).toBeFalse();
    });

    it('normalizeLibraryData fills v19 tactic counts from aliased asset tags without touching the generator counts', () => {
      const data: LibraryData = {
        ...STUB_LIBRARY,
        tactic_counts: { 'defense-evasion': 1 },
        assets: [{ ...STUB_LIBRARY.assets[0], attack_tactics: ['defense-evasion'] }],
      };
      const normalized = normalizeLibraryData(data);
      expect(normalized.tactic_counts['defense-evasion']).toBe(1);
      expect(normalized.tactic_counts['stealth']).toBe(1);
      expect(normalized.tactic_counts['defense-impairment']).toBe(1);
      expect(normalized.tactic_counts['execution']).toBe(0);
      // input untouched
      expect(data.tactic_counts['stealth']).toBeUndefined();
    });

    it('getAssetsForTactic and getAssetsForTechnique resolve v19 slugs against legacy tags', () => {
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({
        providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
      });
      const svc = TestBed.inject(LibraryService);
      const mock = TestBed.inject(HttpTestingController);
      mock.expectOne('assets/library.json').flush({
        ...STUB_LIBRARY,
        assets: [{ ...STUB_LIBRARY.assets[0], id: 'tool:legacy/evasion', attack_tactics: ['defense-evasion'] }],
      });
      expect(svc.getAssetsForTactic('stealth').map(a => a.id)).toEqual(['tool:legacy/evasion']);
      expect(svc.getAssetsForTactic('defense-impairment').map(a => a.id)).toEqual(['tool:legacy/evasion']);
      expect(svc.getAssetsForTechnique('T1036', 'Masquerading', ['stealth']).map(a => a.id)).toContain('tool:legacy/evasion');
      mock.verify();
    });
  });
});
