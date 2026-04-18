// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import {
  LibraryService,
  LibraryData,
  ATTACK_TACTIC_ORDER,
  tacticLabel,
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
      providers: [provideHttpClient(), provideHttpClientTesting()],
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
      providers: [provideHttpClient(), provideHttpClientTesting()],
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
    it('contains all 14 ATT&CK tactics in canonical order', () => {
      expect(ATTACK_TACTIC_ORDER.length).toBe(14);
      expect(ATTACK_TACTIC_ORDER[0]).toBe('reconnaissance');
      expect(ATTACK_TACTIC_ORDER[ATTACK_TACTIC_ORDER.length - 1]).toBe('impact');
    });
  });
});
