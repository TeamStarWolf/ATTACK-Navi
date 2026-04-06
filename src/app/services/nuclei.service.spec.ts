// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';
import { NucleiService } from './nuclei.service';
import { AttackCveService } from './attack-cve.service';

describe('NucleiService', () => {
  let service: NucleiService;
  let httpMock: HttpTestingController;
  let mockAttackCveLoaded$: BehaviorSubject<boolean>;

  const TREE_URL =
    'https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1';

  const mockMappings: Record<string, any> = {
    'CVE-2021-44228': {
      primaryImpact: ['T1059'],
      secondaryImpact: ['T1190'],
      exploitationTechnique: [],
    },
    'CVE-2022-1234': {
      primaryImpact: ['T1059.001'],
      secondaryImpact: [],
      exploitationTechnique: ['T1203'],
    },
  };

  beforeEach(() => {
    mockAttackCveLoaded$ = new BehaviorSubject<boolean>(false);

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        {
          provide: AttackCveService,
          useValue: {
            loaded$: mockAttackCveLoaded$.asObservable(),
            getMappingForCve: (cveId: string) => mockMappings[cveId] ?? null,
          },
        },
      ],
    });

    service = TestBed.inject(NucleiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  function makeTreeEntry(path: string, type: 'blob' | 'tree' = 'blob'): any {
    return { path, mode: '100644', type, sha: 'abc123', size: 100, url: 'https://example.com' };
  }

  function triggerLoad(treeEntries: any[]): void {
    mockAttackCveLoaded$.next(true);
    const req = httpMock.expectOne(TREE_URL);
    req.flush({ sha: 'def456', url: TREE_URL, tree: treeEntries, truncated: false });
  }

  function triggerLoadError(): void {
    mockAttackCveLoaded$.next(true);
    const req = httpMock.expectOne(TREE_URL);
    req.error(new ProgressEvent('error'));
  }

  // --- getTemplateCount() ---

  it('should return 0 before load', () => {
    expect(service.getTemplateCount('T1059')).toBe(0);
  });

  it('should count templates mapped via CVE cross-reference', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
    ]);

    expect(service.getTemplateCount('T1059')).toBe(1);
    expect(service.getTemplateCount('T1190')).toBe(1);
  });

  it('should return 0 for techniques not in any mapping', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
    ]);

    expect(service.getTemplateCount('T9999')).toBe(0);
  });

  // --- hasTemplates() ---

  it('should return true when templates exist for a technique', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
    ]);

    expect(service.hasTemplates('T1059')).toBeTrue();
  });

  it('should return false when no templates exist for a technique', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
    ]);

    expect(service.hasTemplates('T9999')).toBeFalse();
  });

  // --- loaded$ / total$ / covered$ ---

  it('should emit loaded$ as true after tree is processed', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
    ]);

    let loaded = false;
    service.loaded$.subscribe(val => { loaded = val; });
    expect(loaded).toBeTrue();
  });

  it('should emit total$ with the count of mapped CVE templates', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
      makeTreeEntry('http/cves/2022/CVE-2022-1234.yaml'),
    ]);

    let total = 0;
    service.total$.subscribe(val => { total = val; });
    expect(total).toBe(2);
  });

  it('should emit covered$ with the count of unique techniques', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
      makeTreeEntry('http/cves/2022/CVE-2022-1234.yaml'),
    ]);

    let covered = 0;
    service.covered$.subscribe(val => { covered = val; });
    // T1059 + T1190 from first CVE; T1059.001 + T1203 from second = 4
    expect(covered).toBe(4);
  });

  // --- Parent technique rollup ---

  it('should roll up subtechnique counts to parent techniques', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2022/CVE-2022-1234.yaml'),
    ]);

    // CVE-2022-1234 maps to T1059.001 -> parent T1059 should roll up
    expect(service.getTemplateCount('T1059.001')).toBe(1);
    expect(service.getTemplateCount('T1059')).toBe(1);
  });

  // --- Tree filtering ---

  it('should skip tree entries (directories)', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021', 'tree'),
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
    ]);

    let total = 0;
    service.total$.subscribe(val => { total = val; });
    expect(total).toBe(1);
  });

  it('should skip non-yaml files', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021/CVE-2021-44228.txt'),
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
    ]);

    let total = 0;
    service.total$.subscribe(val => { total = val; });
    expect(total).toBe(1);
  });

  it('should deduplicate CVE IDs across different paths', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2021/CVE-2021-44228.yaml'),
      makeTreeEntry('network/cves/2021/CVE-2021-44228.yaml'),
    ]);

    let total = 0;
    service.total$.subscribe(val => { total = val; });
    // Same CVE, only counted once
    expect(total).toBe(1);
  });

  it('should handle yml extension', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2022/CVE-2022-1234.yml'),
    ]);

    expect(service.getTemplateCount('T1059.001')).toBe(1);
  });

  // --- Error handling ---

  it('should handle HTTP error gracefully and set loaded$', () => {
    triggerLoadError();

    let loaded = false;
    service.loaded$.subscribe(val => { loaded = val; });
    expect(loaded).toBeTrue();
    expect(service.getTemplateCount('T1059')).toBe(0);
  });

  it('should handle empty tree', () => {
    triggerLoad([]);

    let total = 0;
    service.total$.subscribe(val => { total = val; });
    expect(total).toBe(0);
  });

  it('should skip CVEs not in AttackCveService', () => {
    triggerLoad([
      makeTreeEntry('http/cves/2023/CVE-2023-9999.yaml'),
    ]);

    let total = 0;
    service.total$.subscribe(val => { total = val; });
    // CVE-2023-9999 has no mapping, so total should be 0
    expect(total).toBe(0);
  });
});
