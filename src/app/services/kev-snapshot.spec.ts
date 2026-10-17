// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The bundled KEV snapshot (plan 6.3 / E1.3): src/assets/data/kev-snapshot.json is the
// dated stand-in for the live CISA KEV feed. These specs read the real shipped file and
// check that it is what the source registry says it is, and that the app, with the
// live feed down, decides journey 1's CVE from it with the date shown.
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { CveService } from './cve.service';
import { DEFAULT_ENVIRONMENT, SsvcService } from './ssvc.service';
import { SourceRegistryService } from './source-registry.service';
import { BUNDLED_KEV_SNAPSHOT, SOURCE_DEFINITIONS } from './source-inventory';
import { NvdCveItem } from '../models/cve';

const KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
const KEV_FALLBACK_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const SNAPSHOT_URL = 'assets/data/kev-snapshot.json';

describe('bundled KEV snapshot (E1.3)', () => {
  let snapshot: any;

  beforeAll(async () => {
    const response = await fetch(SNAPSHOT_URL);
    if (!response.ok) throw new Error(`${SNAPSHOT_URL}: HTTP ${response.status}`);
    snapshot = await response.json();
  });

  it('is the snapshot the source registry names: same date, catalogue version and commit', () => {
    expect(snapshot.__meta.snapshotDate).toBe(BUNDLED_KEV_SNAPSHOT.date);
    expect(snapshot.__meta.catalogVersion).toBe(BUNDLED_KEV_SNAPSHOT.catalogVersion);
    expect(snapshot.__meta.commit).toBe(BUNDLED_KEV_SNAPSHOT.commit);
    const def = SOURCE_DEFINITIONS.find(d => d.id === 'cisa-kev-snapshot')!;
    expect(def.kind).toBe('bundled');
    expect(def.fallbackFor).toBe('cisa-kev');
    expect(def.licence).toBe('kev-cc0');
    expect(def.version).toContain(`snapshot of ${BUNDLED_KEV_SNAPSHOT.date}`);
  });

  it('is a real catalogue: counted, unique CVE ids, nothing added after its date', () => {
    const vulns: Array<{ cveID: string; dateAdded: string }> = snapshot.vulnerabilities;
    expect(vulns.length).toBe(snapshot.__meta.count);
    expect(vulns.length).toBeGreaterThan(1000);
    expect(new Set(vulns.map(v => v.cveID)).size).toBe(vulns.length);
    expect(vulns.filter(v => v.dateAdded > snapshot.__meta.snapshotDate)).toEqual([]);
  });

  it('holds journey 1\'s CVE (CVE-2024-3400) with its date added', () => {
    const entry = snapshot.vulnerabilities.find((v: any) => v.cveID === 'CVE-2024-3400');
    expect(entry?.dateAdded).toBe('2024-04-12');
    expect(entry?.knownRansomwareCampaignUse).toBe('Known');
  });

  it('with the live feed down, the app decides CVE-2024-3400 from the snapshot and names its date', () => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    const http = TestBed.inject(HttpTestingController);
    const cves = TestBed.inject(CveService);
    const ssvc = TestBed.inject(SsvcService);
    const registry = TestBed.inject(SourceRegistryService);
    http.match('assets/data/ssvc-decision-tables.json').forEach(r => r.flush({
      tables: {
        'cisa-coordinator': {
          id: 'cisa-coordinator', label: 'coordinator', describes: '', url: 'u', outcomeColumn: 'o', outcomes: ['act'],
          columns: ['Exploitation', 'Automatable', 'Technical Impact', 'Mission and Well-Being Impact'],
          rows: [{ key: ['active', 'yes', 'total', 'medium'], outcome: 'act' }],
        },
      },
    }));
    http.match(() => true).filter(r => r.request.url.includes('cwe-exploitation-anchor')).forEach(r => r.flush({}));

    cves.loadKev();
    http.expectOne(KEV_URL).error(new ProgressEvent('error'));
    http.expectOne(KEV_FALLBACK_URL).error(new ProgressEvent('error'));
    http.expectOne(SNAPSHOT_URL).flush(snapshot);

    expect(registry.get('cisa-kev').status).toBe('failed');
    expect(registry.get('cisa-kev-snapshot').status).toBe('loaded');
    expect(cves.kevSnapshotDate).toBe(BUNDLED_KEV_SNAPSHOT.date);

    const entry = cves.getKevEntry('CVE-2024-3400')!;
    const record: NvdCveItem = {
      id: 'CVE-2024-3400', description: '', cvssScore: 10, severity: 'CRITICAL',
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', cwes: [], cpes: [], published: '', lastModified: '',
      references: [], mappedAttackIds: [], isKev: true, kevDateAdded: entry.dateAdded, kevKnownRansomware: true,
    };
    const result = ssvc.evaluate(record, DEFAULT_ENVIRONMENT, {}, cves.kevContext);
    expect(result.action).toBe('act');
    expect(result.points.find(p => p.label === 'Exploitation')!.basis)
      .toContain(`bundled CISA KEV snapshot of ${BUNDLED_KEV_SNAPSHOT.date}`);
  });
});
