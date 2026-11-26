// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { LiveDefenseService } from './live-defense.service';

const LAYER_URL = 'assets/data/live-defense/live-defense.layer.json';
const EVIDENCE_URL = 'assets/data/live-defense/live-defense.evidence.json';

const LAYER = {
  __meta: { snapshotDate: '2026-10-16' },
  techniques: [
    { techniqueID: 'T1190', score: 100 },
    { techniqueID: 'T1059', score: 36 },
    { techniqueID: 'T1078', score: 0 }, // below the bar: must not be scored
  ],
};
const EVIDENCE = {
  __meta: { snapshotDate: '2026-10-16' },
  techniques: {
    T1190: {
      techniqueID: 'T1190', name: 'Exploit Public-Facing Application', rank: 1, score: 100, heat: 168.5,
      confidence: 'high', itemCount: 1215, ransomwareCount: 249,
      breakdown: { halfLifeDays: 180, ransomwareBonus: 0.5, asOf: '2026-10-16', itemsShown: 1 },
      brief: 'sourced brief', items: [{
        cve: 'CVE-2026-59310', source: 'CISA KEV', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-59310',
        dateAdded: '2026-08-18', knownRansomware: true, confidence: 'high', quote: 'vuln name',
        cwes: ['CWE-22'], via: 'CWE-22', weight: 1.2,
      }],
    },
  },
};

describe('LiveDefenseService', () => {
  let service: LiveDefenseService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(LiveDefenseService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  function flush(layer: unknown = LAYER, evidence: unknown = EVIDENCE): void {
    http.expectOne(LAYER_URL).flush(layer);
    http.expectOne(EVIDENCE_URL).flush(evidence);
  }

  it('requests both artifacts on construction', () => {
    http.expectOne(LAYER_URL).flush(LAYER);
    http.expectOne(EVIDENCE_URL).flush(EVIDENCE);
  });

  it('scores only techniques above the bar (score > 0)', () => {
    flush();
    expect(service.getScore('T1190')).toBe(100);
    expect(service.getScore('T1059')).toBe(36);
    expect(service.getScore('T1078')).toBe(0); // zero-score row dropped
    expect(service.getScore('T9999')).toBe(0); // absent
  });

  it('exposes the snapshot date as the updated stamp and maxScore', () => {
    flush();
    expect(service.asOf).toBe('2026-10-16');
    expect(service.maxScore).toBe(100);
  });

  it('returns the sourced evidence for a heated technique, null otherwise', () => {
    flush();
    expect(service.getEvidence('T1190')?.itemCount).toBe(1215);
    expect(service.getEvidence('T1190')?.items[0].cve).toBe('CVE-2026-59310');
    expect(service.getEvidence('T1078')).toBeNull();
  });

  it('fails quiet when an artifact does not load (empty scores, null stamp)', () => {
    http.expectOne(LAYER_URL).flush(LAYER);
    http.expectOne(EVIDENCE_URL).error(new ProgressEvent('error'));
    expect(service.getScore('T1190')).toBe(0);
    expect(service.asOf).toBeNull();
    expect(service.getEvidence('T1190')).toBeNull();
  });

  it('publishes scores on scores$', (done) => {
    flush();
    service.scores$.subscribe(scores => {
      expect(scores.get('T1190')).toBe(100);
      expect(scores.has('T1078')).toBe(false);
      done();
    });
  });
});
