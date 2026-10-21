// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Data-health Retry (E1.3): every source with a loader can be retried from the
// data-health view. Each case starts the source through the Retry service (the
// "Load now" path for a source not requested yet), forces it offline, then presses
// Retry and checks that the loader really sent a new request and that the second
// failure is again recorded as 'failed', never as loaded.
import { TestBed, discardPeriodicTasks, fakeAsync, flush, flushMicrotasks, tick } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, TestRequest, provideHttpClientTesting } from '@angular/common/http/testing';
import { SourceRegistryService } from './source-registry.service';
import { SOURCE_DEFINITIONS } from './source-inventory';
import { NO_RETRY_REASON, SOURCE_RETRY, SourceRetryService, sourcesWithoutRetryDecision } from './source-retry.service';
import { AttackDomain, DataService } from './data.service';
import { CapecService } from './capec.service';

/** Answer every request (retries, fallbacks, timeouts included) with a network error; returns how many were sent. */
function forceOffline(http: HttpTestingController, answer?: (req: TestRequest) => boolean): number {
  let sent = 0;
  for (let round = 0; round < 40; round++) {
    flushMicrotasks();
    for (const req of http.match(() => true)) {
      if (req.cancelled) continue;
      sent++;
      if (answer?.(req)) continue;
      req.error(new ProgressEvent('error'), { status: 0, statusText: 'Unknown Error' });
    }
    flushMicrotasks();
    tick(70_000);
  }
  flush();
  discardPeriodicTasks();
  return sent;
}

const CSV_URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv';
/** Serves the CTID ATT&CK-to-CVE CSV, so the three services that wait on it make their own request. */
const ctidUp = (req: TestRequest): boolean => {
  if (req.request.url !== CSV_URL) return false;
  req.flush('CVE ID,Primary Impact,Secondary Impact,Exploitation Technique,Uncategorized,Phase\nCVE-2021-44228,T1190,,T1059,,\n');
  return true;
};
const NEEDS_CTID = new Set(['exploitdb', 'nuclei-tree', 'trickest-poc-tree']);

/**
 * The domain and data mode an ATT&CK source needs to be the one the matrix reads. The live
 * copies run in the default 'bundled' mode: since E1.4 (decision D2) their Load now / Retry
 * is the explicit update check, which works in either mode.
 */
const ATTACK_SETUP: Record<string, { domain: AttackDomain; mode: 'live' | 'bundled' }> = {
  'attack-enterprise': { domain: 'enterprise', mode: 'bundled' },
  'attack-ics': { domain: 'ics', mode: 'bundled' },
  'attack-mobile': { domain: 'mobile', mode: 'bundled' },
  'attack-live-enterprise': { domain: 'enterprise', mode: 'bundled' },
  'attack-live-ics': { domain: 'ics', mode: 'bundled' },
  'attack-live-mobile': { domain: 'mobile', mode: 'bundled' },
  'attack-live-f3': { domain: 'f3', mode: 'bundled' },
};

describe('SourceRetryService: Retry per source on the data-health view (E1.3)', () => {
  let http: HttpTestingController;
  let registry: SourceRegistryService;
  let retry: SourceRetryService;
  let fetchSpy: jasmine.Spy;

  beforeEach(() => {
    localStorage.removeItem('misp_config');
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
    registry = TestBed.inject(SourceRegistryService);
    retry = TestBed.inject(SourceRetryService);
    // ThreatHuntingService uses fetch() rather than HttpClient.
    fetchSpy = spyOn(window, 'fetch').and.callFake(() => Promise.reject(new TypeError('Failed to fetch (forced offline)')));
    spyOn(DataService.prototype as any, 'loadFromIDB').and.returnValue(Promise.resolve(null));
    spyOn(DataService.prototype as any, 'saveToIDB').and.returnValue(Promise.resolve());
  });

  it('gives every inventory source either a Retry or a stated reason why there is none', () => {
    expect(sourcesWithoutRetryDecision()).withContext('add an entry to SOURCE_RETRY or NO_RETRY_REASON').toEqual([]);
    const ids = new Set(SOURCE_DEFINITIONS.map(d => d.id));
    expect(Object.keys(SOURCE_RETRY).filter(id => !ids.has(id))).toEqual([]);
    expect(Object.keys(NO_RETRY_REASON).filter(id => !ids.has(id))).toEqual([]);
    expect(Object.keys(SOURCE_RETRY).filter(id => id in NO_RETRY_REASON)).toEqual([]);
  });

  it('can retry every live source', () => {
    const live = SOURCE_DEFINITIONS.filter(d => d.kind === 'live' && !d.initialStatus).map(d => d.id);
    expect(live.filter(id => !(id in SOURCE_RETRY))).toEqual([]);
    // 39 since the three rule-coverage sources became a bundled snapshot (no Retry: reload).
    expect(live.length).toBeGreaterThan(35);
  });

  Object.keys(SOURCE_RETRY).forEach(id => {
    it(`${id}: Load now and Retry each send a new request, and a failure stays 'failed'`, fakeAsync(() => {
      const setup = ATTACK_SETUP[id];
      if (setup) {
        const data = TestBed.inject(DataService);
        data.setDataSourceMode(setup.mode);
        data.setAttackDomain(setup.domain);
      }
      const answer = NEEDS_CTID.has(id) ? ctidUp : undefined;

      expect(retry.unavailableReason(id)).withContext('before the first attempt').toBeNull();
      expect(retry.retry(id)).withContext('Load now').toBeTrue();
      const firstFetches = fetchSpy.calls.count();
      const first = forceOffline(http, answer) + firstFetches;
      expect(first).withContext('the first attempt sent a request').toBeGreaterThan(0);
      expect(registry.get(id).status).withContext('after the first failure').toBe('failed');

      expect(retry.unavailableReason(id)).withContext('a failed source offers Retry').toBeNull();
      const fetchesBefore = fetchSpy.calls.count();
      expect(retry.retry(id)).withContext('Retry').toBeTrue();
      const again = forceOffline(http, answer) + (fetchSpy.calls.count() - fetchesBefore);
      expect(again).withContext('Retry sent a new request').toBeGreaterThan(0);

      const record = registry.get(id);
      expect(record.status).withContext('after Retry failed again').toBe('failed');
      expect(record.lastError).toBeTruthy();
      expect(record.lastLoadedAt).toBeNull();
    }));
  });

  it('offers no Retry and sends nothing for a source that holds data', fakeAsync(() => {
    TestBed.inject(CapecService);
    forceOffline(http);
    registry.succeed('capec', 12);
    expect(retry.unavailableReason('capec')).toBe('loaded; nothing to retry');
    expect(retry.retry('capec')).toBeFalse();
    http.expectNone(() => true);
  }));

  it('offers no Retry while a request is in flight', fakeAsync(() => {
    TestBed.inject(CapecService);
    expect(registry.get('capec').status).toBe('loading');
    expect(retry.unavailableReason('capec')).toBe('a request is in flight');
    expect(retry.retry('capec')).toBeFalse();
    forceOffline(http);
  }));

  it('does not reload another domain\'s ATT&CK bundle from data health (the matrix would change)', () => {
    const data = TestBed.inject(DataService);
    data.setAttackDomain('enterprise');
    expect(retry.unavailableReason('attack-ics')).toBe('loads when the matrix is switched to ICS');
    // D2: the live copy is fetched only by the update check, which data health may run in
    // any mode; it offers a newer release and never changes the matrix by itself.
    data.setDataSourceMode('bundled');
    expect(retry.unavailableReason('attack-live-enterprise')).toBeNull();
    expect(retry.unavailableReason('attack-live-ics')).toBe('loads when the matrix is switched to ICS');
    expect(retry.retry('attack-ics')).toBeFalse();
  });

  it('states why a source without a loader has no Retry', () => {
    expect(retry.unavailableReason('cis-controls')).toBe('withdrawn upstream; nothing to fetch');
    expect(retry.unavailableReason('wazuh-rules')).toBe('compiled into the app');
    expect(retry.retry('wazuh-rules')).toBeFalse();
  });

  it('retrying one CTID dataset leaves the other alone and lets the waiting services proceed', fakeAsync(() => {
    const svc = TestBed.inject(SourceRetryService);
    svc.retry('ctid-attack-to-cve');
    forceOffline(http);
    expect(registry.get('ctid-attack-to-cve').status).toBe('failed');
    expect(registry.get('ctid-kev').status).toBe('failed');

    svc.retry('ctid-attack-to-cve');
    expect(registry.get('ctid-kev').status).withContext('the KEV mapping is not re-requested').toBe('failed');
    forceOffline(http, ctidUp);
    expect(registry.get('ctid-attack-to-cve').status).toBe('archived-upstream');
    expect(registry.get('ctid-attack-to-cve').rows).toBe(1);
  }));
});
