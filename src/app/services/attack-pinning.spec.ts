// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// E1.4 (decision D2): ATT&CK is pinned to the bundled release. The version on screen never
// changes by itself; 'live' is an explicit "Check for ATT&CK update" that compares MITRE's
// current release with the pinned one and only offers it, for this session only. The data
// mode is a persisted user setting whose default, on a fresh profile, is 'bundled'.
//
// Each test drives the real DataService against HttpTestingController, so any request to
// MITRE's live STIX would be visible; in the walkthrough the old live mode swapped 19.2 for
// 20.0 two minutes into a session.
import { TestBed, discardPeriodicTasks, fakeAsync, flushMicrotasks, tick } from '@angular/core/testing';
import { HttpClient, provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { DataService, compareAttackVersions } from './data.service';
import { SettingsService } from './settings.service';
import { SourceRegistryService } from './source-registry.service';
import { BUNDLED_ATTACK_VERSION } from './source-inventory';
import { AttackIdResolverService } from './attack-id-resolver.service';

const SETTINGS_KEY = 'mitre-nav-settings-v1';
const BUNDLED = {
  enterprise: 'assets/data/enterprise-attack.json',
  ics: 'assets/data/ics-attack.json',
};
const LIVE_ENTERPRISE = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';
const isLive = (url: string) => url.includes('attack-stix-data/master') || url.includes('fight-fraud-framework');
const MINUTE = 60_000;

/** A minimal STIX bundle whose x-mitre-collection declares `version`. */
function bundle(version: string): object {
  return {
    objects: [
      { type: 'x-mitre-collection', x_mitre_version: version, modified: '2026-10-01' },
      {
        type: 'attack-pattern', id: 'attack-pattern--t1', name: 'Command and Scripting Interpreter',
        external_references: [{ source_name: 'mitre-attack', external_id: 'T1059', url: 'https://attack.mitre.org/techniques/T1059' }],
        kill_chain_phases: [{ phase_name: 'execution' }],
      },
    ],
  };
}

describe('ATT&CK pinning and "Check for ATT&CK update" (E1.4, decision D2)', () => {
  let http: HttpTestingController;
  let savedSettings: string | null;

  beforeEach(() => {
    // A fresh profile: no saved settings.
    savedSettings = localStorage.getItem(SETTINGS_KEY);
    localStorage.removeItem(SETTINGS_KEY);
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
    // Keep the tests off the real IndexedDB store.
    spyOn(DataService.prototype as any, 'loadFromIDB').and.returnValue(Promise.resolve(null));
    spyOn(DataService.prototype as any, 'saveToIDB').and.returnValue(Promise.resolve());
  });

  afterEach(() => {
    http.verify();
    if (savedSettings === null) localStorage.removeItem(SETTINGS_KEY);
    else localStorage.setItem(SETTINGS_KEY, savedSettings);
  });

  /** Versions of every non-null domain the service put on screen. */
  function watchVersions(svc: DataService): string[] {
    const seen: string[] = [];
    svc.domain$.subscribe(d => { if (d) seen.push(d.attackVersion); });
    return seen;
  }

  /** A brand-new session (page reload): fresh settings read from storage, fresh registry. */
  function newSession(): DataService {
    return new DataService(TestBed.inject(HttpClient), new AttackIdResolverService(), new SourceRegistryService(), new SettingsService());
  }

  it('defaults to the pinned bundle on a fresh profile and never contacts MITRE on load', fakeAsync(() => {
    const settings = TestBed.inject(SettingsService);
    const svc = TestBed.inject(DataService);
    expect(settings.current.attackDataMode).toBe('bundled');
    expect(svc.getDataSourceMode()).toBe('bundled');

    svc.loadDomain();
    http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));
    flushMicrotasks();

    expect(http.match(req => isLive(req.url)).length).toBe(0);
    expect(svc.getCurrentDomain()?.attackVersion).toBe('19.2');
    expect(svc.freshness$.value).toBe('bundled');
    expect(svc.update$.value.status).toBe('idle');
  }));

  it('a 30-minute session in the default mode shows no version change', fakeAsync(() => {
    const svc = TestBed.inject(DataService);
    const versions = watchVersions(svc);
    svc.loadDomain();
    http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));

    for (let minute = 1; minute <= 30; minute++) {
      tick(MINUTE);
      // Ordinary use: a domain round trip at minute 10 and a reload request at minute 20.
      if (minute === 10) {
        svc.switchDomain('ics');
        http.expectOne(BUNDLED.ics).flush(bundle('19.2'));
        svc.switchDomain('enterprise');
        http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));
      }
      if (minute === 20) {
        svc.loadDomain();
        http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));
      }
      expect(http.match(req => isLive(req.url)).length).withContext(`minute ${minute}: no live request`).toBe(0);
      expect(svc.getCurrentDomain()?.attackVersion).withContext(`minute ${minute}`).toBe('19.2');
    }

    expect(versions.length).toBe(4);
    expect(new Set(versions)).toEqual(new Set(['19.2']));
    expect(svc.freshness$.value).toBe('bundled');
    discardPeriodicTasks();
  }));

  it('a 30-minute session in the opt-in check-at-load mode offers 20.0 but stays on 19.2 until the user applies it', fakeAsync(() => {
    TestBed.inject(SettingsService).update({ attackDataMode: 'live' });
    const svc = TestBed.inject(DataService);
    expect(svc.getDataSourceMode()).toBe('live');
    const versions = watchVersions(svc);

    svc.loadDomain();
    http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));
    flushMicrotasks();
    http.expectOne(LIVE_ENTERPRISE).flush(bundle('20.0'));
    flushMicrotasks();

    expect(svc.update$.value).toEqual(jasmine.objectContaining({ status: 'available', pinnedVersion: '19.2', liveVersion: '20.0' }));
    for (let minute = 1; minute <= 30; minute++) {
      tick(MINUTE);
      expect(svc.getCurrentDomain()?.attackVersion).withContext(`minute ${minute}`).toBe('19.2');
    }
    expect(http.match(req => isLive(req.url)).length).withContext('one check per load, no polling').toBe(0);
    expect(versions).toEqual(['19.2']);
    expect(svc.freshness$.value).toBe('bundled');

    // Only the explicit choice changes the version, and only for this session.
    svc.applyUpdate();
    expect(svc.getCurrentDomain()?.attackVersion).toBe('20.0');
    expect(svc.freshness$.value).toBe('live');
    expect(svc.update$.value.status).toBe('applied');
    discardPeriodicTasks();
  }));

  it('persists the mode as a user setting, with bundled as the default for a fresh profile', fakeAsync(() => {
    expect(newSession().getDataSourceMode()).withContext('fresh profile').toBe('bundled');

    const settings = TestBed.inject(SettingsService);
    const svc = TestBed.inject(DataService);
    settings.update({ attackDataMode: 'live' });
    expect(svc.getDataSourceMode()).withContext('follows the setting').toBe('live');
    expect(new SettingsService().current.attackDataMode).withContext('survives a reload').toBe('live');
    expect(newSession().getDataSourceMode()).withContext('next session').toBe('live');

    settings.reset();
    expect(svc.getDataSourceMode()).withContext('reset to defaults').toBe('bundled');
    expect(newSession().getDataSourceMode()).toBe('bundled');
  }));

  it('"Check for ATT&CK update" offers a newer release, changes nothing until applied, and applies it for this session only', fakeAsync(() => {
    const svc = TestBed.inject(DataService);
    svc.loadDomain();
    http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));

    svc.checkForUpdate();
    expect(svc.update$.value.status).toBe('checking');
    http.expectOne(LIVE_ENTERPRISE).flush(bundle('20.0'));
    flushMicrotasks();
    expect(svc.update$.value).toEqual(jasmine.objectContaining({ status: 'available', pinnedVersion: '19.2', liveVersion: '20.0' }));
    expect(svc.getCurrentDomain()?.attackVersion).withContext('offered, not applied').toBe('19.2');

    // Declining keeps the pinned release; a later apply without an offer does nothing.
    svc.dismissUpdate();
    svc.applyUpdate();
    expect(svc.update$.value.status).toBe('idle');
    expect(svc.getCurrentDomain()?.attackVersion).toBe('19.2');

    svc.checkForUpdate();
    http.expectOne(LIVE_ENTERPRISE).flush(bundle('20.0'));
    flushMicrotasks();
    svc.applyUpdate();
    expect(svc.getCurrentDomain()?.attackVersion).toBe('20.0');

    // The choice holds for the rest of this session, across a domain round trip...
    svc.switchDomain('ics');
    http.expectOne(BUNDLED.ics).flush(bundle('19.2'));
    svc.switchDomain('enterprise');
    expect(svc.getCurrentDomain()?.attackVersion).toBe('20.0');
    expect(svc.update$.value.status).toBe('applied');

    // ...but is never persisted: a new session starts on the pinned bundle.
    const next = newSession();
    next.loadDomain();
    http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));
    expect(next.getCurrentDomain()?.attackVersion).toBe('19.2');

    // And the user can go back to the pinned release at any time.
    svc.revertToPinned();
    http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));
    expect(svc.getCurrentDomain()?.attackVersion).toBe('19.2');
    expect(svc.freshness$.value).toBe('bundled');
    expect(svc.update$.value.status).toBe('idle');
  }));

  it('reports the same or an older live release as up to date', fakeAsync(() => {
    const svc = TestBed.inject(DataService);
    svc.loadDomain();
    http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));

    svc.checkForUpdate();
    http.expectOne(LIVE_ENTERPRISE).flush(bundle('19.2'));
    flushMicrotasks();
    expect(svc.update$.value).toEqual(jasmine.objectContaining({ status: 'up-to-date', pinnedVersion: '19.2', liveVersion: '19.2' }));
    svc.applyUpdate();
    expect(svc.getCurrentDomain()?.attackVersion).toBe('19.2');
  }));

  it('a failed check is shown as failed, records the live source as failed and keeps the pinned release', fakeAsync(() => {
    const svc = TestBed.inject(DataService);
    const registry = TestBed.inject(SourceRegistryService);
    svc.loadDomain();
    http.expectOne(BUNDLED.enterprise).flush(bundle('19.2'));

    svc.checkForUpdate();
    // retryWithBackoff: the first attempt and three retries (1 s, 2 s, 4 s).
    for (let attempt = 0; attempt < 4; attempt++) {
      http.expectOne(LIVE_ENTERPRISE).error(new ProgressEvent('error'), { status: 0, statusText: 'Unknown Error' });
      tick(1000 * 2 ** attempt);
    }
    expect(svc.update$.value.status).toBe('failed');
    expect(svc.update$.value.error).toBeTruthy();
    expect(svc.update$.value.pinnedVersion).toBe('19.2');
    expect(registry.get('attack-live-enterprise').status).toBe('failed');
    expect(svc.getCurrentDomain()?.attackVersion).toBe('19.2');
  }));

  it('reads the pinned version from the bundle meta through the SourceRegistry', fakeAsync(() => {
    const svc = TestBed.inject(DataService);
    const registry = TestBed.inject(SourceRegistryService);
    expect(svc.pinnedVersion()).withContext('before the bundle loads: the inventory version').toBe(BUNDLED_ATTACK_VERSION);

    svc.loadDomain();
    http.expectOne(BUNDLED.enterprise).flush(bundle('18.1'));
    expect(registry.get('attack-enterprise').version).toBe('18.1');
    expect(svc.pinnedVersion()).withContext("the bundle's own x-mitre-collection version").toBe('18.1');

    svc.checkForUpdate();
    http.expectOne(LIVE_ENTERPRISE).flush(bundle('19.2'));
    flushMicrotasks();
    expect(svc.update$.value).toEqual(jasmine.objectContaining({ status: 'available', pinnedVersion: '18.1', liveVersion: '19.2' }));
  }));

  it('compares ATT&CK release numbers numerically and refuses unreadable ones', () => {
    expect(compareAttackVersions('20.0', '19.2')!).toBeGreaterThan(0);
    expect(compareAttackVersions('19.10', '19.2')!).toBeGreaterThan(0);
    expect(compareAttackVersions('19.2', '19.2')).toBe(0);
    expect(compareAttackVersions('19', '19.0')).toBe(0);
    expect(compareAttackVersions('18.1', '19.2')!).toBeLessThan(0);
    expect(compareAttackVersions('', '19.2')).toBeNull();
    expect(compareAttackVersions('master', '19.2')).toBeNull();
  });
});
