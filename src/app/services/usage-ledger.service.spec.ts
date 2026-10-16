// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { UsageLedgerService } from './usage-ledger.service';

describe('UsageLedgerService', () => {
  let service: UsageLedgerService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(UsageLedgerService);
  });

  afterEach(() => localStorage.clear());

  it('is off by default and records nothing while off', () => {
    expect(service.enabled).toBe(false);
    service.record('route', '/matrix');
    expect(service.contents()).toBeNull();
    expect(localStorage.length).toBe(0);
  });

  it('counts by kind and name once enabled, and shows exactly what it holds', () => {
    service.enable();
    service.record('route', '/matrix');
    service.record('route', '/matrix');
    service.record('lens', 'kev');
    expect(service.contents()).toEqual({ route: { '/matrix': 2 }, lens: { kev: 1 }, journey: {} });
  });

  it('keeps an inherited property name as an ordinary own count', () => {
    service.enable();
    service.record('lens', '__proto__');
    service.record('lens', 'toString');
    const lens = service.contents()!.lens;
    expect(Object.keys(lens).sort()).toEqual(['__proto__', 'toString']);
    expect(lens['toString']).toBe(1);
  });

  it('deletes everything when turned off', () => {
    service.enable();
    service.record('journey', 'triage');
    service.disable();
    expect(service.enabled).toBe(false);
    expect(service.contents()).toBeNull();
  });

  it('never transmits: recording makes no network call', () => {
    const fetchSpy = spyOn(window, 'fetch');
    const xhrSpy = spyOn(XMLHttpRequest.prototype, 'send');
    const beaconSpy = spyOn(navigator, 'sendBeacon');
    service.enable();
    service.record('route', '/exposure/cve');
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(xhrSpy).not.toHaveBeenCalled();
    expect(beaconSpy).not.toHaveBeenCalled();
  });

  it('stays silent when storage is blocked', () => {
    spyOn(Storage.prototype, 'getItem').and.throwError('blocked');
    expect(service.contents()).toBeNull();
    expect(() => service.record('lens', 'kev')).not.toThrow();
  });
});
