// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { F3FraudService } from './f3-fraud.service';

const BUNDLE = {
  objects: [
    {
      type: 'attack-pattern',
      name: 'Adversary-in-the-Middle',
      external_references: [{ source_name: 'mitre-f3', external_id: 'T1557', url: 'https://ctid.mitre.org/fraud/techniques/T1557' }],
    },
    {
      type: 'attack-pattern',
      name: 'Account Takeover',
      external_references: [{ source_name: 'mitre-f3', external_id: 'F1001', url: 'https://ctid.mitre.org/fraud/techniques/F1001' }],
    },
    {
      type: 'attack-pattern',
      name: 'Deprecated technique',
      x_mitre_deprecated: true,
      external_references: [{ source_name: 'mitre-f3', external_id: 'T9999', url: '' }],
    },
    { type: 'identity', name: 'not a technique' },
  ],
};

describe('F3FraudService', () => {
  let service: F3FraudService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ imports: [HttpClientTestingModule] });
    service = TestBed.inject(F3FraudService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('indexes only the T-prefixed (ATT&CK-shared) techniques, skipping F-ids and deprecated', () => {
    service.ensureLoaded();
    httpMock.expectOne('assets/data/f3-attack.json').flush(BUNDLE);

    expect(service.loaded).toBe(true);
    expect(service.overlapCount).toBe(1);
    expect(service.hasOverlap('T1557')).toBe(true);
    expect(service.getOverlap('T1557')?.name).toBe('Adversary-in-the-Middle');
    expect(service.hasOverlap('F1001')).toBe(false);
    expect(service.hasOverlap('T9999')).toBe(false); // deprecated, skipped
  });

  it('falls a sub-technique back to its parent overlap', () => {
    service.ensureLoaded();
    httpMock.expectOne('assets/data/f3-attack.json').flush(BUNDLE);

    expect(service.getOverlap('T1557.002')?.id).toBe('T1557');
    expect(service.getOverlap('T1190')).toBeNull();
  });

  it('only fetches once', () => {
    service.ensureLoaded();
    service.ensureLoaded();
    const inFlight = httpMock.match('assets/data/f3-attack.json');
    expect(inFlight.length).toBe(1);
    inFlight[0].flush(BUNDLE);

    // Nor does a call after the bundle has landed re-request it.
    service.ensureLoaded();
    expect(httpMock.match('assets/data/f3-attack.json').length).toBe(0);
    expect(service.loaded).toBe(true);
    expect(service.overlapCount).toBe(1);
  });

  it('never throws on a failed load — overlap set is just empty', () => {
    service.ensureLoaded();
    httpMock.expectOne('assets/data/f3-attack.json').flush('boom', { status: 500, statusText: 'Server Error' });

    expect(service.loaded).toBe(true);
    expect(service.overlapCount).toBe(0);
    expect(service.hasOverlap('T1557')).toBe(false);
  });
});
