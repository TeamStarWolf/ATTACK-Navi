// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { EngageService } from './engage.service';

/**
 * A small slice of the five MITRE Engage JSON files the service joins:
 *   activities -> (approach_activity) -> approach -> (goal_approach) -> goal
 *   attack_mapping: ATT&CK technique -> activity
 */
const ACTIVITIES = [
  { id: 'EAC0002', name: 'Network Monitoring', description: 'Monitor network traffic.' },
  { id: 'EAC0005', name: 'Lures', description: 'Deploy lures.' },
  { id: 'EAC0011', name: 'Decoy Credentials', description: 'Seed fake credentials.' },
  { name: 'row without an id is skipped' },
];
const ATTACK_MAPPING = [
  { attack_id: 'T1566', eac_id: 'EAC0005' },
  { attack_id: 'T1566', eac_id: 'EAC0005' },    // duplicate row -> not double-counted
  { attack_id: 'T1566', eac_id: 'EAC9999' },    // unknown activity -> skipped
  { attack_id: 'T1566.001', eac_id: 'EAC0011' },
  { attack_id: 'T1190', eac_id: 'EAC0002' },
];
const GOAL_APPROACH = [{ goal_id: 'EGO0003', approach_id: 'EAP0010' }];
const APPROACH_ACTIVITY = [{ approach_id: 'EAP0010', activity_id: 'EAC0005' }];
const GOALS = [{ id: 'EGO0003', name: 'Affect' }];

describe('EngageService', () => {
  let service: EngageService;
  let httpMock: HttpTestingController;

  const flush = (file: string, body: object[]) =>
    httpMock.expectOne(r => r.url.endsWith(`/${file}`)).flush(body);

  /** Answer all five requests the constructor issued. */
  function flushAll(): void {
    flush('activities.json', ACTIVITIES);
    flush('attack_mapping.json', ATTACK_MAPPING);
    flush('goal_approach_mappings.json', GOAL_APPROACH);
    flush('approach_activity_mappings.json', APPROACH_ACTIVITY);
    flush('goals.json', GOALS);
  }

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(EngageService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('requests the five official Engage data files on construction', () => {
    const reqs = httpMock.match(r => r.url.includes('/mitre/engage/'));
    expect(reqs.map(r => r.request.url.split('/').pop()).sort()).toEqual([
      'activities.json',
      'approach_activity_mappings.json',
      'attack_mapping.json',
      'goal_approach_mappings.json',
      'goals.json',
    ]);
    reqs.forEach(r => r.flush([]));
  });

  it('has no activities and is not loaded until every file has arrived', () => {
    let loaded: boolean | undefined;
    service.loaded$.subscribe(v => (loaded = v));

    expect(loaded).toBeFalse();
    expect(service.getActivities('T1566')).toEqual([]);

    flushAll();
    expect(loaded).toBeTrue();
  });

  describe('getActivities (after load)', () => {
    beforeEach(() => flushAll());

    it('returns the activities mapped to the queried technique, de-duplicated', () => {
      const acts = service.getActivities('T1566');
      expect(acts.map(a => a.id)).toEqual(['EAC0005']);
      expect(acts[0].name).toBe('Lures');
      expect(acts.every(a => a.attackIds.includes('T1566'))).toBeTrue();
    });

    it('resolves an activity category through approach -> goal', () => {
      expect(service.getActivities('T1566')[0].category).toBe('Affect');
      // EAC0002 has no approach row, so it falls back to the default category.
      expect(service.getActivities('T1190')[0].category).toBe('Expose');
    });

    it('merges a sub-technique with its parent without duplicates', () => {
      const ids = service.getActivities('T1566.001').map(a => a.id);
      expect(ids).toEqual(['EAC0011', 'EAC0005']);
    });

    it('returns empty for a technique with no mapping', () => {
      expect(service.getActivities('T9999')).toEqual([]);
    });

    it('does not credit an activity to a technique it is not mapped to', () => {
      expect(service.getActivities('T1190').map(a => a.id)).toEqual(['EAC0002']);
      expect(service.getActivities('T1190').some(a => a.id === 'EAC0005')).toBeFalse();
    });
  });

  it('tolerates a file that fails to load and still indexes the rest', () => {
    httpMock.expectOne(r => r.url.endsWith('/activities.json')).flush(ACTIVITIES);
    httpMock.expectOne(r => r.url.endsWith('/attack_mapping.json')).flush(ATTACK_MAPPING);
    httpMock
      .expectOne(r => r.url.endsWith('/goal_approach_mappings.json'))
      .flush('boom', { status: 500, statusText: 'Server Error' });
    httpMock.expectOne(r => r.url.endsWith('/approach_activity_mappings.json')).flush(APPROACH_ACTIVITY);
    httpMock.expectOne(r => r.url.endsWith('/goals.json')).flush(GOALS);

    const acts = service.getActivities('T1566');
    expect(acts.map(a => a.id)).toEqual(['EAC0005']);
    // The goal chain is broken, so the category falls back to the default.
    expect(acts[0].category).toBe('Expose');
  });
});
