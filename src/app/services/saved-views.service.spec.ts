// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { SavedViewsService } from './saved-views.service';

const STORAGE_KEY = 'mitre-nav-views-v1';

describe('SavedViewsService', () => {
  let service: SavedViewsService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(SavedViewsService);
  });

  afterEach(() => localStorage.clear());

  it('starts empty when localStorage is fresh', (done) => {
    service.views$.subscribe(views => {
      expect(views).toEqual([]);
      done();
    });
  });

  it('saveCurrentView creates and persists a view', () => {
    const v = service.saveCurrentView('Test View', 'desc');
    expect(v.id).toBeTruthy();
    expect(v.name).toBe('Test View');
    expect(v.description).toBe('desc');
    // urlHash captures whatever window.location.hash currently is — may be empty
    expect(typeof v.urlHash).toBe('string');

    const raw = localStorage.getItem(STORAGE_KEY);
    expect(raw).toBeTruthy();
    const stored = JSON.parse(raw!);
    expect(stored.length).toBe(1);
    expect(stored[0].name).toBe('Test View');
  });

  it('deleteView removes by id', () => {
    const v = service.saveCurrentView('Doomed', '');
    service.deleteView(v.id);
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]');
    expect(stored.length).toBe(0);
  });

  it('persisted views survive a service re-instantiation', (done) => {
    service.saveCurrentView('Persistent', '');
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({});
    const fresh = TestBed.inject(SavedViewsService);
    fresh.views$.subscribe(views => {
      expect(views.length).toBe(1);
      expect(views[0].name).toBe('Persistent');
      done();
    });
  });
});
