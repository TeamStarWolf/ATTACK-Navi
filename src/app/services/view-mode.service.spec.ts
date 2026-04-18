// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { ViewModeService, ViewMode } from './view-mode.service';

describe('ViewModeService', () => {
  let service: ViewModeService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(ViewModeService);
  });

  afterEach(() => localStorage.clear());

  it('defaults to workbench when nothing persisted', () => {
    expect(service.current).toBe('workbench');
  });

  it('reads persisted value from localStorage on init', () => {
    localStorage.setItem('attacknavi.viewMode', 'library');
    // Re-create to re-read storage
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({});
    const fresh = TestBed.inject(ViewModeService);
    expect(fresh.current).toBe('library');
  });

  it('rejects invalid persisted values', () => {
    localStorage.setItem('attacknavi.viewMode', 'garbage');
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({});
    const fresh = TestBed.inject(ViewModeService);
    expect(fresh.current).toBe('workbench');
  });

  it('set() updates current and persists', () => {
    service.set('library');
    expect(service.current).toBe('library');
    expect(localStorage.getItem('attacknavi.viewMode')).toBe('library');
  });

  it('set() is a no-op when value is unchanged', () => {
    let emissions = 0;
    service.viewMode$.subscribe(() => emissions++);
    expect(emissions).toBe(1);     // initial
    service.set('workbench');       // same as default
    expect(emissions).toBe(1);     // no new emission
  });

  it('toggle() flips between workbench and library', () => {
    expect(service.current).toBe('workbench');
    service.toggle();
    expect(service.current).toBe('library');
    service.toggle();
    expect(service.current).toBe('workbench');
  });

  it('viewMode$ emits the current value to new subscribers', (done) => {
    service.set('library');
    service.viewMode$.subscribe(m => {
      const expected: ViewMode = 'library';
      expect(m).toBe(expected);
      done();
    });
  });
});
