// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { WatchlistService } from './watchlist.service';
import { Technique } from '../models/technique';

const STUB_TECH = {
  id: 'attack-pattern--abc',
  attackId: 'T1059',
  name: 'Command and Scripting Interpreter',
} as Technique;

describe('WatchlistService', () => {
  let service: WatchlistService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(WatchlistService);
  });

  afterEach(() => localStorage.clear());

  describe('add / isWatched / remove', () => {
    it('starts with isWatched false', () => {
      expect(service.isWatched('T1059')).toBe(false);
    });

    it('add then isWatched returns true', () => {
      service.add(STUB_TECH);
      expect(service.isWatched('T1059')).toBe(true);
    });

    it('remove restores isWatched to false', () => {
      service.add(STUB_TECH);
      service.remove('T1059');
      expect(service.isWatched('T1059')).toBe(false);
    });
  });

  describe('toggle', () => {
    it('flips watch state on each call', () => {
      service.toggle(STUB_TECH);
      expect(service.isWatched('T1059')).toBe(true);
      service.toggle(STUB_TECH);
      expect(service.isWatched('T1059')).toBe(false);
    });
  });

  describe('updatePriority + updateNote', () => {
    it('updates the priority of an existing entry', () => {
      service.add(STUB_TECH, 'medium');
      service.updatePriority('T1059', 'high');
      expect(service.all.find(e => e.techniqueId === 'T1059')!.priority).toBe('high');
    });

    it('updates the note of an existing entry', () => {
      service.add(STUB_TECH);
      service.updateNote('T1059', 'investigate next sprint');
      expect(service.all.find(e => e.techniqueId === 'T1059')!.note).toContain('investigate');
    });
  });

  describe('persistence', () => {
    it('survives service re-instantiation', () => {
      service.add(STUB_TECH);
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(WatchlistService);
      expect(fresh.isWatched('T1059')).toBe(true);
    });
  });
});
