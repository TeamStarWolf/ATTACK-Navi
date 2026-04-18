// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { TimelineService } from './timeline.service';

describe('TimelineService', () => {
  let service: TimelineService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(TimelineService);
  });

  afterEach(() => localStorage.clear());

  describe('getAll / getLatest', () => {
    it('starts empty', () => {
      expect(service.getAll()).toEqual([]);
      expect(service.getLatest()).toBeNull();
    });
  });

  describe('getStorageSizeKb', () => {
    it('returns a non-negative number', () => {
      expect(service.getStorageSizeKb()).toBeGreaterThanOrEqual(0);
    });
  });

  describe('deleteSnapshot', () => {
    it('is a no-op when no snapshots exist', () => {
      expect(() => service.deleteSnapshot('nonexistent')).not.toThrow();
    });
  });

  describe('updateLabel / updateNotes', () => {
    it('are no-ops when snapshot is missing', () => {
      expect(() => service.updateLabel('nope', 'new')).not.toThrow();
      expect(() => service.updateNotes('nope', 'note')).not.toThrow();
    });
  });
});
