// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { TaggingService } from './tagging.service';

describe('TaggingService', () => {
  let service: TaggingService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(TaggingService);
  });

  afterEach(() => localStorage.clear());

  describe('addTag', () => {
    it('adds a tag to a technique', () => {
      service.addTag('T1059', 'crown-jewel');
      expect(service.getTags('T1059')).toContain('crown-jewel');
    });

    it('does not duplicate', () => {
      service.addTag('T1059', 'a');
      service.addTag('T1059', 'a');
      expect(service.getTags('T1059').filter(t => t === 'a').length).toBe(1);
    });
  });

  describe('removeTag', () => {
    it('removes a specific tag', () => {
      service.addTag('T1059', 'a');
      service.addTag('T1059', 'b');
      service.removeTag('T1059', 'a');
      expect(service.getTags('T1059')).not.toContain('a');
      expect(service.getTags('T1059')).toContain('b');
    });
  });

  describe('hasTags', () => {
    it('returns true after adding any tag, false otherwise', () => {
      expect(service.hasTags('T1059')).toBe(false);
      service.addTag('T1059', 'x');
      expect(service.hasTags('T1059')).toBe(true);
    });
  });

  describe('clearTags', () => {
    it('removes all tags for a technique', () => {
      service.addTag('T1059', 'a');
      service.addTag('T1059', 'b');
      service.clearTags('T1059');
      expect(service.getTags('T1059')).toEqual([]);
    });
  });

  describe('getAllUsedTags', () => {
    it('returns deduplicated tag names across all techniques', () => {
      service.addTag('T1059', 'shared');
      service.addTag('T1078', 'shared');
      service.addTag('T1078', 'unique');
      const all = service.getAllUsedTags();
      expect(all.sort()).toEqual(['shared', 'unique']);
    });
  });

  describe('persistence', () => {
    it('persists across service re-instantiation', () => {
      service.addTag('T1059', 'persistent');
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(TaggingService);
      expect(fresh.getTags('T1059')).toContain('persistent');
    });
  });
});
