// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { OffensiveToolsService } from './offensive-tools.service';

describe('OffensiveToolsService', () => {
  let service: OffensiveToolsService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(OffensiveToolsService);
  });

  describe('getAllTools', () => {
    it('returns the bundled tool catalogue', () => {
      const all = service.getAllTools();
      expect(all.length).toBeGreaterThan(0);
      expect(all[0].name).toBeTruthy();
    });
  });

  describe('getToolsForTechnique', () => {
    it('returns array (possibly empty) for any technique', () => {
      expect(Array.isArray(service.getToolsForTechnique('T1059'))).toBe(true);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getToolsForTechnique('T9999')).toEqual([]);
    });
  });

  describe('getCategories + getByCategory', () => {
    it('returns a non-empty deduplicated category list', () => {
      const cats = service.getCategories();
      expect(cats.length).toBeGreaterThan(0);
      expect(new Set(cats).size).toBe(cats.length);
    });

    it('getByCategory returns tools matching the category', () => {
      const cats = service.getCategories();
      const tools = service.getByCategory(cats[0]);
      tools.forEach(t => expect(t.category).toBe(cats[0]));
    });

    it('getByCategory returns empty for unknown category', () => {
      expect(service.getByCategory('NoSuchCategory')).toEqual([]);
    });
  });
});
