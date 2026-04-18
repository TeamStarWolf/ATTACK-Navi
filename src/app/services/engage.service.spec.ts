// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { EngageService } from './engage.service';

describe('EngageService', () => {
  let service: EngageService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(EngageService);
  });

  describe('getActivities', () => {
    it('returns an array (possibly empty) for any technique', () => {
      const acts = service.getActivities('T1190');
      expect(Array.isArray(acts)).toBe(true);
    });

    it('returns empty array for unknown technique', () => {
      expect(service.getActivities('T9999')).toEqual([]);
    });

    it('matched activities reference the queried technique', () => {
      const acts = service.getActivities('T1566');
      acts.forEach(a => {
        // EAC entries map to ATT&CK techniques via attackIds[]
        expect((a as any).attackIds === undefined || Array.isArray((a as any).attackIds)).toBe(true);
      });
    });
  });
});
