// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { VerisService } from './veris.service';

describe('VerisService', () => {
  let service: VerisService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(VerisService);
  });

  describe('getActionsForTechnique', () => {
    it('returns array (possibly empty) for any technique', () => {
      expect(Array.isArray(service.getActionsForTechnique('T1059'))).toBe(true);
    });

    it('returns empty for unknown technique', () => {
      expect(service.getActionsForTechnique('T9999')).toEqual([]);
    });
  });
});
