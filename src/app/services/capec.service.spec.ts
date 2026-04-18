// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CapecService } from './capec.service';

describe('CapecService', () => {
  let service: CapecService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(CapecService);
  });

  describe('getCapecForTechnique', () => {
    it('returns array (empty before load)', () => {
      expect(service.getCapecForTechnique('T1059')).toEqual([]);
    });
  });

  describe('getCapecCount', () => {
    it('returns 0 before load', () => {
      expect(service.getCapecCount('T1059')).toBe(0);
    });
  });

  describe('getCapecForCwe', () => {
    it('returns array (empty before load)', () => {
      expect(service.getCapecForCwe('CWE-79')).toEqual([]);
    });
  });
});
