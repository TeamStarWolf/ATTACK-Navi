// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { M365DefenderService } from './m365-defender.service';

describe('M365DefenderService', () => {
  let service: M365DefenderService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(M365DefenderService);
  });

  it('returns 0 query count before load', () => {
    expect(service.getQueriesForTechnique('T9999')).toEqual([]);
  });

  it('returns 0 heat score before load', () => {
    expect(service.getHeatScore('T9999')).toBe(0);
  });

  it('loadOnDemand does not throw', () => {
    expect(() => service.loadOnDemand()).not.toThrow();
  });
});
