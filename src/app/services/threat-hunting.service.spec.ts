// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { ThreatHuntingService } from './threat-hunting.service';

describe('ThreatHuntingService', () => {
  let service: ThreatHuntingService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ThreatHuntingService);
  });

  it('returns empty queries for unknown technique before load', () => {
    expect(service.getQueriesForTechnique('T9999')).toEqual([]);
  });

  it('loadOnDemand does not throw', () => {
    expect(() => service.loadOnDemand()).not.toThrow();
  });
});
