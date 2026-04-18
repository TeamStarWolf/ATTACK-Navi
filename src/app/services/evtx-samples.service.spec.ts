// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { EvtxSamplesService } from './evtx-samples.service';

describe('EvtxSamplesService', () => {
  let service: EvtxSamplesService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(EvtxSamplesService);
  });

  it('returns empty array of samples for unknown technique', () => {
    expect(service.getSamplesForTechnique('T9999')).toEqual([]);
  });

  it('returns 0 sample count for unknown technique', () => {
    expect(service.getSampleCount('T9999')).toBe(0);
  });

  it('loadOnDemand does not throw when called', () => {
    expect(() => service.loadOnDemand()).not.toThrow();
  });
});
