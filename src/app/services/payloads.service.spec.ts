// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { PayloadsService } from './payloads.service';

describe('PayloadsService', () => {
  let service: PayloadsService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(PayloadsService);
  });

  it('returns empty payloads for unknown technique before load', () => {
    expect(service.getPayloadsForTechnique('T9999')).toEqual([]);
  });

  it('returns 0 payload count for unknown technique before load', () => {
    expect(service.getPayloadCount('T9999')).toBe(0);
  });

  it('loadOnDemand does not throw', () => {
    expect(() => service.loadOnDemand()).not.toThrow();
  });
});
