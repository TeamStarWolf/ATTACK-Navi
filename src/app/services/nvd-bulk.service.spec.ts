// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { NvdBulkService } from './nvd-bulk.service';

describe('NvdBulkService', () => {
  let service: NvdBulkService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(NvdBulkService);
  });

  it('returns 0 CVE count for unknown technique before load', () => {
    expect(service.getCveCountForTechnique('T9999')).toBe(0);
  });

  it('returns empty CVE array for unknown technique before load', () => {
    expect(service.getCvesForTechnique('T9999')).toEqual([]);
  });
});
