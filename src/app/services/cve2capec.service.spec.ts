// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { Cve2CapecService } from './cve2capec.service';

describe('Cve2CapecService', () => {
  let service: Cve2CapecService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(Cve2CapecService);
  });

  it('returns empty array for getChainForTechnique on unknown id', () => {
    expect(service.getChainForTechnique('T9999')).toEqual([]);
  });

  it('returns null for getChainForCve on unknown id', () => {
    expect(service.getChainForCve('CVE-9999-9999')).toBeNull();
  });

  it('returns 0 chain count for unknown id', () => {
    expect(service.getChainCount('T9999')).toBe(0);
  });

  it('returns empty defenses array for unknown id', () => {
    expect(service.getDefensesForTechnique('T9999')).toEqual([]);
  });
});
