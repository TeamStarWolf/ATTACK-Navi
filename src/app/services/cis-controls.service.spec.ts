// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CisControlsService } from './cis-controls.service';

describe('CisControlsService', () => {
  let service: CisControlsService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(CisControlsService);
  });

  it('loads as empty (no JSON source available since ATT&CK v16)', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        expect(service.getControlsForTechnique('T1003.001')).toEqual([]);
        done();
      }
    });
  });

  it('returns empty array for any technique when no mappings loaded', () => {
    expect(service.getControlsForTechnique('T1078')).toEqual([]);
    expect(service.getControlsForTechnique('NOT-REAL')).toEqual([]);
  });
});
