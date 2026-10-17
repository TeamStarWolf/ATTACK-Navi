// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { CisControlsService } from './cis-controls.service';
import { SourceRegistryService } from './source-registry.service';

describe('CisControlsService', () => {
  let service: CisControlsService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(CisControlsService);
  });

  it('is recorded as withdrawn upstream and never reports loaded (no JSON source since ATT&CK v16)', () => {
    let loaded: boolean | undefined;
    service.loaded$.subscribe(v => (loaded = v));
    expect(loaded).toBeFalse();
    expect(service.getControlsForTechnique('T1003.001')).toEqual([]);
    const record = TestBed.inject(SourceRegistryService).get('cis-controls');
    expect(record.status).toBe('archived-upstream');
    expect(record.note).toContain('withdrawn');
  });

  it('returns empty array for any technique when no mappings loaded', () => {
    expect(service.getControlsForTechnique('T1078')).toEqual([]);
    expect(service.getControlsForTechnique('NOT-REAL')).toEqual([]);
  });
});
