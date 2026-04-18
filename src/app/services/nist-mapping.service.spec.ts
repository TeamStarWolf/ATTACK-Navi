// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { NistMappingService } from './nist-mapping.service';

describe('NistMappingService', () => {
  let service: NistMappingService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(NistMappingService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  function flushFixture() {
    const req = httpMock.expectOne(r => r.url.includes('nist_800_53'));
    req.flush({
      mapping_objects: [
        {
          attack_object_id: 'T1078',
          capability_id: 'AC-02',
          capability_description: 'Account Management',
          capability_group: 'AC',
          mapping_type: 'mitigates',
          status: 'complete',
        },
        {
          attack_object_id: 'T1078',
          capability_id: 'IA-02',
          capability_description: 'Identification and Authentication',
          capability_group: 'IA',
          mapping_type: 'mitigates',
          status: 'complete',
        },
        {
          // Should be filtered out (status not 'complete')
          attack_object_id: 'T9999',
          capability_id: 'XX-99',
          capability_description: 'Unrelated',
          capability_group: 'XX',
          status: 'in_progress',
        },
      ],
    });
  }

  it('loads and indexes mappings on construction', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        const controls = service.getControlsForTechnique('T1078');
        expect(controls.length).toBe(2);
        expect(controls.map(c => c.id)).toEqual(jasmine.arrayContaining(['AC-02', 'IA-02']));
        expect(controls[0].family).toBeTruthy();
        done();
      }
    });
    flushFixture();
  });

  it('skips mappings with non-complete status', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        expect(service.getControlsForTechnique('T9999')).toEqual([]);
        done();
      }
    });
    flushFixture();
  });

  it('returns empty array for unknown technique', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        expect(service.getControlsForTechnique('T0000')).toEqual([]);
        done();
      }
    });
    flushFixture();
  });

  it('handles HTTP error gracefully without throwing', (done) => {
    // After error, subsequent queries should return empty (not throw)
    setTimeout(() => {
      expect(service.getControlsForTechnique('T9999')).toEqual([]);
      done();
    }, 50);
    const req = httpMock.expectOne(r => r.url.includes('nist_800_53'));
    req.error(new ProgressEvent('boom'));
  });
});
