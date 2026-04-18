// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { CriProfileService } from './cri-profile.service';

describe('CriProfileService', () => {
  let service: CriProfileService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(CriProfileService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('parses CRI Profile mappings and resolves human-readable function labels', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        const ctrls = service.getControlsForTechnique('T1078');
        expect(ctrls.length).toBe(1);
        expect(ctrls[0].id).toBe('PR.IR-01.05');
        expect(ctrls[0].function).toBe('PR');
        expect(ctrls[0].functionLabel).toBe('Protect');
        expect(ctrls[0].url).toContain('mappings-explorer');
        done();
      }
    });

    const req = httpMock.expectOne(r => r.url.includes('cri_profile'));
    req.flush({
      mapping_objects: [{
        attack_object_id: 'T1078',
        capability_id: 'PR.IR-01.05',
        capability_description: 'Implement additional safeguards',
        mapping_type: 'mitigates',
        status: 'complete',
      }],
    });
  });

  it('groups controls by category for a technique', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        const grouped = service.getGroupedControls('T1078');
        expect(grouped.size).toBeGreaterThanOrEqual(1);
        done();
      }
    });
    const req = httpMock.expectOne(r => r.url.includes('cri_profile'));
    req.flush({
      mapping_objects: [
        {
          attack_object_id: 'T1078',
          capability_id: 'PR.IR-01.05',
          capability_description: 'X',
          mapping_type: 'mitigates',
          status: 'complete',
        },
        {
          attack_object_id: 'T1078',
          capability_id: 'PR.IR-02.01',
          capability_description: 'Y',
          mapping_type: 'mitigates',
          status: 'complete',
        },
      ],
    });
  });

  it('returns empty results when load fails', (done) => {
    let count = 0;
    service.loaded$.subscribe(() => {
      count++;
      if (count === 1) {
        expect(service.getControlsForTechnique('T9999')).toEqual([]);
        done();
      }
    });
    const req = httpMock.expectOne(r => r.url.includes('cri_profile'));
    req.error(new ProgressEvent('boom'));
  });
});
