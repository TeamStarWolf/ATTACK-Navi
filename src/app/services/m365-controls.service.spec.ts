// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { M365ControlsService } from './m365-controls.service';

describe('M365ControlsService', () => {
  let service: M365ControlsService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(M365ControlsService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('parses mapping_objects on load', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        const ctrls = service.getControlsForTechnique('T1078');
        expect(ctrls.length).toBeGreaterThanOrEqual(1);
        expect(ctrls[0].controlId).toBe('EID-CA-E3');
        done();
      }
    });
    const req = httpMock.expectOne(r => r.url.includes('m365'));
    req.flush({
      mapping_objects: [{
        attack_object_id: 'T1078',
        capability_id: 'EID-CA-E3',
        capability_description: 'Conditional Access E3 baseline',
        capability_group: 'entra-id',
        score_category: 'protect',
        score_value: 'significant',
        status: 'complete',
      }],
    });
  });

  it('handles HTTP failure gracefully', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        expect(service.getControlsForTechnique('T9999')).toEqual([]);
        done();
      }
    });
    const req = httpMock.expectOne(r => r.url.includes('m365'));
    req.error(new ProgressEvent('boom'));
  });
});
