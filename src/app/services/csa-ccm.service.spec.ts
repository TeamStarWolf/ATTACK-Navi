// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { CsaCcmService } from './csa-ccm.service';

describe('CsaCcmService', () => {
  let service: CsaCcmService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(CsaCcmService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('parses mapping_objects on load', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        const ctrls = service.getControlsForTechnique('T1021');
        expect(ctrls.length).toBe(1);
        expect(ctrls[0].controlId).toBe('STA-16');
        done();
      }
    });
    const req = httpMock.expectOne(r => r.url.includes('csa_ccm'));
    req.flush({
      mapping_objects: [{
        attack_object_id: 'T1021',
        capability_id: 'STA-16',
        capability_description: 'Supply Chain Threat Modeling',
        mapping_type: 'mitigates',
        score_category: 'protect',
        score_value: 'partial',
        status: 'complete',
      }],
    });
  });

  it('marks loaded on HTTP error and exposes empty results', (done) => {
    service.loaded$.subscribe(loaded => {
      if (loaded) {
        expect(service.getControlsForTechnique('T9999')).toEqual([]);
        done();
      }
    });
    const req = httpMock.expectOne(r => r.url.includes('csa_ccm'));
    req.error(new ProgressEvent('boom'));
  });
});
