// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { CsaCcmService } from './csa-ccm.service';
import { SourceRegistryService } from './source-registry.service';

describe('CsaCcmService', () => {
  let service: CsaCcmService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
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

  it('records an HTTP error as failed, never as loaded, and exposes empty results (E1.3)', () => {
    let loaded: boolean | undefined;
    service.loaded$.subscribe(v => (loaded = v));
    const req = httpMock.expectOne(r => r.url.includes('csa_ccm'));
    req.error(new ProgressEvent('boom'));
    expect(loaded).toBeFalse();
    expect(service.getControlsForTechnique('T9999')).toEqual([]);
    expect(TestBed.inject(SourceRegistryService).get('ctid-csa-ccm').status).toBe('failed');
  });
});
