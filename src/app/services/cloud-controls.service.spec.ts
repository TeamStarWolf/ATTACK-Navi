// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { CloudControlsService } from './cloud-controls.service';

describe('CloudControlsService', () => {
  let service: CloudControlsService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(CloudControlsService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  function flushAll(awsCount = 1, azureCount = 1, gcpCount = 1) {
    const buildPayload = (provider: string, n: number) => ({
      mapping_objects: Array.from({ length: n }, (_, i) => ({
        attack_object_id: 'T1078',
        capability_id: `${provider.toUpperCase()}-${i + 1}`,
        capability_description: `${provider} control ${i + 1}`,
        status: 'complete',
        mapping_type: 'mitigates',
      })),
    });
    httpMock.expectOne(r => r.url.includes('aws')).flush(buildPayload('aws', awsCount));
    httpMock.expectOne(r => r.url.includes('azure')).flush(buildPayload('azure', azureCount));
    httpMock.expectOne(r => r.url.includes('gcp')).flush(buildPayload('gcp', gcpCount));
  }

  it('isProviderLoaded transitions to true after a provider responds', () => {
    expect(service.isProviderLoaded('aws')).toBe(false);
    flushAll();
    expect(service.isProviderLoaded('aws')).toBe(true);
    expect(service.isProviderLoaded('azure')).toBe(true);
    expect(service.isProviderLoaded('gcp')).toBe(true);
  });

  it('getControlsForTechnique returns provider-tagged controls', () => {
    flushAll(2, 1, 0);
    const aws = service.getControlsForTechnique('T1078', 'aws');
    expect(aws.length).toBe(2);
    expect(aws[0].provider).toBe('aws');

    const azure = service.getControlsForTechnique('T1078', 'azure');
    expect(azure.length).toBe(1);
    expect(azure[0].provider).toBe('azure');

    const gcp = service.getControlsForTechnique('T1078', 'gcp');
    expect(gcp.length).toBe(0);
  });

  it('getControlsForTechnique without provider returns all providers combined', () => {
    flushAll(1, 1, 1);
    const all = service.getControlsForTechnique('T1078');
    expect(all.length).toBe(3);
    const providers = all.map(c => c.provider);
    expect(providers).toEqual(jasmine.arrayContaining(['aws', 'azure', 'gcp'] as Array<'aws' | 'azure' | 'gcp'>));
  });

  it('getProviderTotal counts unique controls per provider', () => {
    flushAll(3, 2, 0);
    expect(service.getProviderTotal('aws')).toBe(3);
    expect(service.getProviderTotal('azure')).toBe(2);
    expect(service.getProviderTotal('gcp')).toBe(0);
  });
});
