// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { HttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { MispService } from './misp.service';
import { SettingsService } from './settings.service';

describe('MispService', () => {
  let service: MispService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        MispService,
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(MispService);
    httpMock = TestBed.inject(HttpTestingController);
    httpMock.expectOne('https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json').flush({ values: [] });
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should persist only non-secret MISP config values', () => {
    service.saveConfig({
      url: 'https://misp.example/',
      apiKey: 'super-secret',
      orgId: '1',
      connected: false,
      mode: 'direct',
      proxyUrl: '',
    });

    const req = httpMock.expectOne('https://misp.example/servers/getVersion');
    expect(req.request.headers.get('Authorization')).toBe('super-secret');
    req.flush({ version: '2.4' });

    expect(localStorage.getItem('misp_config')).toBe(JSON.stringify({
      url: 'https://misp.example',
      orgId: '1',
      mode: 'direct',
      proxyUrl: '',
    }));
  });

  it('should not restore an API key from localStorage', () => {
    localStorage.setItem('misp_config', JSON.stringify({
      url: 'https://misp.example',
      orgId: '1',
      apiKey: 'persisted-secret',
    }));

    const fresh = new MispService(TestBed.inject(HttpClient), TestBed.inject(SettingsService));
    httpMock.expectOne('https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-attack-pattern.json').flush({ values: [] });

    expect(fresh.getConfig().url).toBe('https://misp.example');
    expect(fresh.getConfig().orgId).toBe('1');
    expect(fresh.getConfig().apiKey).toBe('');
  });

  it('should persist proxy mode without storing an API key', () => {
    service.saveConfig({
      url: '',
      apiKey: '',
      orgId: '',
      connected: false,
      mode: 'proxy',
      proxyUrl: 'https://proxy.example/',
    });

    const req = httpMock.expectOne('https://proxy.example/api/misp/servers/getVersion');
    expect(req.request.headers.has('Authorization')).toBeFalse();
    expect(req.request.headers.get('X-Requested-With')).toBe('ATTACK-Navi');
    expect(req.request.headers.has('X-Proxy-Key')).withContext('no token entered yet').toBeFalse();
    req.flush({ version: '2.4' });

    expect(localStorage.getItem('misp_config')).toBe(JSON.stringify({
      url: '',
      orgId: '',
      mode: 'proxy',
      proxyUrl: 'https://proxy.example',
    }));
  });

  it('sends the proxy access token as X-Proxy-Key in proxy mode and never in direct mode', () => {
    sessionStorage.clear();
    TestBed.inject(SettingsService).setProxyToken('  proxy-secret  ');

    service.saveConfig({ url: '', apiKey: '', orgId: '', connected: false, mode: 'proxy', proxyUrl: 'https://proxy.example' });
    const viaProxy = httpMock.expectOne('https://proxy.example/api/misp/servers/getVersion');
    expect(viaProxy.request.headers.get('X-Proxy-Key')).toBe('proxy-secret');
    expect(viaProxy.request.headers.get('X-Requested-With')).toBe('ATTACK-Navi');
    expect(viaProxy.request.headers.has('Authorization')).toBeFalse();
    viaProxy.flush({ version: '2.4' });

    service.saveConfig({ url: 'https://misp.example', apiKey: 'misp-key', orgId: '', connected: false, mode: 'direct', proxyUrl: '' });
    const direct = httpMock.expectOne('https://misp.example/servers/getVersion');
    expect(direct.request.headers.get('Authorization')).toBe('misp-key');
    expect(direct.request.headers.has('X-Proxy-Key')).toBeFalse();
    expect(direct.request.headers.has('X-Requested-With')).toBeFalse();
    direct.flush({ version: '2.4' });
    sessionStorage.clear();
  });

  it('should not retry through a third-party proxy when direct requests fail', () => {
    (service as any).serverConfig = {
      url: 'https://misp.example',
      apiKey: 'super-secret',
      orgId: '',
      connected: true,
      mode: 'direct',
      proxyUrl: '',
    };

    service.getEventsForTechnique('T1059').subscribe(events => {
      expect(events).toEqual([]);
    });

    httpMock.expectOne('https://misp.example/events/restSearch').flush('fail', { status: 500, statusText: 'Server Error' });
  });
});
