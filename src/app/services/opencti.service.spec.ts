// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { HttpClient, withXhr } from '@angular/common/http';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { OpenCtiService } from './opencti.service';
import { SettingsService } from './settings.service';

describe('OpenCtiService', () => {
  let service: OpenCtiService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        OpenCtiService,
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    service = TestBed.inject(OpenCtiService);
  });

  it('should persist only the URL and keep the token session-only', () => {
    spyOn(service, 'testConnection');

    service.saveConfig({
      url: 'https://example.com/',
      token: 'secret-token',
      mode: 'direct',
      proxyUrl: '',
    });

    expect(service.getConfig().token).toBe('secret-token');
    expect(localStorage.getItem('opencti_config')).toBe(JSON.stringify({
      url: 'https://example.com',
      mode: 'direct',
      proxyUrl: '',
    }));
  });

  it('should not restore a token from localStorage', () => {
    localStorage.setItem('opencti_config', JSON.stringify({ url: 'https://example.com', token: 'persisted-token' }));

    const fresh = new OpenCtiService(TestBed.inject(HttpClient), TestBed.inject(SettingsService));
    expect(fresh.getConfig().url).toBe('https://example.com');
    expect(fresh.getConfig().token).toBe('');
  });

  it('should persist proxy mode without storing a token', () => {
    spyOn(service, 'testConnection');

    service.saveConfig({
      url: '',
      token: '',
      mode: 'proxy',
      proxyUrl: 'https://proxy.example/',
    });

    expect(service.getConfig().mode).toBe('proxy');
    expect(service.getConfig().proxyUrl).toBe('https://proxy.example');
    expect(localStorage.getItem('opencti_config')).toBe(JSON.stringify({
      url: '',
      mode: 'proxy',
      proxyUrl: 'https://proxy.example',
    }));
  });

  describe('proxy-mode request headers', () => {
    let httpMock: HttpTestingController;

    beforeEach(() => {
      sessionStorage.clear();
      httpMock = TestBed.inject(HttpTestingController);
    });

    afterEach(() => {
      httpMock.verify();
      sessionStorage.clear();
    });

    it('sends X-Requested-With and the proxy access token as X-Proxy-Key, never the OpenCTI token', () => {
      TestBed.inject(SettingsService).setProxyToken('proxy-secret');
      service.saveConfig({ url: '', token: '', mode: 'proxy', proxyUrl: 'https://proxy.example' });

      const req = httpMock.expectOne('https://proxy.example/api/opencti/graphql');
      expect(req.request.method).toBe('POST');
      expect(req.request.headers.get('X-Proxy-Key')).toBe('proxy-secret');
      expect(req.request.headers.get('X-Requested-With')).toBe('ATTACK-Navi');
      expect(req.request.headers.has('Authorization')).toBeFalse();
      req.flush({ data: { about: { version: '6.0', title: 'OpenCTI' } } });
      expect(service.getConfig().connected).toBeTrue();
    });

    it('omits X-Proxy-Key when no proxy access token is set, but still sends X-Requested-With', () => {
      service.saveConfig({ url: '', token: '', mode: 'proxy', proxyUrl: 'https://proxy.example' });

      const req = httpMock.expectOne('https://proxy.example/api/opencti/graphql');
      expect(req.request.headers.has('X-Proxy-Key')).toBeFalse();
      expect(req.request.headers.get('X-Requested-With')).toBe('ATTACK-Navi');
      req.flush({ data: { about: { version: '6.0', title: 'OpenCTI' } } });
    });

    it('direct mode sends the OpenCTI bearer token and no proxy headers even when a proxy token exists', () => {
      TestBed.inject(SettingsService).setProxyToken('proxy-secret');
      service.saveConfig({ url: 'https://opencti.example', token: 'cti-token', mode: 'direct', proxyUrl: '' });

      const req = httpMock.expectOne('https://opencti.example/graphql');
      expect(req.request.headers.get('Authorization')).toBe('Bearer cti-token');
      expect(req.request.headers.has('X-Proxy-Key')).toBeFalse();
      expect(req.request.headers.has('X-Requested-With')).toBeFalse();
      req.flush({ data: { about: { version: '6.0', title: 'OpenCTI' } } });
    });

    it('routes the ImportStix mutation through the proxy endpoint with the proxy headers', () => {
      TestBed.inject(SettingsService).setProxyToken('proxy-secret');
      service.saveConfig({ url: '', token: '', mode: 'proxy', proxyUrl: 'https://proxy.example' });
      httpMock.expectOne('https://proxy.example/api/opencti/graphql').flush({ data: { about: { version: '6.0', title: 'OpenCTI' } } });

      let result: { success: boolean; message: string } | undefined;
      service.importStixBundle('{"type":"bundle"}').subscribe(r => { result = r; });
      const req = httpMock.expectOne('https://proxy.example/api/opencti/graphql');
      expect(req.request.body.query).toContain('mutation ImportStix');
      expect(req.request.headers.get('X-Proxy-Key')).toBe('proxy-secret');
      req.flush({ data: { stixObjectOrStixRelationshipImport: { id: 'x' } } });
      expect(result?.success).toBeTrue();
    });
  });
});
