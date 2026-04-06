// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { OpenCtiService } from './opencti.service';

describe('OpenCtiService', () => {
  let service: OpenCtiService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        OpenCtiService,
        provideHttpClient(),
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

    const fresh = new OpenCtiService(TestBed.inject(HttpClient));
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
});
