// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { CweService } from './cwe.service';

describe('CweService', () => {
  let service: CweService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(CweService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  // Helper to flush the catalog request made in the constructor
  function flushCatalog(data: Record<string, any> | null = {}): void {
    const req = httpMock.expectOne('assets/data/cwe-catalog.json');
    if (data === null) {
      req.error(new ProgressEvent('error'));
    } else {
      req.flush(data);
    }
  }

  // --- getInfo() for known CWEs ---

  it('should return CweInfo for CWE-79 from the static MAP', () => {
    flushCatalog();
    const info = service.getInfo('CWE-79');
    expect(info).toBeTruthy();
    expect(info!.id).toBe('CWE-79');
    expect(info!.name).toBe('Cross-site Scripting (XSS)');
  });

  it('should return CweInfo for CWE-89 from the static MAP', () => {
    flushCatalog();
    const info = service.getInfo('CWE-89');
    expect(info).toBeTruthy();
    expect(info!.id).toBe('CWE-89');
    expect(info!.name).toBe('SQL Injection');
  });

  it('should handle CWE id without prefix (just numeric)', () => {
    flushCatalog();
    const info = service.getInfo('79');
    expect(info).toBeTruthy();
    expect(info!.id).toBe('CWE-79');
  });

  it('should include the URL in the returned CweInfo', () => {
    flushCatalog();
    const info = service.getInfo('CWE-79');
    expect(info!.url).toContain('79.html');
  });

  it('should include a description in the returned CweInfo', () => {
    flushCatalog();
    const info = service.getInfo('CWE-89');
    expect(info!.description).toBeTruthy();
  });

  // --- getInfo() for unknown CWEs ---

  it('should return null for unknown CWE before catalog loads', () => {
    // Do not flush the catalog - simulate pre-load state
    // The static MAP is already loaded, so we test a CWE not in the static MAP
    const info = service.getInfo('CWE-99999');
    expect(info).toBeNull();
    // Flush to avoid afterEach verification error
    flushCatalog();
  });

  it('should return null for a CWE not in the catalog or static MAP', () => {
    flushCatalog();
    const info = service.getInfo('CWE-99999');
    expect(info).toBeNull();
  });

  // --- getUrl() ---

  it('should return the correct MITRE URL for a CWE id with prefix', () => {
    flushCatalog();
    const url = service.getUrl('CWE-79');
    expect(url).toBe('https://cwe.mitre.org/data/definitions/79.html');
  });

  it('should return the correct MITRE URL for a plain numeric CWE id', () => {
    flushCatalog();
    const url = service.getUrl('89');
    expect(url).toBe('https://cwe.mitre.org/data/definitions/89.html');
  });

  // --- loaded$ ---

  it('should emit true after the catalog loads successfully', () => {
    flushCatalog({ '99998': { name: 'Test CWE', description: 'test' } });
    let loaded = false;
    service.loaded$.subscribe(val => { loaded = val; });
    expect(loaded).toBeTrue();
  });

  it('should emit true even if the catalog request fails', () => {
    flushCatalog(null);
    let loaded = false;
    service.loaded$.subscribe(val => { loaded = val; });
    expect(loaded).toBeTrue();
  });

  it('should merge fetched catalog data with static MAP', () => {
    flushCatalog({ '99998': { name: 'Dynamic CWE', description: 'dynamic desc' } });
    const info = service.getInfo('CWE-99998');
    expect(info).toBeTruthy();
    expect(info!.name).toBe('Dynamic CWE');
  });
});
