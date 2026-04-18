// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { TaxiiService } from './taxii.service';

describe('TaxiiService', () => {
  let service: TaxiiService;

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(TaxiiService);
  });

  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  describe('CRUD lifecycle', () => {
    it('starts with no servers', () => {
      expect(service.getServers()).toEqual([]);
    });

    it('addServer assigns an id and persists', () => {
      const s = service.addServer({
        name: 'Test',
        url: 'https://taxii.example.com',
        username: '',
      } as any);
      expect(s.id).toBeTruthy();
      expect(service.getServers().length).toBe(1);
    });

    it('updateServer mutates existing server', () => {
      const s = service.addServer({ name: 'A', url: 'https://a.example.com' } as any);
      service.updateServer(s.id, { name: 'A-renamed' } as any);
      expect(service.getServers().find(x => x.id === s.id)!.name).toBe('A-renamed');
    });

    it('removeServer deletes by id', () => {
      const s = service.addServer({ name: 'doomed', url: 'https://x.example.com' } as any);
      service.removeServer(s.id);
      expect(service.getServers()).toEqual([]);
    });
  });
});
