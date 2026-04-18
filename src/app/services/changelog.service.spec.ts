// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { ChangelogService } from './changelog.service';

describe('ChangelogService', () => {
  let service: ChangelogService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ChangelogService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('starts with empty releases list before HTTP completes', (done) => {
    let firstEmission = true;
    service.releases$.subscribe(rs => {
      if (firstEmission) {
        firstEmission = false;
        expect(rs).toEqual([]);
        done();
      }
    });
    // Drain the in-flight request so verify() doesn't complain
    httpMock.expectOne(r => r.url.includes('releases')).flush([]);
  });

  it('loads releases from MITRE GitHub on construction', (done) => {
    service.releases$.subscribe(rs => {
      if (rs.length > 0) {
        expect(rs[0].tag).toBe('ATT&CK-v17.1');
        expect(rs[0].name).toBe('17.1 Release');
        done();
      }
    });
    const req = httpMock.expectOne(r => r.url.includes('mitre-attack/attack-stix-data/releases'));
    req.flush([
      {
        tag_name: 'ATT&CK-v17.1',
        name: '17.1 Release',
        published_at: '2026-04-01T00:00:00Z',
        body: 'Notes',
        html_url: 'https://github.com/mitre-attack/attack-stix-data/releases/tag/v17.1',
      },
    ]);
  });

  it('handles HTTP error without throwing', (done) => {
    setTimeout(() => {
      // No assertion beyond "didn't throw" — releases$ stays empty
      service.releases$.subscribe(rs => {
        expect(rs).toEqual([]);
        done();
      });
    }, 50);
    const req = httpMock.expectOne(r => r.url.includes('releases'));
    req.error(new ProgressEvent('boom'));
  });
});
