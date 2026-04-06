// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { DataService } from './data.service';

describe('DataService', () => {
  let service: DataService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        {
          provide: HttpClient,
          useValue: { get: () => of({}) },
        },
      ],
    });
    service = TestBed.inject(DataService);
  });

  it('should ignore stale load results when a newer request wins', fakeAsync(() => {
    const enterpriseDomain = { name: 'Enterprise ATT&CK' } as any;
    const icsDomain = { name: 'ICS ATT&CK' } as any;
    const pending: Array<() => void> = [];

    spyOn<any>(service, 'loadLive').and.callFake((config: { name: string }) =>
      new Observable((subscriber) => {
        pending.push(() => subscriber.next(config.name === 'Enterprise ATT&CK' ? enterpriseDomain : icsDomain));
      })
    );

    service.loadDomain();
    service.switchDomain('ics');

    pending[1]();
    pending[0]();
    tick();

    expect(service.getCurrentDomain()).toBe(icsDomain);
  }));

  it('should load bundled data for mobile when bundled mode is selected', fakeAsync(() => {
    const mobileDomain = { name: 'Mobile ATT&CK' } as any;

    spyOn<any>(service, 'loadBundled').and.returnValue(of(mobileDomain));

    service.setDataSourceMode('bundled');
    service.switchDomain('mobile');
    tick();

    expect((service as any).loadBundled).toHaveBeenCalled();
    expect(service.getCurrentDomain()).toBe(mobileDomain);
  }));
});
