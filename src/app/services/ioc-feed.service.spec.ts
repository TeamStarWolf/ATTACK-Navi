// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { IocFeedService } from './ioc-feed.service';

describe('IocFeedService', () => {
  let service: IocFeedService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(IocFeedService);
  });

  it('returns empty IoCs for unknown technique before load', () => {
    expect(service.getIocsForTechnique('T9999')).toEqual([]);
  });

  it('returns empty array for getAllIocs before load', () => {
    expect(service.getAllIocs()).toEqual([]);
  });

  it('searchIocs returns empty for empty query', () => {
    expect(service.searchIocs('')).toEqual([]);
  });

  it('searchIocs returns empty for unknown query', () => {
    expect(service.searchIocs('not-a-real-ioc-string-xyz')).toEqual([]);
  });

  it('loadOnDemand does not throw', () => {
    expect(() => service.loadOnDemand()).not.toThrow();
  });
});
