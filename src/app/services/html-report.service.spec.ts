// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { HtmlReportService } from './html-report.service';

describe('HtmlReportService', () => {
  let service: HtmlReportService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(HtmlReportService);
  });

  it('is created', () => {
    expect(service).toBeTruthy();
  });

  it('exposes the public generateAndOpen method', () => {
    expect(typeof service.generateAndOpen).toBe('function');
  });
});
