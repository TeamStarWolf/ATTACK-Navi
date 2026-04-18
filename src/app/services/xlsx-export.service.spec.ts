// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { XlsxExportService } from './xlsx-export.service';

describe('XlsxExportService', () => {
  let service: XlsxExportService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(XlsxExportService);
  });

  it('is created', () => {
    expect(service).toBeTruthy();
  });

  it('exposes the public exportWorkbook method', () => {
    expect(typeof service.exportWorkbook).toBe('function');
  });
});
