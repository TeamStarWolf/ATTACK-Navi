// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { MatrixExportService } from './matrix-export.service';

describe('MatrixExportService', () => {
  let service: MatrixExportService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(MatrixExportService);
  });

  it('is created', () => {
    expect(service).toBeTruthy();
  });

  it('exposes the public exportPng method', () => {
    expect(typeof service.exportPng).toBe('function');
  });
});
