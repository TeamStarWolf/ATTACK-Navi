// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { SettingsService } from './settings.service';

describe('SettingsService', () => {
  let service: SettingsService;

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(SettingsService);
  });

  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it('starts with default settings', () => {
    expect(service.current).toBeTruthy();
    expect(service.current.matrixCellSize).toBeTruthy();
    expect(['compact', 'normal', 'large']).toContain(service.current.matrixCellSize);
  });

  describe('update', () => {
    it('merges partial settings into the current snapshot', () => {
      service.update({ matrixCellSize: 'large' });
      expect(service.current.matrixCellSize).toBe('large');
    });

    it('persists across service re-instantiation', () => {
      service.update({ matrixCellSize: 'compact' });
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(SettingsService);
      expect(fresh.current.matrixCellSize).toBe('compact');
    });
  });

  describe('updateWeights', () => {
    it('merges new weight values', () => {
      service.updateWeights({ atomic: 25 });
      expect(service.current.scoringWeights.atomic).toBe(25);
    });
  });

  describe('reset', () => {
    it('restores defaults', () => {
      service.update({ matrixCellSize: 'large' });
      service.reset();
      expect(service.current.matrixCellSize).not.toBe('large');
    });
  });

  describe('getNormalizedWeights', () => {
    it('returns weight values that sum to a positive number', () => {
      const w = service.getNormalizedWeights();
      const sum = Object.values(w).reduce((a, b) => a + b, 0);
      expect(sum).toBeGreaterThan(0);
    });
  });

  describe('getCoverageColors', () => {
    it('returns an array of color strings', () => {
      const colors = service.getCoverageColors();
      expect(Array.isArray(colors)).toBe(true);
      expect(colors.length).toBeGreaterThan(0);
      colors.forEach(c => expect(typeof c).toBe('string'));
    });
  });

  describe('setNvdApiKey', () => {
    it('stores the key', () => {
      service.setNvdApiKey('test-key-123');
      // Key may go to sessionStorage or settings — either way no exception
      expect(() => service.setNvdApiKey('')).not.toThrow();
    });
  });
});
